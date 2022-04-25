/*
 * Copyright (C) 2022, Alibaba Cloud
 */
#define FSCACHE_USE_NEW_IO_API
#include <linux/fscache.h>
#include <linux/netfs.h>
#include <linux/uio.h>
#include "internal.h"

struct fscache_netfs erofs_fscache_netfs = {
	.name = "erofs",
	.version = 0,
};

int erofs_fscache_register(void)
{
	return fscache_register_netfs(&erofs_fscache_netfs);
}

void erofs_fscache_unregister(void)
{
	fscache_unregister_netfs(&erofs_fscache_netfs);
}

const struct fscache_cookie_def erofs_fscache_super_index_def = {
	.name = "EROFS.super",
	.type = FSCACHE_COOKIE_TYPE_INDEX,
	.check_aux = NULL,
};

const struct fscache_cookie_def erofs_fscache_inode_object_def = {
	.name           = "CIFS.uniqueid",
	.type           = FSCACHE_COOKIE_TYPE_DATAFILE,
};

/*
 * Read data from fscache and fill the read data into page cache described by
 * @start/len, which shall be both aligned with PAGE_SIZE. @pstart describes
 * the start physical address in the cache file.
 */
static int erofs_fscache_data_read(struct fscache_cookie *cookie,
				     struct address_space *mapping,
				     loff_t start, size_t len,
				     loff_t pstart)
{
	enum netfs_read_source source;
	struct netfs_read_request rreq = {};
	struct netfs_read_subrequest subreq = { .rreq = &rreq, };
	struct netfs_cache_resources *cres = &rreq.cache_resources;
	struct super_block *sb = mapping->host->i_sb;
	struct iov_iter iter;
	size_t done = 0;
	int ret;

	ret = fscache_begin_read_operation(&rreq, cookie);
	if (ret)
		return ret;

	while (done < len) {
		subreq.start = pstart + done;
		subreq.len = len - done;
		subreq.flags = 1 << NETFS_SREQ_ONDEMAND;

		source = cres->ops->prepare_read(&subreq, LLONG_MAX);
		if (WARN_ON(subreq.len == 0))
			source = NETFS_INVALID_READ;
		if (source != NETFS_READ_FROM_CACHE) {
			erofs_err(sb, "failed to fscache prepare_read (source %d)",
				  source);
			ret = -EIO;
			goto out;
		}

		iov_iter_xarray(&iter, READ, &mapping->i_pages,
				start + done, subreq.len);
		ret = cres->ops->read(cres, subreq.start, &iter,
				   true, NULL, NULL);
		if (ret) {
			erofs_err(sb, "failed to fscache_read (ret %d)", ret);
			goto out;
		}

		done += subreq.len;
	}
out:
	cres->ops->end_operation(cres);
	return ret;
}

static int erofs_fscache_meta_readpage(struct file *data, struct page *page)
{
	int ret;
	struct super_block *sb = page_mapping(page)->host->i_sb;
	struct erofs_map_dev mdev = {
		.m_deviceid = 0,
		.m_pa = page_offset(page),
	};

	ret = erofs_map_dev(sb, &mdev);
	if (ret)
		goto out;

	ret = erofs_fscache_data_read(mdev.m_fscache->cookie,
	               page_mapping(page), page_offset(page),
	               page_size(page), mdev.m_pa);
	if (!ret)
		SetPageUptodate(page);
	out:
	unlock_page(page);
	return ret;
}

static int erofs_fscache_readpage_inline(struct page *page,
                                        struct erofs_map_blocks *map)
{
	struct super_block *sb = page_mapping(page)->host->i_sb;
	struct erofs_buf buf = __EROFS_BUF_INITIALIZER;
	erofs_blk_t blknr;
	size_t offset, len;
	void *src, *dst;

	/* For tail packing layout, the offset may be non-zero. */
	offset = erofs_blkoff(map->m_pa);
	blknr = erofs_blknr(map->m_pa);
	len = map->m_llen;

	src = erofs_read_metabuf(&buf, sb, blknr, EROFS_KMAP);
	if (IS_ERR(src))
		return PTR_ERR(src);

	dst = kmap_atomic(page);
	memcpy(dst, src + offset, len);
	memset(dst + len, 0, PAGE_SIZE - len);
	kunmap_atomic(dst);

	erofs_put_metabuf(&buf);
	return 0;
}


static int erofs_fscache_readpage(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct super_block *sb = inode->i_sb;
	struct erofs_map_blocks map;
	struct erofs_map_dev mdev;
	erofs_off_t pos;
	loff_t pstart;
	int ret;

	DBG_BUGON(page_size(page) != EROFS_BLKSIZ);

	pos = page_offset(page);
	map.m_la = pos;

	ret = erofs_map_blocks(inode, &map, EROFS_GET_BLOCKS_RAW);
	if (ret)
		goto out_unlock;

	if (!(map.m_flags & EROFS_MAP_MAPPED)) {
		zero_user_segments(page, 0, page_size(page), 0, 0);
		goto out_uptodate;
	}

	if (map.m_flags & EROFS_MAP_META) {
		ret = erofs_fscache_readpage_inline(page, &map);
		goto out_uptodate;
	}

	mdev = (struct erofs_map_dev) {
		.m_deviceid = map.m_deviceid,
		.m_pa = map.m_pa,
	};

	ret = erofs_map_dev(sb, &mdev);
	if (ret)
		goto out_unlock;

	pstart = mdev.m_pa + (pos - map.m_la);
	ret = erofs_fscache_data_read(mdev.m_fscache->cookie,
	       page->mapping, page_offset(page),
	       page_size(page), pstart);

out_uptodate:
	if (!ret)
		SetPageUptodate(page);
out_unlock:
	unlock_page(page);
	return ret;
}

static const struct address_space_operations erofs_fscache_meta_aops = {
	.readpage = erofs_fscache_meta_readpage,
};

const struct address_space_operations erofs_fscache_access_aops = {
	.readpage = erofs_fscache_readpage,
};


int erofs_fscache_register_cookie(struct super_block *sb,
				  struct erofs_fscache **fscache,
				  char *name, bool need_inode)
{
	struct erofs_fscache *ctx;
	struct fscache_cookie *cookie;
	int ret;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	cookie = fscache_acquire_cookie(EROFS_SB(sb)->volume,
					&erofs_fscache_inode_object_def,
					name, strlen(name),
					NULL, 0, NULL, 0, true);
	if (!cookie) {
		erofs_err(sb, "failed to get cookie for %s", name);
		ret = -EINVAL;
		goto err;
	}

	ctx->cookie = cookie;

	if (need_inode) {
		struct inode *const inode = new_inode(sb);

		if (!inode) {
			erofs_err(sb, "failed to get anon inode for %s", name);
			ret = -ENOMEM;
			goto err_cookie;
		}

		set_nlink(inode, 1);
		inode->i_size = OFFSET_MAX;
		inode->i_mapping->a_ops = &erofs_fscache_meta_aops;
		mapping_set_gfp_mask(inode->i_mapping, GFP_NOFS);

		ctx->inode = inode;
	}

	*fscache = ctx;
	return 0;

err_cookie:
	fscache_relinquish_cookie(ctx->cookie, NULL, false);
	ctx->cookie = NULL;
err:
	kfree(ctx);
	return ret;
}

void erofs_fscache_unregister_cookie(struct erofs_fscache **fscache)
{
	struct erofs_fscache *ctx = *fscache;

	if (!ctx)
		return;

	fscache_relinquish_cookie(ctx->cookie, NULL, false);
	ctx->cookie = NULL;

	iput(ctx->inode);
	ctx->inode = NULL;

	kfree(ctx);
	*fscache = NULL;
}

int erofs_fscache_register_fs(struct super_block *sb)
{

	struct erofs_sb_info *sbi = EROFS_SB(sb);
	struct fscache_cookie *volume;
	char *name;
	int ret = 0;

	name = kasprintf(GFP_KERNEL, "erofs,%s", sbi->opt.fsid);
	if (!name)
		return -ENOMEM;

	volume = fscache_acquire_cookie(erofs_fscache_netfs.primary_index,
			&erofs_fscache_super_index_def, name, strlen(name),
			NULL, 0, NULL, 0, true);
	if (IS_ERR_OR_NULL(volume)) {
		erofs_err(sb, "failed to register volume for %s", name);
		ret = volume ? PTR_ERR(volume) : -EOPNOTSUPP;
		volume = NULL;
	}
	sbi->volume = volume;
	kfree(name);
	return ret;
}

void erofs_fscache_unregister_fs(struct super_block *sb)
{
	struct erofs_sb_info *sbi = EROFS_SB(sb);

	fscache_relinquish_cookie(sbi->volume, NULL, false);
	sbi->volume = NULL;
}
