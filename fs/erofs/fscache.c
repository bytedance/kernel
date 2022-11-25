/*
 * Copyright (C) 2022, Alibaba Cloud
 * Copyright (C) 2022, Bytedance Inc. All rights reserved.
 */
#define FSCACHE_USE_NEW_IO_API
#include <linux/fscache.h>
#include <linux/netfs.h>
#include <linux/uio.h>
#include <linux/mount.h>
#include "internal.h"

static DEFINE_MUTEX(erofs_domain_list_lock);
static DEFINE_MUTEX(erofs_domain_cookies_lock);
static LIST_HEAD(erofs_domain_list);
static struct vfsmount *erofs_pseudo_mnt;

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

static void erofs_fscache_free_request(struct work_struct *work)
{
	struct netfs_read_request *rreq =
		container_of(work, struct netfs_read_request, work);

	if (rreq->cache_resources.ops)
		rreq->cache_resources.ops->end_operation(&rreq->cache_resources);
	kfree(rreq);
}

static struct netfs_read_request *erofs_fscache_alloc_request(struct address_space *mapping,
					     loff_t start, size_t len)
{
	struct netfs_read_request *rreq;

	rreq = kzalloc(sizeof(struct netfs_read_request), GFP_KERNEL);
	if (!rreq)
		return ERR_PTR(-ENOMEM);

	rreq->start	= start;
	rreq->len	= len;
	rreq->mapping	= mapping;
	INIT_LIST_HEAD(&rreq->subrequests);
	INIT_WORK(&rreq->work, erofs_fscache_free_request);
	refcount_set(&rreq->usage, 1);
	return rreq;
}

static void erofs_fscache_put_request(struct netfs_read_request *rreq, bool was_async)
{
	if (!refcount_dec_and_test(&rreq->usage))
		return;
	if (was_async) {
		if (!queue_work(system_unbound_wq, &rreq->work))
			BUG();
	} else
		erofs_fscache_free_request(&rreq->work);
}

static void erofs_fscache_put_subrequest(struct netfs_read_subrequest *subreq, bool was_async)
{
	if (!refcount_dec_and_test(&subreq->usage))
		return;
	erofs_fscache_put_request(subreq->rreq, was_async);
	kfree(subreq);
}

static void erofs_fscache_clear_subrequests(struct netfs_read_request *rreq, bool was_async)
{
	struct netfs_read_subrequest *subreq;

	while (!list_empty(&rreq->subrequests)) {
		subreq = list_first_entry(&rreq->subrequests,
				struct netfs_read_subrequest, rreq_link);
		list_del(&subreq->rreq_link);
		erofs_fscache_put_subrequest(subreq, was_async);
	}
}

static void erofs_fscache_rreq_unlock_pages(struct netfs_read_request *rreq)
{
	struct netfs_read_subrequest *subreq;
	struct page *page;
	unsigned int iopos = 0;
	pgoff_t start_page = rreq->start / PAGE_SIZE;
	pgoff_t last_page = ((rreq->start + rreq->len) / PAGE_SIZE) - 1;
	bool subreq_failed = false;

	XA_STATE(xas, &rreq->mapping->i_pages, start_page);

	subreq = list_first_entry(&rreq->subrequests,
				  struct netfs_read_subrequest, rreq_link);
	subreq_failed = (subreq->error < 0);

	rcu_read_lock();
	xas_for_each(&xas, page, last_page) {
		unsigned int pgpos, pgend;
		bool pg_failed = false;

		if (xas_retry(&xas, page))
			continue;

		pgpos = (page_index(page) - start_page) * PAGE_SIZE;
		pgend = pgpos + PAGE_SIZE;

		for (;;) {
			if (!subreq) {
				pg_failed = true;
				break;
			}

			pg_failed |= subreq_failed;
			if (pgend < iopos + subreq->len)
				break;

			iopos += subreq->len;
			if (!list_is_last(&subreq->rreq_link,
					  &rreq->subrequests)) {
				subreq = list_next_entry(subreq, rreq_link);
				subreq_failed = (subreq->error < 0);
			} else {
				subreq = NULL;
				subreq_failed = false;
			}
			if (pgend == iopos)
				break;
		}

		if (!pg_failed)
			SetPageUptodate(page);

		unlock_page(page);
	}
	rcu_read_unlock();
}

static void erofs_fscache_rreq_complete(struct netfs_read_request *rreq, bool was_async)
{
	erofs_fscache_rreq_unlock_pages(rreq);
	erofs_fscache_clear_subrequests(rreq, was_async);
	erofs_fscache_put_request(rreq, was_async);
}

static void erofs_fscache_subreq_complete(void *priv,
		ssize_t transferred_or_error, bool was_async)
{
	struct netfs_read_subrequest *subreq = priv;
	struct netfs_read_request *rreq = subreq->rreq;

	if (IS_ERR_VALUE(transferred_or_error))
		subreq->error = transferred_or_error;

	if (atomic_dec_and_test(&rreq->nr_rd_ops))
		erofs_fscache_rreq_complete(rreq, was_async);

	erofs_fscache_put_subrequest(subreq, was_async);
}

/*
 * Read data from fscache and fill the read data into page cache described by
 * @rreq, which shall be both aligned with PAGE_SIZE. @pstart describes
 * the start physical address in the cache file.
 */
static int erofs_fscache_data_read_async(struct fscache_cookie *cookie,
				     struct netfs_read_request *rreq, loff_t pstart)
{
	enum netfs_read_source source;
	struct super_block *sb = rreq->mapping->host->i_sb;
	struct netfs_read_subrequest *subreq;
	struct netfs_cache_resources *cres = &rreq->cache_resources;
	struct iov_iter iter;
	loff_t start = rreq->start;
	size_t len = rreq->len;
	size_t done = 0;
	int ret;

	if (len == 0)
		return 0;
	atomic_set(&rreq->nr_rd_ops, 1);

	ret = fscache_begin_read_operation(rreq, cookie);
	if (ret)
		goto out;

	while (done < len) {
		subreq = kzalloc(sizeof(struct netfs_read_subrequest),
				 GFP_KERNEL);
		if (subreq) {
			INIT_LIST_HEAD(&subreq->rreq_link);
			refcount_set(&subreq->usage, 2);
			subreq->rreq = rreq;
			refcount_inc(&rreq->usage);
		} else {
			ret = -ENOMEM;
			goto out;
		}

		subreq->start = pstart + done;
		subreq->len	=  len - done;
		subreq->flags = 1 << NETFS_SREQ_ONDEMAND;

		list_add_tail(&subreq->rreq_link, &rreq->subrequests);

		source = cres->ops->prepare_read(subreq, LLONG_MAX);
		if (WARN_ON(subreq->len == 0))
			source = NETFS_INVALID_READ;
		if (source != NETFS_READ_FROM_CACHE) {
			erofs_err(sb, "failed to fscache prepare_read (source %d)",
				  source);
			ret = -EIO;
			subreq->error = ret;
			erofs_fscache_put_subrequest(subreq, false);
			goto out;
		}

		atomic_inc(&rreq->nr_rd_ops);

		iov_iter_xarray(&iter, READ, &rreq->mapping->i_pages,
				start + done, subreq->len);

		ret = cres->ops->read(cres, subreq->start, &iter,
				   true, erofs_fscache_subreq_complete, subreq);
		if (ret == -EIOCBQUEUED)
			ret = 0;
		if (ret) {
			erofs_err(sb, "failed to fscache_read (ret %d)", ret);
			goto out;
		}
		done += subreq->len;
	}
out:
	if (atomic_dec_and_test(&rreq->nr_rd_ops))
		erofs_fscache_rreq_complete(rreq, false);

	return ret;
}

static int erofs_fscache_meta_readpage(struct file *data, struct page *page)
{
	int ret;
	struct super_block *sb = page_mapping(page)->host->i_sb;
	struct netfs_read_request *rreq;
	struct erofs_map_dev mdev = {
		.m_deviceid = 0,
		.m_pa = page_offset(page),
	};

	ret = erofs_map_dev(sb, &mdev);
	if (ret)
		goto out;

	rreq = erofs_fscache_alloc_request(page_mapping(page),
				page_offset(page), PAGE_SIZE);
	if (IS_ERR(rreq)) {
		ret = PTR_ERR(rreq);
		goto out;
	}

	return erofs_fscache_data_read_async(mdev.m_fscache->cookie,
				rreq, mdev.m_pa);
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
	struct netfs_read_request *rreq;
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


	rreq = erofs_fscache_alloc_request(page_mapping(page),
				page_offset(page), PAGE_SIZE);
	if (IS_ERR(rreq)) {
		ret = PTR_ERR(rreq);
		goto out_unlock;
	}
	pstart = mdev.m_pa + (pos - map.m_la);
	return erofs_fscache_data_read_async(mdev.m_fscache->cookie,
				rreq, pstart);

out_uptodate:
	if (!ret)
		SetPageUptodate(page);
out_unlock:
	unlock_page(page);
	return ret;
}

static int erofs_fscache_readpages(struct file *filp, struct address_space *mapping,
                       struct list_head *pages, unsigned int nr_pages)
{
	struct inode *inode = mapping->host;
	struct super_block *sb = inode->i_sb;
	size_t len, count, done = 0;
	erofs_off_t pos;
	loff_t start, offset;
	int ret;
	struct page *page;

	if (!nr_pages)
		return 0;

	start = page_offset(lru_to_page(pages));
	len = nr_pages * PAGE_SIZE;

	do {
		struct erofs_map_blocks map;
		struct erofs_map_dev mdev;
		struct netfs_read_request *rreq;
		unsigned int i, batch;

		pos = start + done;
		map.m_la = pos;

		ret = erofs_map_blocks(inode, &map, EROFS_GET_BLOCKS_RAW);
		if (ret)
			return ret;

		offset = start + done;
		count = min_t(size_t, map.m_llen - (pos - map.m_la),
						len - done);

		if (!(map.m_flags & EROFS_MAP_MAPPED)) {
			page = lru_to_page(pages);

			list_del(&page->lru);
			ret = add_to_page_cache_lru(page, mapping, page->index,
					readahead_gfp_mask(mapping));
			if (ret) {
				put_page(page);
				return ret;
			}
			zero_user_segment(page, 0, PAGE_SIZE);
			SetPageUptodate(page);
			unlock_page(page);
			put_page(page);
			ret = PAGE_SIZE;
			continue;
		}

		if (map.m_flags & EROFS_MAP_META) {
			page = lru_to_page(pages);

			list_del(&page->lru);
			ret = add_to_page_cache_lru(page, mapping, page->index,
					readahead_gfp_mask(mapping));
			if (ret) {
				put_page(page);
				return ret;
			}
			ret = erofs_fscache_readpage_inline(page, &map);
			if (!ret) {
				SetPageUptodate(page);
				ret = PAGE_SIZE;
			}
			unlock_page(page);
			put_page(page);
			continue;
		}

		mdev = (struct erofs_map_dev) {
			.m_deviceid = map.m_deviceid,
			.m_pa = map.m_pa,
		};
		ret = erofs_map_dev(sb, &mdev);
		if (ret)
			return ret;

		rreq = erofs_fscache_alloc_request(mapping,
				offset, count);
		if (IS_ERR(rreq))
			return PTR_ERR(rreq);
		/*
		 * Drop the ref of page here. Unlock them in
		 * rreq_unlock_pages() when rreq complete.
		 */
		if (WARN_ON(count % PAGE_SIZE))
			return 0;
		batch = count >> PAGE_SHIFT;

		for (i = 0; i < batch; i++) {
			page = lru_to_page(pages);
			if (WARN_ON(page_offset(page) != (pos + PAGE_SIZE * i))) {
				return 0;
			}
			list_del(&page->lru);
			ret = add_to_page_cache_lru(page, mapping, page->index,
					readahead_gfp_mask(mapping));
			if (ret) {
				put_page(page);
				/* only process pages already added to page cache,
				 * skip the failed page in next loop.
				 */
				rreq->len = i * PAGE_SIZE;
				count = rreq->len + PAGE_SIZE;
				break;
			}
			put_page(page);
		}

		ret = erofs_fscache_data_read_async(mdev.m_fscache->cookie,
				rreq, mdev.m_pa + (pos - map.m_la));
		if (!ret)
			ret = count;
	} while (ret > 0 && ((done += ret) < len));
	return ret;
}

static const struct address_space_operations erofs_fscache_meta_aops = {
	.readpage = erofs_fscache_meta_readpage,
};

const struct address_space_operations erofs_fscache_access_aops = {
	.readpage = erofs_fscache_readpage,
	.readpages = erofs_fscache_readpages,
};

static void erofs_fscache_domain_put(struct erofs_domain *domain)
{
	if (!domain)
		return;
	mutex_lock(&erofs_domain_list_lock);
	if (refcount_dec_and_test(&domain->ref)) {
		list_del(&domain->list);
		if (list_empty(&erofs_domain_list)) {
			kern_unmount(erofs_pseudo_mnt);
			erofs_pseudo_mnt = NULL;
		}
		mutex_unlock(&erofs_domain_list_lock);
		fscache_relinquish_cookie(domain->volume, NULL, false);
		kfree(domain->domain_id);
		kfree(domain);
		return;
	}
	mutex_unlock(&erofs_domain_list_lock);
}

static int erofs_fscache_register_volume(struct super_block *sb)
{
	struct erofs_sb_info *sbi = EROFS_SB(sb);
	struct fscache_cookie *volume;
	char *domain_id = sbi->domain_id;
	char *name;
	int ret = 0;

	name = kasprintf(GFP_KERNEL, "erofs,%s",
			 domain_id ? domain_id : sbi->fsid);
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

static int erofs_fscache_init_domain(struct super_block *sb)
{
	int err;
	struct erofs_domain *domain;
	struct erofs_sb_info *sbi = EROFS_SB(sb);

	domain = kzalloc(sizeof(struct erofs_domain), GFP_KERNEL);
	if (!domain)
		return -ENOMEM;

	domain->domain_id = kstrdup(sbi->domain_id, GFP_KERNEL);
	if (!domain->domain_id) {
		kfree(domain);
		return -ENOMEM;
	}

	err = erofs_fscache_register_volume(sb);
	if (err)
		goto out;

	if (!erofs_pseudo_mnt) {
		erofs_pseudo_mnt = kern_mount(&erofs_fs_type);
		if (IS_ERR(erofs_pseudo_mnt)) {
			err = PTR_ERR(erofs_pseudo_mnt);
			goto out;
		}
	}

	domain->volume = sbi->volume;
	refcount_set(&domain->ref, 1);
	list_add(&domain->list, &erofs_domain_list);
	sbi->domain = domain;
	return 0;
out:
	kfree(domain->domain_id);
	kfree(domain);
	return err;
}

static int erofs_fscache_register_domain(struct super_block *sb)
{
	int err;
	struct erofs_domain *domain;
	struct erofs_sb_info *sbi = EROFS_SB(sb);

	mutex_lock(&erofs_domain_list_lock);
	list_for_each_entry(domain, &erofs_domain_list, list) {
		if (!strcmp(domain->domain_id, sbi->domain_id)) {
			sbi->domain = domain;
			sbi->volume = domain->volume;
			refcount_inc(&domain->ref);
			mutex_unlock(&erofs_domain_list_lock);
			return 0;
		}
	}
	err = erofs_fscache_init_domain(sb);
	mutex_unlock(&erofs_domain_list_lock);
	return err;
}

static
struct erofs_fscache *erofs_fscache_acquire_cookie(struct super_block *sb,
						   char *name,
						   unsigned int flags)
{
	struct erofs_fscache *ctx;
	struct fscache_cookie *cookie;
	int ret;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

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

	if (flags & EROFS_REG_COOKIE_NEED_INODE) {
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

	return ctx;

err_cookie:
	fscache_relinquish_cookie(ctx->cookie, NULL, false);
err:
	kfree(ctx);
	return ERR_PTR(ret);
}

static void erofs_fscache_relinquish_cookie(struct erofs_fscache *ctx)
{
	if (!ctx)
		return;

	fscache_relinquish_cookie(ctx->cookie, NULL, false);
	iput(ctx->inode);
	kfree(ctx->name);
	kfree(ctx);
}

static
struct erofs_fscache *erofs_fscache_domain_init_cookie(struct super_block *sb,
						       char *name,
						       unsigned int flags)
{
	int err;
	struct inode *inode;
	struct erofs_fscache *ctx;
	struct erofs_domain *domain = EROFS_SB(sb)->domain;

	ctx = erofs_fscache_acquire_cookie(sb, name, flags);
	if (IS_ERR(ctx))
		return ctx;

	ctx->name = kstrdup(name, GFP_KERNEL);
	if (!ctx->name) {
		err = -ENOMEM;
		goto out;
	}

	inode = new_inode(erofs_pseudo_mnt->mnt_sb);
	if (!inode) {
		err = -ENOMEM;
		goto out;
	}

	ctx->domain = domain;
	ctx->anon_inode = inode;
	inode->i_private = ctx;
	refcount_inc(&domain->ref);
	return ctx;
out:
	erofs_fscache_relinquish_cookie(ctx);
	return ERR_PTR(err);
}

static
struct erofs_fscache *erofs_domain_register_cookie(struct super_block *sb,
						   char *name,
						   unsigned int flags)
{
	struct inode *inode;
	struct erofs_fscache *ctx;
	struct erofs_domain *domain = EROFS_SB(sb)->domain;
	struct super_block *psb = erofs_pseudo_mnt->mnt_sb;

	mutex_lock(&erofs_domain_cookies_lock);
	spin_lock(&psb->s_inode_list_lock);
	list_for_each_entry(inode, &psb->s_inodes, i_sb_list) {
		ctx = inode->i_private;
		if (!ctx || ctx->domain != domain || strcmp(ctx->name, name))
			continue;
		if (!(flags & EROFS_REG_COOKIE_NEED_NOEXIST)) {
			igrab(inode);
		} else {
			erofs_err(sb, "%s already exists in domain %s", name,
				  domain->domain_id);
			ctx = ERR_PTR(-EEXIST);
		}
		spin_unlock(&psb->s_inode_list_lock);
		mutex_unlock(&erofs_domain_cookies_lock);
		return ctx;
	}
	spin_unlock(&psb->s_inode_list_lock);
	ctx = erofs_fscache_domain_init_cookie(sb, name, flags);
	mutex_unlock(&erofs_domain_cookies_lock);
	return ctx;
}

struct erofs_fscache *erofs_fscache_register_cookie(struct super_block *sb,
						    char *name,
						    unsigned int flags)
{
	if (EROFS_SB(sb)->domain_id)
		return erofs_domain_register_cookie(sb, name, flags);
	return erofs_fscache_acquire_cookie(sb, name, flags);
}

void erofs_fscache_unregister_cookie(struct erofs_fscache *ctx)
{
	bool drop;
	struct erofs_domain *domain;

	if (!ctx)
		return;
	domain = ctx->domain;
	if (domain) {
		mutex_lock(&erofs_domain_cookies_lock);
		drop = atomic_read(&ctx->anon_inode->i_count) == 1;
		iput(ctx->anon_inode);
		mutex_unlock(&erofs_domain_cookies_lock);
		if (!drop)
			return;
	}

	erofs_fscache_relinquish_cookie(ctx);
	erofs_fscache_domain_put(domain);
}

int erofs_fscache_register_fs(struct super_block *sb)
{
	int ret;
	struct erofs_sb_info *sbi = EROFS_SB(sb);
	struct erofs_fscache *fscache;
	unsigned int flags;

	if (sbi->domain_id)
		ret = erofs_fscache_register_domain(sb);
	else
		ret = erofs_fscache_register_volume(sb);
	if (ret)
		return ret;

	/*
	 * When shared domain is enabled, using NEED_NOEXIST to guarantee
	 * the primary data blob (aka fsid) is unique in the shared domain.
	 *
	 * For non-shared-domain case, fscache_acquire_volume() invoked by
	 * erofs_fscache_register_volume() has already guaranteed
	 * the uniqueness of primary data blob.
	 *
	 * Acquired domain/volume will be relinquished in kill_sb() on error.
	 */
	flags = EROFS_REG_COOKIE_NEED_INODE;
	if (sbi->domain_id)
		flags |= EROFS_REG_COOKIE_NEED_NOEXIST;
	fscache = erofs_fscache_register_cookie(sb, sbi->fsid, flags);
	if (IS_ERR(fscache))
		return PTR_ERR(fscache);

	sbi->s_fscache = fscache;
	return 0;
}

void erofs_fscache_unregister_fs(struct super_block *sb)
{
	struct erofs_sb_info *sbi = EROFS_SB(sb);

	erofs_fscache_unregister_cookie(sbi->s_fscache);

	if (sbi->domain)
		erofs_fscache_domain_put(sbi->domain);
	else
		fscache_relinquish_cookie(sbi->volume, NULL, false);

	sbi->s_fscache = NULL;
	sbi->volume = NULL;
	sbi->domain = NULL;
}
