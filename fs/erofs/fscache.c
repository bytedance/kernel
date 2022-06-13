/*
 * Copyright (C) 2022, Alibaba Cloud
 */
#include <linux/fscache.h>
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

int erofs_fscache_register_cookie(struct super_block *sb,
				  struct erofs_fscache **fscache, char *name)
{
	struct erofs_fscache *ctx;
	struct fscache_cookie *cookie;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	cookie = fscache_acquire_cookie(EROFS_SB(sb)->volume,
					&erofs_fscache_inode_object_def,
					name, strlen(name),
					NULL, 0, NULL, 0, true);
	if (!cookie) {
		erofs_err(sb, "failed to get cookie for %s", name);
		kfree(ctx);
		return -EINVAL;
	}

	ctx->cookie = cookie;

	*fscache = ctx;
	return 0;
}

void erofs_fscache_unregister_cookie(struct erofs_fscache **fscache)
{
	struct erofs_fscache *ctx = *fscache;

	if (!ctx)
		return;

	fscache_relinquish_cookie(ctx->cookie, NULL, false);
	ctx->cookie = NULL;

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
