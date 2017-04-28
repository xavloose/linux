#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mount.h>
#include <linux/major.h>
#include <linux/xsecurity.h>
#include <linux/xinternal.h>

void
x_log_remount(const char *devname, const int retval)
{
#ifdef CONFIG_XKERNSEC_AUDIT_MOUNT
	if (xsec_enable_mount && (retval >= 0))
		x_log_str(X_DO_AUDIT, X_REMOUNT_AUDIT_MSG, devname ? devname : "none");
#endif
	return;
}

void
x_log_unmount(const char *devname, const int retval)
{
#ifdef CONFIG_XKERNSEC_AUDIT_MOUNT
	if (xsec_enable_mount && (retval >= 0))
		x_log_str(X_DO_AUDIT, X_UNMOUNT_AUDIT_MSG, devname ? devname : "none");
#endif
	return;
}

void
x_log_mount(const char *from, struct path *to, const int retval)
{
#ifdef CONFIG_XKERNSEC_AUDIT_MOUNT
	if (xsec_enable_mount && (retval >= 0))
		x_log_str_fs(X_DO_AUDIT, X_MOUNT_AUDIT_MSG, from ? from : "none", to->dentry, to->mnt);
#endif
	return;
}

int
x_handle_rofs_mount(struct dentry *dentry, struct vfsmount *mnt, int mnt_flags)
{
#ifdef CONFIG_XKERNSEC_ROFS
	if (xsec_enable_rofs && !(mnt_flags & MNT_READONLY)) {
		x_log_fs_generic(X_DO_AUDIT, X_ROFS_MOUNT_MSG, dentry, mnt);
		return -EPERM;
	} else
		return 0;
#endif
	return 0;
}

int
x_handle_rofs_blockwrite(struct dentry *dentry, struct vfsmount *mnt, int acc_mode)
{
#ifdef CONFIG_XKERNSEC_ROFS
	struct inode *inode = d_backing_inode(dentry);

	if (xsec_enable_rofs && (acc_mode & MAY_WRITE) &&
	    inode && (S_ISBLK(inode->i_mode) || (S_ISCHR(inode->i_mode) && imajor(inode) == RAW_MAJOR))) {
		x_log_fs_generic(X_DO_AUDIT, X_ROFS_BLOCKWRITE_MSG, dentry, mnt);
		return -EPERM;
	} else
		return 0;
#endif
	return 0;
}
