#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/xsecurity.h>
#include <linux/xinternal.h>

void
x_log_chdir(const struct dentry *dentry, const struct vfsmount *mnt)
{
#ifdef CONFIG_XKERNSEC_AUDIT_CHDIR
	if ((xsec_enable_chdir && xsec_enable_group &&
	     in_group_p(xsec_audit_gid)) || (xsec_enable_chdir &&
					      !xsec_enable_group)) {
		x_log_fs_generic(X_DO_AUDIT, X_CHDIR_AUDIT_MSG, dentry, mnt);
	}
#endif
	return;
}
