#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/xinternal.h>
#include <linux/security.h>

void
x_audit_ptrace(struct task_struct *task)
{
#ifdef CONFIG_XKERNSEC_AUDIT_PTRACE
	if (xsec_enable_audit_ptrace)
		x_log_ptrace(X_DO_AUDIT, X_PTRACE_AUDIT_MSG, task);
#endif
	return;
}

int
x_ptrace_readexec(struct file *file, int unsafe_flags)
{
#ifdef CONFIG_XKERNSEC_PTRACE_READEXEC
	const struct dentry *dentry = file->f_path.dentry;
	const struct vfsmount *mnt = file->f_path.mnt;

	if (xsec_enable_ptrace_readexec && (unsafe_flags & LSM_UNSAFE_PTRACE) &&
	    (inode_permission(d_backing_inode(dentry), MAY_READ) || !x_acl_handle_open(dentry, mnt, MAY_READ))) {
		x_log_fs_generic(X_DONT_AUDIT, X_PTRACE_READEXEC_MSG, dentry, mnt);
		return -EACCES;
	}
#endif
	return 0;
}
