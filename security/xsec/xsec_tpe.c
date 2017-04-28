#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/xinternal.h>

extern int x_acl_tpe_check(void);

int
x_tpe_allow(const struct file *file)
{
#ifdef CONFIG_XKERNSEC
	struct inode *inode = d_backing_inode(file->f_path.dentry->d_parent);
	struct inode *file_inode = d_backing_inode(file->f_path.dentry);
	const struct cred *cred = current_cred();
	char *msg = NULL;
	char *msg2 = NULL;

	// never restrict root
	if (x_is_global_root(cred->uid))
		return 1;

	if (xsec_enable_tpe) {
#ifdef CONFIG_XKERNSEC_TPE_INVERT
		if (xsec_enable_tpe_invert && !in_group_p(xsec_tpe_gid))
			msg = "not being in trusted group";
		else if (!xsec_enable_tpe_invert && in_group_p(xsec_tpe_gid))
			msg = "being in untrusted group";
#else
		if (in_group_p(xsec_tpe_gid))
			msg = "being in untrusted group";
#endif
	}
	if (!msg && x_acl_tpe_check())
		msg = "being in untrusted role";

	// not in any affected group/role
	if (!msg)
		goto next_check;

	if (x_is_global_nonroot(inode->i_uid))
		msg2 = "file in non-root-owned directory";
	else if (inode->i_mode & S_IWOTH)
		msg2 = "file in world-writable directory";
	else if ((inode->i_mode & S_IWGRP) && x_is_global_nonroot_gid(inode->i_gid))
		msg2 = "file in group-writable directory";
	else if (file_inode->i_mode & S_IWOTH)
		msg2 = "file is world-writable";

	if (msg && msg2) {
		char fullmsg[70] = {0};
		snprintf(fullmsg, sizeof(fullmsg)-1, "%s and %s", msg, msg2);
		x_log_str_fs(X_DONT_AUDIT, X_EXEC_TPE_MSG, fullmsg, file->f_path.dentry, file->f_path.mnt);
		return 0;
	}
	msg = NULL;
next_check:
#ifdef CONFIG_XKERNSEC_TPE_ALL
	if (!xsec_enable_tpe || !xsec_enable_tpe_all)
		return 1;

	if (x_is_global_nonroot(inode->i_uid) && !uid_eq(inode->i_uid, cred->uid))
		msg = "directory not owned by user";
	else if (inode->i_mode & S_IWOTH)
		msg = "file in world-writable directory";
	else if ((inode->i_mode & S_IWGRP) && x_is_global_nonroot_gid(inode->i_gid))
		msg = "file in group-writable directory";
	else if (file_inode->i_mode & S_IWOTH)
		msg = "file is world-writable";

	if (msg) {
		x_log_str_fs(X_DONT_AUDIT, X_EXEC_TPE_MSG, msg, file->f_path.dentry, file->f_path.mnt);
		return 0;
	}
#endif
#endif
	return 1;
}
