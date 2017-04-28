#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/xsec.h>
#include <linux/xinternal.h>
#include <linux/xacl.h>

umode_t
x_acl_umask(void)
{
	if (unlikely(!x_acl_is_enabled()))
		return 0;

	return current->role->umask;
}

__u32
x_acl_handle_hidden_file(const struct dentry * dentry,
			  const struct vfsmount * mnt)
{
	__u32 mode;

	if (unlikely(d_is_negative(dentry)))
		return X_FIND;

	mode =
	    x_search_file(dentry, X_FIND | X_AUDIT_FIND | X_SUPPRESS, mnt);

	if (unlikely(mode & X_FIND && mode & X_AUDIT_FIND)) {
		x_log_fs_rbac_generic(X_DO_AUDIT, X_HIDDEN_ACL_MSG, dentry, mnt);
		return mode;
	} else if (unlikely(!(mode & X_FIND) && !(mode & X_SUPPRESS))) {
		x_log_fs_rbac_generic(X_DONT_AUDIT, X_HIDDEN_ACL_MSG, dentry, mnt);
		return 0;
	} else if (unlikely(!(mode & X_FIND)))
		return 0;

	return X_FIND;
}

__u32
x_acl_handle_open(const struct dentry * dentry, const struct vfsmount * mnt,
		   int acc_mode)
{
	__u32 reqmode = X_FIND;
	__u32 mode;

	if (unlikely(d_is_negative(dentry)))
		return reqmode;

	if (acc_mode & MAY_APPEND)
		reqmode |= X_APPEND;
	else if (acc_mode & MAY_WRITE)
		reqmode |= X_WRITE;
	if ((acc_mode & MAY_READ) && !d_is_dir(dentry))
		reqmode |= X_READ;

	mode =
	    x_search_file(dentry, reqmode | to_x_audit(reqmode) | X_SUPPRESS,
			   mnt);

	if (unlikely(((mode & reqmode) == reqmode) && mode & X_AUDITS)) {
		x_log_fs_rbac_mode2(X_DO_AUDIT, X_OPEN_ACL_MSG, dentry, mnt,
			       reqmode & X_READ ? " reading" : "",
			       reqmode & X_WRITE ? " writing" : reqmode &
			       X_APPEND ? " appending" : "");
		return reqmode;
	} else
	    if (unlikely((mode & reqmode) != reqmode && !(mode & X_SUPPRESS)))
	{
		x_log_fs_rbac_mode2(X_DONT_AUDIT, X_OPEN_ACL_MSG, dentry, mnt,
			       reqmode & X_READ ? " reading" : "",
			       reqmode & X_WRITE ? " writing" : reqmode &
			       X_APPEND ? " appending" : "");
		return 0;
	} else if (unlikely((mode & reqmode) != reqmode))
		return 0;

	return reqmode;
}

__u32
x_acl_handle_creat(const struct dentry * dentry,
		    const struct dentry * p_dentry,
		    const struct vfsmount * p_mnt, int open_flags, int acc_mode,
		    const int imode)
{
	__u32 reqmode = X_WRITE | X_CREATE;
	__u32 mode;

	if (acc_mode & MAY_APPEND)
		reqmode |= X_APPEND;
	// if a directory was required or the directory already exists, then
	// don't count this open as a read
	if ((acc_mode & MAY_READ) &&
	    !((open_flags & O_DIRECTORY) || d_is_dir(dentry)))
		reqmode |= X_READ;
	if ((open_flags & O_CREAT) &&
	    ((imode & S_ISUID) || ((imode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP))))
		reqmode |= X_SETID;

	mode =
	    x_check_create(dentry, p_dentry, p_mnt,
			    reqmode | to_x_audit(reqmode) | X_SUPPRESS);

	if (unlikely(((mode & reqmode) == reqmode) && mode & X_AUDITS)) {
		x_log_fs_rbac_mode2(X_DO_AUDIT, X_CREATE_ACL_MSG, dentry, p_mnt,
			       reqmode & X_READ ? " reading" : "",
			       reqmode & X_WRITE ? " writing" : reqmode &
			       X_APPEND ? " appending" : "");
		return reqmode;
	} else
	    if (unlikely((mode & reqmode) != reqmode && !(mode & X_SUPPRESS)))
	{
		x_log_fs_rbac_mode2(X_DONT_AUDIT, X_CREATE_ACL_MSG, dentry, p_mnt,
			       reqmode & X_READ ? " reading" : "",
			       reqmode & X_WRITE ? " writing" : reqmode &
			       X_APPEND ? " appending" : "");
		return 0;
	} else if (unlikely((mode & reqmode) != reqmode))
		return 0;

	return reqmode;
}

__u32
x_acl_handle_access(const struct dentry * dentry, const struct vfsmount * mnt,
		     const int fmode)
{
	__u32 mode, reqmode = X_FIND;

	if ((fmode & S_IXOTH) && !d_is_dir(dentry))
		reqmode |= X_EXEC;
	if (fmode & S_IWOTH)
		reqmode |= X_WRITE;
	if (fmode & S_IROTH)
		reqmode |= X_READ;

	mode =
	    x_search_file(dentry, reqmode | to_x_audit(reqmode) | X_SUPPRESS,
			   mnt);

	if (unlikely(((mode & reqmode) == reqmode) && mode & X_AUDITS)) {
		x_log_fs_rbac_mode3(X_DO_AUDIT, X_ACCESS_ACL_MSG, dentry, mnt,
			       reqmode & X_READ ? " reading" : "",
			       reqmode & X_WRITE ? " writing" : "",
			       reqmode & X_EXEC ? " executing" : "");
		return reqmode;
	} else
	    if (unlikely((mode & reqmode) != reqmode && !(mode & X_SUPPRESS)))
	{
		x_log_fs_rbac_mode3(X_DONT_AUDIT, X_ACCESS_ACL_MSG, dentry, mnt,
			       reqmode & X_READ ? " reading" : "",
			       reqmode & X_WRITE ? " writing" : "",
			       reqmode & X_EXEC ? " executing" : "");
		return 0;
	} else if (unlikely((mode & reqmode) != reqmode))
		return 0;

	return reqmode;
}

static __u32 generic_fs_handler(const struct dentry *dentry, const struct vfsmount *mnt, __u32 reqmode, const char *fmt)
{
	__u32 mode;

	mode = x_search_file(dentry, reqmode | to_x_audit(reqmode) | X_SUPPRESS, mnt);

	if (unlikely(((mode & (reqmode)) == (reqmode)) && mode & X_AUDITS)) {
		x_log_fs_rbac_generic(X_DO_AUDIT, fmt, dentry, mnt);
		return mode;
	} else if (unlikely((mode & (reqmode)) != (reqmode) && !(mode & X_SUPPRESS))) {
		x_log_fs_rbac_generic(X_DONT_AUDIT, fmt, dentry, mnt);
		return 0;
	} else if (unlikely((mode & (reqmode)) != (reqmode)))
		return 0;

	return (reqmode);
}

__u32
x_acl_handle_rmdir(const struct dentry * dentry, const struct vfsmount * mnt)
{
	return generic_fs_handler(dentry, mnt, X_WRITE | X_DELETE , X_RMDIR_ACL_MSG);
}

__u32
x_acl_handle_unlink(const struct dentry *dentry, const struct vfsmount *mnt)
{
	return generic_fs_handler(dentry, mnt, X_WRITE | X_DELETE , X_UNLINK_ACL_MSG);
}

__u32
x_acl_handle_truncate(const struct dentry *dentry, const struct vfsmount *mnt)
{
	return generic_fs_handler(dentry, mnt, X_WRITE, X_TRUNCATE_ACL_MSG);
}

__u32
x_acl_handle_utime(const struct dentry *dentry, const struct vfsmount *mnt)
{
	return generic_fs_handler(dentry, mnt, X_WRITE, X_ATIME_ACL_MSG);
}

__u32
x_acl_handle_chmod(const struct dentry *dentry, const struct vfsmount *mnt,
		     umode_t *modeptr)
{
	umode_t mode;
	struct inode *inode = d_backing_inode(dentry);

	*modeptr &= ~x_acl_umask();
	mode = *modeptr;

	if (unlikely(inode && S_ISSOCK(inode->i_mode)))
		return 1;

	if (unlikely(!d_is_dir(dentry) &&
		     ((mode & S_ISUID) || ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP))))) {
		return generic_fs_handler(dentry, mnt, X_WRITE | X_SETID,
				   X_CHMOD_ACL_MSG);
	} else {
		return generic_fs_handler(dentry, mnt, X_WRITE, X_CHMOD_ACL_MSG);
	}
}

__u32
x_acl_handle_chown(const struct dentry *dentry, const struct vfsmount *mnt)
{
	return generic_fs_handler(dentry, mnt, X_WRITE, X_CHOWN_ACL_MSG);
}

__u32
x_acl_handle_setxattr(const struct dentry *dentry, const struct vfsmount *mnt)
{
	return generic_fs_handler(dentry, mnt, X_WRITE, X_SETXATTR_ACL_MSG);
}

__u32
x_acl_handle_removexattr(const struct dentry *dentry, const struct vfsmount *mnt)
{
	return generic_fs_handler(dentry, mnt, X_WRITE, X_REMOVEXATTR_ACL_MSG);
}

__u32
x_acl_handle_execve(const struct dentry *dentry, const struct vfsmount *mnt)
{
	return generic_fs_handler(dentry, mnt, X_EXEC, X_EXEC_ACL_MSG);
}

__u32
x_acl_handle_unix(const struct dentry *dentry, const struct vfsmount *mnt)
{
	return generic_fs_handler(dentry, mnt, X_READ | X_WRITE,
			   X_UNIXCONNECT_ACL_MSG);
}

/* hardlinks require at minimum create and link permission,
   any additional privilege required is based on the
   privilege of the file being linked to
*/
__u32
x_acl_handle_link(const struct dentry * new_dentry,
		   const struct dentry * parent_dentry,
		   const struct vfsmount * parent_mnt,
		   const struct dentry * old_dentry,
		   const struct vfsmount * old_mnt, const struct filename *to)
{
	__u32 mode;
	__u32 needmode = X_CREATE | X_LINK;
	__u32 needaudit = X_AUDIT_CREATE | X_AUDIT_LINK;

	mode =
	    x_check_link(new_dentry, parent_dentry, parent_mnt, old_dentry,
			  old_mnt);

	if (unlikely(((mode & needmode) == needmode) && (mode & needaudit))) {
		x_log_fs_rbac_str(X_DO_AUDIT, X_LINK_ACL_MSG, old_dentry, old_mnt, to->name);
		return mode;
	} else if (unlikely(((mode & needmode) != needmode) && !(mode & X_SUPPRESS))) {
		x_log_fs_rbac_str(X_DONT_AUDIT, X_LINK_ACL_MSG, old_dentry, old_mnt, to->name);
		return 0;
	} else if (unlikely((mode & needmode) != needmode))
		return 0;

	return 1;
}

__u32
x_acl_handle_symlink(const struct dentry * new_dentry,
		      const struct dentry * parent_dentry,
		      const struct vfsmount * parent_mnt, const struct filename *from)
{
	__u32 needmode = X_WRITE | X_CREATE;
	__u32 mode;

	mode =
	    x_check_create(new_dentry, parent_dentry, parent_mnt,
			    X_CREATE | X_AUDIT_CREATE |
			    X_WRITE | X_AUDIT_WRITE | X_SUPPRESS);

	if (unlikely(mode & X_WRITE && mode & X_AUDITS)) {
		x_log_fs_str_rbac(X_DO_AUDIT, X_SYMLINK_ACL_MSG, from->name, new_dentry, parent_mnt);
		return mode;
	} else if (unlikely(((mode & needmode) != needmode) && !(mode & X_SUPPRESS))) {
		x_log_fs_str_rbac(X_DONT_AUDIT, X_SYMLINK_ACL_MSG, from->name, new_dentry, parent_mnt);
		return 0;
	} else if (unlikely((mode & needmode) != needmode))
		return 0;

	return (X_WRITE | X_CREATE);
}

static __u32 generic_fs_create_handler(const struct dentry *new_dentry, const struct dentry *parent_dentry, const struct vfsmount *parent_mnt, __u32 reqmode, const char *fmt)
{
	__u32 mode;

	mode = x_check_create(new_dentry, parent_dentry, parent_mnt, reqmode | to_x_audit(reqmode) | X_SUPPRESS);

	if (unlikely(((mode & (reqmode)) == (reqmode)) && mode & X_AUDITS)) {
		x_log_fs_rbac_generic(X_DO_AUDIT, fmt, new_dentry, parent_mnt);
		return mode;
	} else if (unlikely((mode & (reqmode)) != (reqmode) && !(mode & X_SUPPRESS))) {
		x_log_fs_rbac_generic(X_DONT_AUDIT, fmt, new_dentry, parent_mnt);
		return 0;
	} else if (unlikely((mode & (reqmode)) != (reqmode)))
		return 0;

	return (reqmode);
}

__u32
x_acl_handle_mknod(const struct dentry * new_dentry,
		    const struct dentry * parent_dentry,
		    const struct vfsmount * parent_mnt,
		    const int mode)
{
	__u32 reqmode = X_WRITE | X_CREATE;
	if (unlikely((mode & S_ISUID) || ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP))))
		reqmode |= X_SETID;

	return generic_fs_create_handler(new_dentry, parent_dentry, parent_mnt,
				  reqmode, X_MKNOD_ACL_MSG);
}

__u32
x_acl_handle_mkdir(const struct dentry *new_dentry,
		    const struct dentry *parent_dentry,
		    const struct vfsmount *parent_mnt)
{
	return generic_fs_create_handler(new_dentry, parent_dentry, parent_mnt,
				  X_WRITE | X_CREATE, X_MKDIR_ACL_MSG);
}

#define RENAME_CHECK_SUCCESS(old, new) \
	(((old & (X_WRITE | X_READ)) == (X_WRITE | X_READ)) && \
	 ((new & (X_WRITE | X_READ)) == (X_WRITE | X_READ)))

int
x_acl_handle_rename(struct dentry *new_dentry,
		     struct dentry *parent_dentry,
		     const struct vfsmount *parent_mnt,
		     struct dentry *old_dentry,
		     struct inode *old_parent_inode,
		     struct vfsmount *old_mnt, const struct filename *newname, unsigned int flags)
{
	__u32 comp1, comp2;
	int error = 0;

	if (unlikely(!x_acl_is_enabled()))
		return 0;

	if (flags & RENAME_EXCHANGE) {
		comp1 = x_search_file(new_dentry, X_READ | X_WRITE |
				       X_AUDIT_READ | X_AUDIT_WRITE |
				       X_SUPPRESS, parent_mnt);
		comp2 =
		    x_search_file(old_dentry,
				   X_READ | X_WRITE | X_AUDIT_READ |
				   X_AUDIT_WRITE | X_SUPPRESS, old_mnt);
	} else if (d_is_negative(new_dentry)) {
		comp1 = x_check_create(new_dentry, parent_dentry, parent_mnt,
					X_READ | X_WRITE | X_CREATE | X_AUDIT_READ |
					X_AUDIT_WRITE | X_AUDIT_CREATE | X_SUPPRESS);
		comp2 = x_search_file(old_dentry, X_READ | X_WRITE |
				       X_DELETE | X_AUDIT_DELETE |
				       X_AUDIT_READ | X_AUDIT_WRITE |
				       X_SUPPRESS, old_mnt);
	} else {
		comp1 = x_search_file(new_dentry, X_READ | X_WRITE |
				       X_CREATE | X_DELETE |
				       X_AUDIT_CREATE | X_AUDIT_DELETE |
				       X_AUDIT_READ | X_AUDIT_WRITE |
				       X_SUPPRESS, parent_mnt);
		comp2 =
		    x_search_file(old_dentry,
				   X_READ | X_WRITE | X_AUDIT_READ |
				   X_DELETE | X_AUDIT_DELETE |
				   X_AUDIT_WRITE | X_SUPPRESS, old_mnt);
	}

	if (RENAME_CHECK_SUCCESS(comp1, comp2) &&
	    ((comp1 & X_AUDITS) || (comp2 & X_AUDITS)))
		x_log_fs_rbac_str(X_DO_AUDIT, X_RENAME_ACL_MSG, old_dentry, old_mnt, newname->name);
	else if (!RENAME_CHECK_SUCCESS(comp1, comp2) && !(comp1 & X_SUPPRESS)
		 && !(comp2 & X_SUPPRESS)) {
		x_log_fs_rbac_str(X_DONT_AUDIT, X_RENAME_ACL_MSG, old_dentry, old_mnt, newname->name);
		error = -EACCES;
	} else if (unlikely(!RENAME_CHECK_SUCCESS(comp1, comp2)))
		error = -EACCES;

	return error;
}

void
x_acl_handle_exit(void)
{
	u16 id;
	char *rolename;

	if (unlikely(current->acl_sp_role && x_acl_is_enabled() &&
	    !(current->role->roletype & X_ROLE_PERSIST))) {
		id = current->acl_role_id;
		rolename = current->role->rolename;
		x_set_acls(1);
		x_log_str_int(X_DONT_AUDIT_GOOD, X_SPROLEL_ACL_MSG, rolename, id);
	}

	x_put_exec_file(current);
	return;
}

int
x_acl_handle_procpidmem(const struct task_struct *task)
{
	if (unlikely(!x_acl_is_enabled()))
		return 0;

	if (task != current && (task->acl->mode & X_PROTPROCFD) &&
	    !(current->acl->mode & X_POVERRIDE) &&
	    !(current->role->roletype & X_ROLE_GOD))
		return -EACCES;

	return 0;
}
