#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/xacl.h>
#include <linux/xsec.h>
#include <linux/xinternal.h>

extern const char *captab_log[];
extern int captab_log_entries;

int gr_learn_cap(const struct task_struct *task, const struct cred *cred, const int cap, bool log)
{
	struct acl_subject_label *curracl;

	if (!x_acl_is_enabled())
		return 1;

	curracl = task->acl;

	if (curracl->mode & (X_LEARN | X_INHERITLEARN)) {
		if (log)
			security_learn(X_LEARN_AUDIT_MSG, task->role->rolename,
			       task->role->roletype, X_GLOBAL_UID(cred->uid),
			       X_GLOBAL_GID(cred->gid), task->exec_file ?
			       x_to_filename(task->exec_file->f_path.dentry,
			       task->exec_file->f_path.mnt) : curracl->filename,
			       curracl->filename, 0UL,
			       0UL, "", (unsigned long) cap, &task->signal->saved_ip);
		return 1;
	}

	return 0;
}

int x_task_acl_is_capable(const struct task_struct *task, const struct cred *cred, const int cap, bool log)
{
	struct acl_subject_label *curracl;
	kernel_cap_t cap_drop = __cap_empty_set, cap_mask = __cap_empty_set;
	kernel_cap_t cap_audit = __cap_empty_set;

	if (!x_acl_is_enabled())
		return 1;

	curracl = task->acl;

	cap_drop = curracl->cap_lower;
	cap_mask = curracl->cap_mask;
	cap_audit = curracl->cap_invert_audit;

	while ((curracl = curracl->parent_subject)) {
		/* if the cap isn't specified in the current computed mask but is specified in the
		   current level subject, and is lowered in the current level subject, then add
		   it to the set of dropped capabilities
		   otherwise, add the current level subject's mask to the current computed mask
		 */
		if (!cap_raised(cap_mask, cap) && cap_raised(curracl->cap_mask, cap)) {
			cap_raise(cap_mask, cap);
			if (cap_raised(curracl->cap_lower, cap))
				cap_raise(cap_drop, cap);
			if (cap_raised(curracl->cap_invert_audit, cap))
				cap_raise(cap_audit, cap);
		}
	}

	if (!cap_raised(cap_drop, cap)) {
		if (log && cap_raised(cap_audit, cap))
			x_log_cap(X_DO_AUDIT, X_CAP_ACL_MSG2, task, captab_log[cap]);
		return 1;
	}

	/* only learn the capability use if the process has the capability in the
	   general case, the two uses in sys.c of gr_learn_cap are an exception
	   to this rule to ensure any role transition involves what the full-learned
	   policy believes in a privileged process
	*/
	if (cap_raised(cred->cap_effective, cap) && x_learn_cap(task, cred, cap, log))
		return 1;

	if (log && (cap >= 0) && (cap < captab_log_entries) && cap_raised(cred->cap_effective, cap) && !cap_raised(cap_audit, cap))
		x_log_cap(X_DONT_AUDIT, X_CAP_ACL_MSG, task, captab_log[cap]);

	return 0;
}

int
x_acl_is_capable(const int cap)
{
	return x_task_acl_is_capable(current, current_cred(), cap, true);
}

int
x_acl_is_capable_nolog(const int cap)
{
	return x_task_acl_is_capable(current, current_cred(), cap, false);
}
