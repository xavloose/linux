#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/tty.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/xinternal.h>

#ifdef CONFIG_TREE_PREEMPT_RCU
#define DISABLE_PREEMPT() preempt_disable()
#define ENABLE_PREEMPT() preempt_enable()
#else
#define DISABLE_PREEMPT()
#define ENABLE_PREEMPT()
#endif

#define BEGIN_LOCKS(x) \
	DISABLE_PREEMPT(); \
	rcu_read_lock(); \
	read_lock(&tasklist_lock); \
	read_lock(&xsec_exec_file_lock); \
	if (x != X_DO_AUDIT) \
		spin_lock(&xsec_alert_lock); \
	else \
		spin_lock(&xsec_audit_lock)

#define END_LOCKS(x) \
	if (x != X_DO_AUDIT) \
		spin_unlock(&xsec_alert_lock); \
	else \
		spin_unlock(&xsec_audit_lock); \
	read_unlock(&xsec_exec_file_lock); \
	read_unlock(&tasklist_lock); \
	rcu_read_unlock(); \
	ENABLE_PREEMPT(); \
	if (x == X_DONT_AUDIT) \
		x_handle_alertkill(current)

enum {
	FLOODING,
	NO_FLOODING
};

extern char *x_alert_log_fmt;
extern char *x_audit_log_fmt;
extern char *x_alert_log_buf;
extern char *x_audit_log_buf;

static int x_log_start(int audit)
{
	char *loglevel = (audit == X_DO_AUDIT) ? KERN_INFO : KERN_ALERT;
	char *fmt = (audit == X_DO_AUDIT) ? x_audit_log_fmt : x_alert_log_fmt;
	char *buf = (audit == X_DO_AUDIT) ? x_audit_log_buf : x_alert_log_buf;
#if (CONFIG_XKERNSEC_FLOODTIME > 0 && CONFIG_XKERNSEC_FLOODBURST > 0)
	unsigned long curr_secs = get_seconds();

	if (audit == X_DO_AUDIT)
		goto set_fmt;

	if (!xsec_alert_wtime || time_after(curr_secs, xsec_alert_wtime + CONFIG_XKERNSEC_FLOODTIME)) {
		xsec_alert_wtime = curr_secs;
		xsec_alert_fyet = 0;
	} else if (time_before_eq(curr_secs, xsec_alert_wtime + CONFIG_XKERNSEC_FLOODTIME)
		    && (xsec_alert_fyet < CONFIG_XKERNSEC_FLOODBURST)) {
		xsec_alert_fyet++;
	} else if (xsec_alert_fyet == CONFIG_XKERNSEC_FLOODBURST) {
		xsec_alert_wtime = curr_secs;
		xsec_alert_fyet++;
		printk(KERN_ALERT "xsec: more alerts, logging disabled for %d seconds\n", CONFIG_XKERNSEC_FLOODTIME);
		return FLOODING;
	}
	else return FLOODING;

set_fmt:
#endif
	memset(buf, 0, PAGE_SIZE);
	if (current->signal->curr_ip && x_acl_is_enabled()) {
		sprintf(fmt, "%s%s", loglevel, "xsec: From %pI4: (%.64s:%c:%.950s) ");
		snprintf(buf, PAGE_SIZE - 1, fmt, &current->signal->curr_ip, current->role->rolename, x_roletype_to_char(), current->acl->filename);
	} else if (current->signal->curr_ip) {
		sprintf(fmt, "%s%s", loglevel, "xsec: From %pI4: ");
		snprintf(buf, PAGE_SIZE - 1, fmt, &current->signal->curr_ip);
	} else if (x_acl_is_enabled()) {
		sprintf(fmt, "%s%s", loglevel, "xsec: (%.64s:%c:%.950s) ");
		snprintf(buf, PAGE_SIZE - 1, fmt, current->role->rolename, x_roletype_to_char(), current->acl->filename);
	} else {
		sprintf(fmt, "%s%s", loglevel, "xsec: ");
		strcpy(buf, fmt);
	}

	return NO_FLOODING;
}

static void x_log_middle(int audit, const char *msg, va_list ap)
	__attribute__ ((format (printf, 2, 0)));

static void x_log_middle(int audit, const char *msg, va_list ap)
{
	char *buf = (audit == X_DO_AUDIT) ? x_audit_log_buf : x_alert_log_buf;
	unsigned int len = strlen(buf);

	vsnprintf(buf + len, PAGE_SIZE - len - 1, msg, ap);

	return;
}

static void x_log_middle_varargs(int audit, const char *msg, ...)
	__attribute__ ((format (printf, 2, 3)));

static void x_log_middle_varargs(int audit, const char *msg, ...)
{
	char *buf = (audit == X_DO_AUDIT) ? x_audit_log_buf : x_alert_log_buf;
	unsigned int len = strlen(buf);
	va_list ap;

	va_start(ap, msg);
	vsnprintf(buf + len, PAGE_SIZE - len - 1, msg, ap);
	va_end(ap);

	return;
}

static void x_log_end(int audit, int append_default)
{
	char *buf = (audit == X_DO_AUDIT) ? x_audit_log_buf : x_alert_log_buf;
	if (append_default) {
		struct task_struct *task = current;
		struct task_struct *parent = task->real_parent;
		const struct cred *cred = __task_cred(task);
		const struct cred *pcred = __task_cred(parent);
		unsigned int len = strlen(buf);

		snprintf(buf + len, PAGE_SIZE - len - 1, DEFAULTSECMSG, x_task_fullpath(task), task->comm, task_pid_nr(task), X_GLOBAL_UID(cred->uid), X_GLOBAL_UID(cred->euid), X_GLOBAL_GID(cred->gid), X_GLOBAL_GID(cred->egid), x_parent_task_fullpath(task), parent->comm, task_pid_nr(task->real_parent), X_GLOBAL_UID(pcred->uid), X_GLOBAL_UID(pcred->euid), X_GLOBAL_GID(pcred->gid), X_GLOBAL_GID(pcred->egid));
	}

	printk("%s\n", buf);

	return;
}

void x_log_varargs(int audit, const char *msg, int argtypes, ...)
{
	int logtype;
	char *result = (audit == X_DO_AUDIT) ? "successful" : "denied";
	char *str1 = NULL, *str2 = NULL, *str3 = NULL;
	void *voidptr = NULL;
	int num1 = 0, num2 = 0;
	unsigned long ulong1 = 0, ulong2 = 0;
	struct dentry *dentry = NULL;
	struct vfsmount *mnt = NULL;
	struct file *file = NULL;
	struct task_struct *task = NULL;
	struct vm_area_struct *vma = NULL;
	const struct cred *cred, *pcred;
	va_list ap;

	BEGIN_LOCKS(audit);
	logtype = x_log_start(audit);
	if (logtype == FLOODING) {
		END_LOCKS(audit);
		return;
	}
	va_start(ap, argtypes);
	switch (argtypes) {
	case X_TTYSNIFF:
		task = va_arg(ap, struct task_struct *);
		x_log_middle_varargs(audit, msg, &task->signal->curr_ip, x_task_fullpath0(task), task->comm, task_pid_nr(task), x_parent_task_fullpath0(task), task->real_parent->comm, task_pid_nr(task->real_parent));
		break;
	case X_SYSCTL_HIDDEN:
		str1 = va_arg(ap, char *);
		x_log_middle_varargs(audit, msg, result, str1);
		break;
	case X_RBAC:
		dentry = va_arg(ap, struct dentry *);
		mnt = va_arg(ap, struct vfsmount *);
		x_log_middle_varargs(audit, msg, result, x_to_filename(dentry, mnt));
		break;
	case X_RBAC_STR:
		dentry = va_arg(ap, struct dentry *);
		mnt = va_arg(ap, struct vfsmount *);
		str1 = va_arg(ap, char *);
		x_log_middle_varargs(audit, msg, result, x_to_filename(dentry, mnt), str1);
		break;
	case X_STR_RBAC:
		str1 = va_arg(ap, char *);
		dentry = va_arg(ap, struct dentry *);
		mnt = va_arg(ap, struct vfsmount *);
		x_log_middle_varargs(audit, msg, result, str1, x_to_filename(dentry, mnt));
		break;
	case X_RBAC_MODE2:
		dentry = va_arg(ap, struct dentry *);
		mnt = va_arg(ap, struct vfsmount *);
		str1 = va_arg(ap, char *);
		str2 = va_arg(ap, char *);
		x_log_middle_varargs(audit, msg, result, x_to_filename(dentry, mnt), str1, str2);
		break;
	case X_RBAC_MODE3:
		dentry = va_arg(ap, struct dentry *);
		mnt = va_arg(ap, struct vfsmount *);
		str1 = va_arg(ap, char *);
		str2 = va_arg(ap, char *);
		str3 = va_arg(ap, char *);
		x_log_middle_varargs(audit, msg, result, x_to_filename(dentry, mnt), str1, str2, str3);
		break;
	case GX_FILENAME:
		dentry = va_arg(ap, struct dentry *);
		mnt = va_arg(ap, struct vfsmount *);
		x_log_middle_varargs(audit, msg, x_to_filename(dentry, mnt));
		break;
	case X_STR_FILENAME:
		str1 = va_arg(ap, char *);
		dentry = va_arg(ap, struct dentry *);
		mnt = va_arg(ap, struct vfsmount *);
		x_log_middle_varargs(audit, msg, str1, x_to_filename(dentry, mnt));
		break;
	case X_FILENAME_STR:
		dentry = va_arg(ap, struct dentry *);
		mnt = va_arg(ap, struct vfsmount *);
		str1 = va_arg(ap, char *);
		x_log_middle_varargs(audit, msg, x_to_filename(dentry, mnt), str1);
		break;
	case X_FILENAME_TWO_INT:
		dentry = va_arg(ap, struct dentry *);
		mnt = va_arg(ap, struct vfsmount *);
		num1 = va_arg(ap, int);
		num2 = va_arg(ap, int);
		x_log_middle_varargs(audit, msg, x_to_filename(dentry, mnt), num1, num2);
		break;
	case X_FILENAME_TWO_INT_STR:
		dentry = va_arg(ap, struct dentry *);
		mnt = va_arg(ap, struct vfsmount *);
		num1 = va_arg(ap, int);
		num2 = va_arg(ap, int);
		str1 = va_arg(ap, char *);
		x_log_middle_varargs(audit, msg, x_to_filename(dentry, mnt), num1, num2, str1);
		break;
	case X_TEXTREL:
		str1 = va_arg(ap, char *);
		file = va_arg(ap, struct file *);
		ulong1 = va_arg(ap, unsigned long);
		ulong2 = va_arg(ap, unsigned long);
		x_log_middle_varargs(audit, msg, str1, file ? x_to_filename(file->f_path.dentry, file->f_path.mnt) : "<anonymous mapping>", ulong1, ulong2);
		break;
	case X_PTRACE:
		task = va_arg(ap, struct task_struct *);
		x_log_middle_varargs(audit, msg, task->exec_file ? x_to_filename(task->exec_file->f_path.dentry, task->exec_file->f_path.mnt) : "(none)", task->comm, task_pid_nr(task));
		break;
	case X_RESOURCE:
		task = va_arg(ap, struct task_struct *);
		cred = __task_cred(task);
		pcred = __task_cred(task->real_parent);
		ulong1 = va_arg(ap, unsigned long);
		str1 = va_arg(ap, char *);
		ulong2 = va_arg(ap, unsigned long);
		x_log_middle_varargs(audit, msg, ulong1, str1, ulong2, x_task_fullpath(task), task->comm, task_pid_nr(task), X_GLOBAL_UID(cred->uid), X_GLOBAL_UID(cred->euid), X_GLOBAL_GID(cred->gid), X_GLOBAL_GID(cred->egid), x_parent_task_fullpath(task), task->real_parent->comm, task_pid_nr(task->real_parent), X_GLOBAL_UID(pcred->uid), X_GLOBAL_UID(pcred->euid), X_GLOBAL_GID(pcred->gid), X_GLOBAL_GID(pcred->egid));
		break;
	case X_CAP:
		task = va_arg(ap, struct task_struct *);
		cred = __task_cred(task);
		pcred = __task_cred(task->real_parent);
		str1 = va_arg(ap, char *);
		x_log_middle_varargs(audit, msg, str1, x_task_fullpath(task), task->comm, task_pid_nr(task), X_GLOBAL_UID(cred->uid), X_GLOBAL_UID(cred->euid), X_GLOBAL_GID(cred->gid), X_GLOBAL_GID(cred->egid), x_parent_task_fullpath(task), task->real_parent->comm, task_pid_nr(task->real_parent), X_GLOBAL_UID(pcred->uid), X_GLOBAL_UID(pcred->euid), X_GLOBAL_GID(pcred->gid), X_GLOBAL_GID(pcred->egid));
		break;
	case X_SIG:
		str1 = va_arg(ap, char *);
		voidptr = va_arg(ap, void *);
		x_log_middle_varargs(audit, msg, str1, voidptr);
		break;
	case X_SIG2:
		task = va_arg(ap, struct task_struct *);
		cred = __task_cred(task);
		pcred = __task_cred(task->real_parent);
		num1 = va_arg(ap, int);
		x_log_middle_varargs(audit, msg, num1, x_task_fullpath0(task), task->comm, task_pid_nr(task), X_GLOBAL_UID(cred->uid), X_GLOBAL_UID(cred->euid), X_GLOBAL_GID(cred->gid), X_GLOBAL_GID(cred->egid), x_parent_task_fullpath0(task), task->real_parent->comm, task_pid_nr(task->real_parent), X_GLOBAL_UID(pcred->uid), X_GLOBAL_UID(pcred->euid), X_GLOBAL_GID(pcred->gid), X_GLOBAL_GID(pcred->egid));
		break;
	case X_CRASH1:
		task = va_arg(ap, struct task_struct *);
		cred = __task_cred(task);
		pcred = __task_cred(task->real_parent);
		ulong1 = va_arg(ap, unsigned long);
		x_log_middle_varargs(audit, msg, x_task_fullpath(task), task->comm, task_pid_nr(task), X_GLOBAL_UID(cred->uid), X_GLOBAL_UID(cred->euid), X_GLOBAL_GID(cred->gid), X_GLOBAL_GID(cred->egid), x_parent_task_fullpath(task), task->real_parent->comm, task_pid_nr(task->real_parent), X_GLOBAL_UID(pcred->uid), X_GLOBAL_UID(pcred->euid), X_GLOBAL_GID(pcred->gid), X_GLOBAL_GID(pcred->egid), X_GLOBAL_UID(cred->uid), ulong1);
		break;
	case X_CRASH2:
		task = va_arg(ap, struct task_struct *);
		cred = __task_cred(task);
		pcred = __task_cred(task->real_parent);
		ulong1 = va_arg(ap, unsigned long);
		x_log_middle_varargs(audit, msg, x_task_fullpath(task), task->comm, task_pid_nr(task), X_GLOBAL_UID(cred->uid), X_GLOBAL_UID(cred->euid), X_GLOBAL_GID(cred->gid), X_GLOBAL_GID(cred->egid), x_parent_task_fullpath(task), task->real_parent->comm, task_pid_nr(task->real_parent), X_GLOBAL_UID(pcred->uid), X_GLOBAL_UID(pcred->euid), X_GLOBAL_GID(pcred->gid), X_GLOBAL_GID(pcred->egid), ulong1);
		break;
	case X_RWXMAP:
		file = va_arg(ap, struct file *);
		x_log_middle_varargs(audit, msg, file ? x_to_filename(file->f_path.dentry, file->f_path.mnt) : "<anonymous mapping>");
		break;
	case X_RWXMAPVMA:
		vma = va_arg(ap, struct vm_area_struct *);
		if (vma->vm_file)
			str1 = x_to_filename(vma->vm_file->f_path.dentry, vma->vm_file->f_path.mnt);
		else if (vma->vm_flags & (VM_GROWSDOWN | VM_GROWSUP))
			str1 = "<stack>";
		else if (vma->vm_start <= current->mm->brk &&
			 vma->vm_end >= current->mm->start_brk)
			str1 = "<heap>";
		else
			str1 = "<anonymous mapping>";
		x_log_middle_varargs(audit, msg, str1);
		break;
	case X_PSACCT:
		{
			unsigned int wday, cday;
			__u8 whr, chr;
			__u8 wmin, cmin;
			__u8 wsec, csec;

			task = va_arg(ap, struct task_struct *);
			wday = va_arg(ap, unsigned int);
			cday = va_arg(ap, unsigned int);
			whr = va_arg(ap, int);
			chr = va_arg(ap, int);
			wmin = va_arg(ap, int);
			cmin = va_arg(ap, int);
			wsec = va_arg(ap, int);
			csec = va_arg(ap, int);
			ulong1 = va_arg(ap, unsigned long);
			cred = __task_cred(task);
			pcred = __task_cred(task->real_parent);

			x_log_middle_varargs(audit, msg, x_task_fullpath(task), task->comm, task_pid_nr(task), &task->signal->curr_ip, tty_name(task->signal->tty), X_GLOBAL_UID(cred->uid), X_GLOBAL_UID(cred->euid), X_GLOBAL_GID(cred->gid), X_GLOBAL_GID(cred->egid), wday, whr, wmin, wsec, cday, chr, cmin, csec, (task->flags & PF_SIGNALED) ? "killed by signal" : "exited", ulong1, x_parent_task_fullpath(task), task->real_parent->comm, task_pid_nr(task->real_parent), &task->real_parent->signal->curr_ip, tty_name(task->real_parent->signal->tty), X_GLOBAL_UID(pcred->uid), X_GLOBAL_UID(pcred->euid), X_GLOBAL_GID(pcred->gid), X_GLOBAL_GID(pcred->egid));
		}
		break;
	default:
		x_log_middle(audit, msg, ap);
	}
	va_end(ap);
	// these don't need DEFAULTSECARGS printed on the end
	if (argtypes == X_CRASH1 || argtypes == X_CRASH2)
		x_log_end(audit, 0);
	else
		x_log_end(audit, 1);
	END_LOCKS(audit);
}
