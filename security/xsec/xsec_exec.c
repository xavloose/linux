#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/binfmts.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/xdefs.h>
#include <linux/xsecurity.h>
#include <linux/xinternal.h>
#include <linux/capability.h>
#include <linux/module.h>
#include <linux/compat.h>

#include <asm/uaccess.h>

#ifdef CONFIG_XKERNSEC_EXECLOG
static char x_exec_arg_buf[132];
static DEFINE_MUTEX(x_exec_arg_mutex);
#endif

struct user_arg_ptr {
#ifdef CONFIG_COMPAT
	bool is_compat;
#endif
	union {
		const char __user *const __user *native;
#ifdef CONFIG_COMPAT
		const compat_uptr_t __user *compat;
#endif
	} ptr;
};

extern const char __user *get_user_arg_ptr(struct user_arg_ptr argv, int nr);

void
x_handle_exec_args(struct linux_binprm *bprm, struct user_arg_ptr argv)
{
#ifdef CONFIG_XKERNSEC_EXECLOG
	char *grarg = x_exec_arg_buf;
	unsigned int i, x, execlen = 0;
	char c;

	if (!((xsec_enable_execlog && xsec_enable_group &&
	       in_group_p(xsec_audit_gid))
	      || (xsec_enable_execlog && !xsec_enable_group)))
		return;

	mutex_lock(&x_exec_arg_mutex);
	memset(grarg, 0, sizeof(x_exec_arg_buf));

	for (i = 0; i < bprm->argc && execlen < 128; i++) {
		const char __user *p;
		unsigned int len;

		p = get_user_arg_ptr(argv, i);
		if (IS_ERR(p))
			goto log;

		len = strnlen_user(p, 128 - execlen);
		if (len > 128 - execlen)
			len = 128 - execlen;
		else if (len > 0)
			len--;
		if (copy_from_user(grarg + execlen, p, len))
			goto log;

		/* rewrite unprintable characters */
		for (x = 0; x < len; x++) {
			c = *(grarg + execlen + x);
			if (c < 32 || c > 126)
				*(grarg + execlen + x) = ' ';
		}

		execlen += len;
		*(grarg + execlen) = ' ';
		*(grarg + execlen + 1) = '\0';
		execlen++;
	}

      log:
	x_log_fs_str(X_DO_AUDIT, X_EXEC_AUDIT_MSG, bprm->file->f_path.dentry,
			bprm->file->f_path.mnt, grarg);
	mutex_unlock(&x_exec_arg_mutex);
#endif
	return;
}

#ifdef CONFIG_XKERNSEC
extern int x_acl_is_capable(const int cap);
extern int x_acl_is_capable_nolog(const int cap);
extern int x_task_acl_is_capable(const struct task_struct *task, const struct cred *cred, const int cap, bool log);
extern int x_chroot_is_capable(const int cap);
extern int x_chroot_is_capable_nolog(const int cap);
extern int x_task_chroot_is_capable(const struct task_struct *task, const struct cred *cred, const int cap);
extern int x_task_chroot_is_capable_nolog(const struct task_struct *task, const int cap);
#endif

const char *captab_log[] = {
	"CAP_CHOWN",
	"CAP_DAC_OVERRIDE",
	"CAP_DAC_READ_SEARCH",
	"CAP_FOWNER",
	"CAP_FSETID",
	"CAP_KILL",
	"CAP_SETGID",
	"CAP_SETUID",
	"CAP_SETPCAP",
	"CAP_LINUX_IMMUTABLE",
	"CAP_NET_BIND_SERVICE",
	"CAP_NET_BROADCAST",
	"CAP_NET_ADMIN",
	"CAP_NET_RAW",
	"CAP_IPC_LOCK",
	"CAP_IPC_OWNER",
	"CAP_SYS_MODULE",
	"CAP_SYS_RAWIO",
	"CAP_SYS_CHROOT",
	"CAP_SYS_PTRACE",
	"CAP_SYS_PACCT",
	"CAP_SYS_ADMIN",
	"CAP_SYS_BOOT",
	"CAP_SYS_NICE",
	"CAP_SYS_RESOURCE",
	"CAP_SYS_TIME",
	"CAP_SYS_TTY_CONFIG",
	"CAP_MKNOD",
	"CAP_LEASE",
	"CAP_AUDIT_WRITE",
	"CAP_AUDIT_CONTROL",
	"CAP_SETFCAP",
	"CAP_MAC_OVERRIDE",
	"CAP_MAC_ADMIN",
	"CAP_SYSLOG",
	"CAP_WAKE_ALARM",
	"CAP_BLOCK_SUSPEND",
	"CAP_AUDIT_READ"
};

int captab_log_entries = sizeof(captab_log)/sizeof(captab_log[0]);

int x_is_capable(const int cap)
{
#ifdef CONFIG_XKERNSEC
	if (x_acl_is_capable(cap) && x_chroot_is_capable(cap))
		return 1;
	return 0;
#else
	return 1;
#endif
}

int x_task_is_capable(const struct task_struct *task, const struct cred *cred, const int cap)
{
#ifdef CONFIG_XKERNSEC
	if (x_task_acl_is_capable(task, cred, cap, true) && x_task_chroot_is_capable(task, cred, cap))
		return 1;
	return 0;
#else
	return 1;
#endif
}

int x_is_capable_nolog(const int cap)
{
#ifdef CONFIG_XKERNSEC
	if (x_acl_is_capable_nolog(cap) && x_chroot_is_capable_nolog(cap))
		return 1;
	return 0;
#else
	return 1;
#endif
}

int x_task_is_capable_nolog(const struct task_struct *task, const struct cred *cred, const int cap)
{
#ifdef CONFIG_XKERNSEC
	if (x_task_acl_is_capable(task, cred, cap, false) && x_task_chroot_is_capable_nolog(task, cap))
		return 1;
	return 0;
#else
	return 1;
#endif
}

EXPORT_SYMBOL_GPL(x_is_capable);
EXPORT_SYMBOL_GPL(x_is_capable_nolog);
EXPORT_SYMBOL_GPL(x_task_is_capable);
EXPORT_SYMBOL_GPL(x_task_is_capable_nolog);
