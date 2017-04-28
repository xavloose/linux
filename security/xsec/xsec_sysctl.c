#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sysctl.h>
#include <linux/xsec.h>
#include <linux/xinternal.h>

int
x_handle_sysctl_mod(const char *dirname, const char *name, const int op)
{
#ifdef CONFIG_XKERNSEC_SYSCTL
	if (dirname == NULL || name == NULL)
		return 0;
	if (!strcmp(dirname, "xsec") && xsec_lock && (op & MAY_WRITE)) {
		x_log_str(X_DONT_AUDIT, X_SYSCTL_MSG, name);
		return -EACCES;
	}
#endif
	return 0;
}

#if defined(CONFIG_XKERNSEC_ROFS) || defined(CONFIG_XKERNSEC_DENYUSB)
static int __maybe_unused __read_only one = 1;
#endif

#if defined(CONFIG_XKERNSEC_SYSCTL) || defined(CONFIG_XKERNSEC_ROFS) || \
	defined(CONFIG_XKERNSEC_DENYUSB)
struct ctl_table xsec_table[] = {
#ifdef CONFIG_XKERNSEC_SYSCTL
#ifdef CONFIG_XKERNSEC_SYSCTL_DISTRO
#ifdef CONFIG_XKERNSEC_IO
	{
		.procname	= "disable_priv_io",
		.data		= &xsec_disable_privio,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#endif
#ifdef CONFIG_XKERNSEC_LINK
	{
		.procname	= "linking_restrictions",
		.data		= &xsec_enable_link,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_SYMLINKOWN
	{
		.procname	= "enforce_symlinksifowner",
		.data		= &xsec_enable_symlinkown,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
	{
		.procname	= "symlinkown_gid",
		.data		= &xsec_symlinkown_gid,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_BRUTE
	{
		.procname	= "deter_bruteforce",
		.data		= &xsec_enable_brute,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_FIFO
	{
		.procname	= "fifo_restrictions",
		.data		= &xsec_enable_fifo,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_PTRACE_READEXEC
	{
		.procname	= "ptrace_readexec",
		.data		= &xsec_enable_ptrace_readexec,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_SETXID
	{
		.procname	= "consistent_setxid",
		.data		= &xsec_enable_setxid,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_BLACKHOLE
	{
		.procname	= "ip_blackhole",
		.data		= &xsec_enable_blackhole,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
	{
		.procname	= "lastack_retries",
		.data		= &xsec_lastack_retries,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_EXECLOG
	{
		.procname	= "exec_logging",
		.data		= &xsec_enable_execlog,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_RWXMAP_LOG
	{
		.procname	= "rwxmap_logging",
		.data		= &xsec_enable_log_rwxmaps,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_SIGNAL
	{
		.procname	= "signal_logging",
		.data		= &xsec_enable_signal,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_FORKFAIL
	{
		.procname	= "forkfail_logging",
		.data		= &xsec_enable_forkfail,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_TIME
	{
		.procname	= "timechange_logging",
		.data		= &xsec_enable_time,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_CHROOT_SHMAT
	{
		.procname	= "chroot_deny_shmat",
		.data		= &xsec_enable_chroot_shmat,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_CHROOT_UNIX
	{
		.procname	= "chroot_deny_unix",
		.data		= &xsec_enable_chroot_unix,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_CHROOT_MOUNT
	{
		.procname	= "chroot_deny_mount",
		.data		= &xsec_enable_chroot_mount,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_CHROOT_FCHDIR
	{
		.procname	= "chroot_deny_fchdir",
		.data		= &xsec_enable_chroot_fchdir,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_CHROOT_DOUBLE
	{
		.procname	= "chroot_deny_chroot",
		.data		= &xsec_enable_chroot_double,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_CHROOT_PIVOT
	{
		.procname	= "chroot_deny_pivot",
		.data		= &xsec_enable_chroot_pivot,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_CHROOT_CHDIR
	{
		.procname	= "chroot_enforce_chdir",
		.data		= &xsec_enable_chroot_chdir,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_CHROOT_CHMOD
	{
		.procname	= "chroot_deny_chmod",
		.data		= &xsec_enable_chroot_chmod,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_CHROOT_MKNOD
	{
		.procname	= "chroot_deny_mknod",
		.data		= &xsec_enable_chroot_mknod,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_CHROOT_NICE
	{
		.procname	= "chroot_restrict_nice",
		.data		= &xsec_enable_chroot_nice,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_CHROOT_EXECLOG
	{
		.procname	= "chroot_execlog",
		.data		= &xsec_enable_chroot_execlog,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_CHROOT_CAPS
	{
		.procname	= "chroot_caps",
		.data		= &xsec_enable_chroot_caps,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_CHROOT_RENAME
	{
		.procname	= "chroot_deny_bad_rename",
		.data		= &xsec_enable_chroot_rename,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_CHROOT_SYSCTL
	{
		.procname	= "chroot_deny_sysctl",
		.data		= &xsec_enable_chroot_sysctl,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_TPE
	{
		.procname	= "tpe",
		.data		= &xsec_enable_tpe,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
	{
		.procname	= "tpe_gid",
		.data		= &xsec_tpe_gid,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_TPE_INVERT
	{
		.procname	= "tpe_invert",
		.data		= &xsec_enable_tpe_invert,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_TPE_ALL
	{
		.procname	= "tpe_restrict_all",
		.data		= &xsec_enable_tpe_all,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_SOCKET_ALL
	{
		.procname	= "socket_all",
		.data		= &xsec_enable_socket_all,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
	{
		.procname	= "socket_all_gid",
		.data		= &xsec_socket_all_gid,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_SOCKET_CLIENT
	{
		.procname	= "socket_client",
		.data		= &xsec_enable_socket_client,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
	{
		.procname	= "socket_client_gid",
		.data		= &xsec_socket_client_gid,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_SOCKET_SERVER
	{
		.procname	= "socket_server",
		.data		= &xsec_enable_socket_server,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
	{
		.procname	= "socket_server_gid",
		.data		= &xsec_socket_server_gid,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_AUDIT_GROUP
	{
		.procname	= "audit_group",
		.data		= &xsec_enable_group,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
	{
		.procname	= "audit_gid",
		.data		= &xsec_audit_gid,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_AUDIT_CHDIR
	{
		.procname	= "audit_chdir",
		.data		= &xsec_enable_chdir,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_AUDIT_MOUNT
	{
		.procname	= "audit_mount",
		.data		= &xsec_enable_mount,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_DMESG
	{
		.procname	= "dmesg",
		.data		= &xsec_enable_dmesg,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_CHROOT_FINDTASK
	{
		.procname	= "chroot_findtask",
		.data		= &xsec_enable_chroot_findtask,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_RESLOG
	{
		.procname	= "resource_logging",
		.data		= &xsec_resource_logging,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_AUDIT_PTRACE
	{
		.procname	= "audit_ptrace",
		.data		= &xsec_enable_audit_ptrace,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_HARDEN_PTRACE
	{
		.procname	= "harden_ptrace",
		.data		= &xsec_enable_harden_ptrace,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_HARDEN_IPC
	{
		.procname	= "harden_ipc",
		.data		= &xsec_enable_harden_ipc,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_HARDEN_TTY
	{
		.procname	= "harden_tty",
		.data		= &xsec_enable_harden_tty,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
	{
		.procname	= "grsec_lock",
		.data		= &xsec_lock,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_XKERNSEC_ROFS
	{
		.procname	= "romount_protect",
		.data		= &xsec_enable_rofs,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_minmax_secure,
		.extra1		= &one,
		.extra2		= &one,
	},
#endif
#if defined(CONFIG_XKERNSEC_DENYUSB) && !defined(CONFIG_XKERNSEC_DENYUSB_FORCE)
	{
		.procname	= "deny_new_usb",
		.data		= &xsec_deny_new_usb,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
	{ }
};
#endif
