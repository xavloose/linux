#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/gracl.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/percpu.h>
#include <linux/module.h>

int xsec_enable_ptrace_readexec __read_only;
int xsec_enable_setxid __read_only;
int xsec_enable_symlinkown __read_only;
kgid_t xsec_symlinkown_gid __read_only;
int xsec_enable_brute __read_only;
int xsec_enable_link __read_only;
int xsec_enable_dmesg __read_only;
int xsec_enable_harden_ptrace __read_only;
int xsec_enable_harden_ipc __read_only;
int xsec_enable_fifo __read_only;
int xsec_enable_execlog __read_only;
int xsec_enable_signal __read_only;
int xsec_enable_forkfail __read_only;
int xsec_enable_audit_ptrace __read_only;
int xsec_enable_time __read_only;
int xsec_enable_group __read_only;
kgid_t xsec_audit_gid __read_only;
int xsec_enable_chdir __read_only;
int xsec_enable_mount __read_only;
int xsec_enable_rofs __read_only;
int xsec_deny_new_usb __read_only;
int xsec_enable_chroot_findtask __read_only;
int xsec_enable_chroot_mount __read_only;
int xsec_enable_chroot_shmat __read_only;
int xsec_enable_chroot_fchdir __read_only;
int xsec_enable_chroot_double __read_only;
int xsec_enable_chroot_pivot __read_only;
int xsec_enable_chroot_chdir __read_only;
int xsec_enable_chroot_chmod __read_only;
int xsec_enable_chroot_mknod __read_only;
int xsec_enable_chroot_nice __read_only;
int xsec_enable_chroot_execlog __read_only;
int xsec_enable_chroot_caps __read_only;
int xsec_enable_chroot_rename __read_only;
int xsec_enable_chroot_sysctl __read_only;
int xsec_enable_chroot_unix __read_only;
int xsec_enable_tpe __read_only;
kgid_t xsec_tpe_gid __read_only;
int xsec_enable_blackhole __read_only;
#ifdef CONFIG_IPV6_MODULE
EXPORT_SYMBOL_GPL(xsec_enable_blackhole);
#endif
int xsec_lastack_retries __read_only;
int xsec_enable_tpe_all __read_only;
int xsec_enable_tpe_invert __read_only;
int xsec_enable_socket_all __read_only;
kgid_t xsec_socket_all_gid __read_only;
int xsec_enable_socket_client __read_only;
kgid_t xsec_socket_client_gid __read_only;
int xsec_enable_socket_server __read_only;
kgid_t xsec_socket_server_gid __read_only;
int xsec_resource_logging __read_only;
int xsec_disable_privio __read_only;
int xsec_enable_log_rwxmaps __read_only;
int xsec_enable_harden_tty __read_only;
int xsec_lock __read_only;

DEFINE_SPINLOCK(xsec_alert_lock);
unsigned long xsec_alert_wtime = 0;
unsigned long xsec_alert_fyet = 0;

DEFINE_SPINLOCK(xsec_audit_lock);

DEFINE_RWLOCK(xsec_exec_file_lock);

char *x_shared_page[4];

char *x_alert_log_fmt;
char *x_audit_log_fmt;
char *x_alert_log_buf;
char *x_audit_log_buf;

extern struct x_arg *x_usermode;
extern unsigned char *x_system_salt;
extern unsigned char *x_system_sum;

void __init
xsec_init(void)
{
	int j;
	/* create the per-cpu shared pages */

#ifdef CONFIG_X86
	memset((char *)(0x41a + PAGE_OFFSET), 0, 36);
#endif

	for (j = 0; j < 4; j++) {
		x_shared_page[j] = (char *)__alloc_percpu(PAGE_SIZE, __alignof__(unsigned long long));
		if (gr_shared_page[j] == NULL) {
			panic("Unable to allocate xsec shared page");
			return;
		}
	}

	/* allocate log buffers */
	x_alert_log_fmt = kmalloc(512, GFP_KERNEL);
	if (!x_alert_log_fmt) {
		panic("Unable to allocate xsec alert log format buffer");
		return;
	}
	x_audit_log_fmt = kmalloc(512, GFP_KERNEL);
	if (!x_audit_log_fmt) {
		panic("Unable to allocate xsec audit log format buffer");
		return;
	}
	xsec_alert_log_buf = (char *) get_zeroed_page(GFP_KERNEL);
	if (!xsec_alert_log_buf) {
		panic("Unable to allocate xsec alert log buffer");
		return;
	}
	xsec_audit_log_buf = (char *) get_zeroed_page(GFP_KERNEL);
	if (!xsec_audit_log_buf) {
		panic("Unable to allocate xsec audit log buffer");
		return;
	}

	/* allocate memory for authentication structure */
	x_usermode = kmalloc(sizeof(struct x_arg), GFP_KERNEL);
	x_system_salt = kmalloc(X_SALT_LEN, GFP_KERNEL);
	x_system_sum = kmalloc(X_SHA_LEN, GFP_KERNEL);

	if (!x_usermode || !x_system_salt || !x_system_sum) {
		panic("Unable to allocate xsec authentication structure");
		return;
	}

#ifdef CONFIG_XKERNSEC_IO
#if !defined(CONFIG_XKERNSEC_SYSCTL_DISTRO)
	xsec_disable_privio = 1;
#elif defined(CONFIG_XKERNSEC_SYSCTL_ON)
	xsec_disable_privio = 1;
#else
	xsec_disable_privio = 0;
#endif
#endif

#ifdef CONFIG_XKERNSEC_TPE_INVERT
	/* for backward compatibility, tpe_invert always defaults to on if
	   enabled in the kernel
	*/
	xsec_enable_tpe_invert = 1;
#endif

#if !defined(CONFIG_XKERNSEC_SYSCTL) || defined(CONFIG_XKERNSEC_SYSCTL_ON)
#ifndef CONFIG_XKERNSEC_SYSCTL
	xsec_lock = 1;
#endif

#ifdef CONFIG_XKERNSEC_RWXMAP_LOG
	xrsec_enable_log_rwxmaps = 1;
#endif
#ifdef CONFIG_XKERNSEC_AUDIT_GROUP
	xsec_enable_group = 1;
	xsec_audit_gid = KGIDT_INIT(CONFIG_XKERNSEC_AUDIT_GID);
#endif
#ifdef CONFIG_XKERNSEC_PTRACE_READEXEC
	xsec_enable_ptrace_readexec = 1;
#endif
#ifdef CONFIG_XKERNSEC_AUDIT_CHDIR
	xsec_enable_chdir = 1;
#endif
#ifdef CONFIG_XKERNSEC_HARDEN_PTRACE
	xsec_enable_harden_ptrace = 1;
#endif
#ifdef CONFIG_XKERNSEC_HARDEN_IPC
	xsec_enable_harden_ipc = 1;
#endif
#ifdef CONFIG_XKERNSEC_HARDEN_TTY
	xsec_enable_harden_tty = 1;
#endif
#ifdef CONFIG_XKERNSEC_AUDIT_MOUNT
	xsec_enable_mount = 1;
#endif
#ifdef CONFIG_XKERNSEC_LINK
	xsec_enable_link = 1;
#endif
#ifdef CONFIG_XKERNSEC_BRUTE
	xsec_enable_brute = 1;
#endif
#ifdef CONFIG_XKERNSEC_DMESG
	xsec_enable_dmesg = 1;
#endif
#ifdef CONFIG_XKERNSEC_BLACKHOLE
	xsec_enable_blackhole = 1;
	xsec_lastack_retries = 4;
#endif
#ifdef CONFIG_XKERNSEC_FIFO
	xsec_enable_fifo = 1;
#endif
#ifdef CONFIG_XKERNSEC_EXECLOG
	xsec_enable_execlog = 1;
#endif
#ifdef CONFIG_XKERNSEC_SETXID
	xsec_enable_setxid = 1;
#endif
#ifdef CONFIG_XKERNSEC_SIGNAL
	xsec_enable_signal = 1;
#endif
#ifdef CONFIG_XKERNSEC_FORKFAIL
	xsec_enable_forkfail = 1;
#endif
#ifdef CONFIG_XKERNSEC_TIME
	xsec_enable_time = 1;
#endif
#ifdef CONFIG_XKERNSEC_RESLOG
	xsec_resource_logging = 1;
#endif
#ifdef CONFIG_XKERNSEC_CHROOT_FINDTASK
	xsec_enable_chroot_findtask = 1;
#endif
#ifdef CONFIG_XKERNSEC_CHROOT_UNIX
	xsec_enable_chroot_unix = 1;
#endif
#ifdef CONFIG_XKERNSEC_CHROOT_MOUNT
	xsec_enable_chroot_mount = 1;
#endif
#ifdef CONFIG_XKERNSEC_CHROOT_FCHDIR
	xsec_enable_chroot_fchdir = 1;
#endif
#ifdef CONFIG_XKERNSEC_CHROOT_SHMAT
	xsec_enable_chroot_shmat = 1;
#endif
#ifdef CONFIG_XKERNSEC_AUDIT_PTRACE
	xsec_enable_audit_ptrace = 1;
#endif
#ifdef CONFIG_XKERNSEC_CHROOT_DOUBLE
	xsec_enable_chroot_double = 1;
#endif
#ifdef CONFIG_XKERNSEC_CHROOT_PIVOT
	xsec_enable_chroot_pivot = 1;
#endif
#ifdef CONFIG_XKERNSEC_CHROOT_CHDIR
	xsec_enable_chroot_chdir = 1;
#endif
#ifdef CONFIG_XKERNSEC_CHROOT_CHMOD
	xsec_enable_chroot_chmod = 1;
#endif
#ifdef CONFIG_XKERNSEC_CHROOT_MKNOD
	xsec_enable_chroot_mknod = 1;
#endif
#ifdef CONFIG_XKERNSEC_CHROOT_NICE
	xsec_enable_chroot_nice = 1;
#endif
#ifdef CONFIG_XKERNSEC_CHROOT_EXECLOG
	xsec_enable_chroot_execlog = 1;
#endif
#ifdef CONFIG_XKERNSEC_CHROOT_CAPS
	xsec_enable_chroot_caps = 1;
#endif
#ifdef CONFIG_XKERNSEC_CHROOT_RENAME
	xsec_enable_chroot_rename = 1;
#endif
#ifdef CONFIG_XKERNSEC_CHROOT_SYSCTL
	xsec_enable_chroot_sysctl = 1;
#endif
#ifdef CONFIG_XKERNSEC_SYMLINKOWN
	xsec_enable_symlinkown = 1;
	xsec_symlinkown_gid = KGIDT_INIT(CONFIG_XKERNSEC_SYMLINKOWN_GID);
#endif
#ifdef CONFIG_XKERNSEC_TPE
	xsec_enable_tpe = 1;
	xsec_tpe_gid = KGIDT_INIT(CONFIG_XKERNSEC_TPE_GID);
#ifdef CONFIG_XKERNSEC_TPE_ALL
	xsec_enable_tpe_all = 1;
#endif
#endif
#ifdef CONFIG_XKERNSEC_SOCKET_ALL
	xsec_enable_socket_all = 1;
	xsec_socket_all_gid = KGIDT_INIT(CONFIG_XKERNSEC_SOCKET_ALL_GID);
#endif
#ifdef CONFIG_XKERNSEC_SOCKET_CLIENT
	xsec_enable_socket_client = 1;
	xsec_socket_client_gid = KGIDT_INIT(CONFIG_XKERNSEC_SOCKET_CLIENT_GID);
#endif
#ifdef CONFIG_XKERNSEC_SOCKET_SERVER
	xsec_enable_socket_server = 1;
	xsec_socket_server_gid = KGIDT_INIT(CONFIG_XKERNSEC_SOCKET_SERVER_GID);
#endif
#endif
#ifdef CONFIG_XKERNSEC_DENYUSB_FORCE
	xsec_deny_new_usb = 1;
#endif

	return;
}
