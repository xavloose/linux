#ifndef __XINTERNAL_H
#define __XINTERNAL_H

#ifdef CONFIG_XKERNSEC

#include <linux/fs.h>
#include <linux/mnt_namespace.h>
#include <linux/nsproxy.h>
#include <linux/xacl.h>
#include <linux/xdefs.h>
#include <linux/xmsg.h>

void x_add_learn_entry(const char *fmt, ...)
	__attribute__ ((format (printf, 1, 2)));
__u32 x_search_file(const struct dentry *dentry, const __u32 mode,
			    const struct vfsmount *mnt);
__u32 x_check_create(const struct dentry *new_dentry,
			     const struct dentry *parent,
			     const struct vfsmount *mnt, const __u32 mode);
int x_check_protected_task(const struct task_struct *task);
__u32 to_x_audit(const __u32 reqmode);
int x_set_acls(const int type);
int x_acl_is_enabled(void);
char x_roletype_to_char(void);

void x_handle_alertkill(struct task_struct *task);
char *x_to_filename(const struct dentry *dentry,
			    const struct vfsmount *mnt);
char *x_to_filename1(const struct dentry *dentry,
			    const struct vfsmount *mnt);
char *x_to_filename2(const struct dentry *dentry,
			    const struct vfsmount *mnt);
char *x_to_filename3(const struct dentry *dentry,
			    const struct vfsmount *mnt);

extern int xsec_enable_ptrace_readexec;
extern int xsec_enable_harden_ptrace;
extern int xsec_enable_link;
extern int xsec_enable_fifo;
extern int xsec_enable_execve;
extern int xsec_enable_shm;
extern int xsec_enable_execlog;
extern int xsec_enable_signal;
extern int xsec_enable_audit_ptrace;
extern int xsec_enable_forkfail;
extern int xsec_enable_time;
extern int xsec_enable_rofs;
extern int xsec_deny_new_usb;
extern int xsec_enable_chroot_shmat;
extern int xsec_enable_chroot_mount;
extern int xsec_enable_chroot_double;
extern int xsec_enable_chroot_pivot;
extern int xsec_enable_chroot_chdir;
extern int xsec_enable_chroot_chmod;
extern int xsec_enable_chroot_mknod;
extern int xsec_enable_chroot_fchdir;
extern int xsec_enable_chroot_nice;
extern int xsec_enable_chroot_execlog;
extern int xsec_enable_chroot_caps;
extern int xsec_enable_chroot_rename;
extern int xsec_enable_chroot_sysctl;
extern int xsec_enable_chroot_unix;
extern int xsec_enable_symlinkown;
extern kgid_t xsec_symlinkown_gid;
extern int xsec_enable_tpe;
extern kgid_t xsec_tpe_gid;
extern int xsec_enable_tpe_all;
extern int xsec_enable_tpe_invert;
extern int xsec_enable_socket_all;
extern kgid_t xsec_socket_all_gid;
extern int xsec_enable_socket_client;
extern kgid_t xsec_socket_client_gid;
extern int xsec_enable_socket_server;
extern kgid_t xsec_socket_server_gid;
extern kgid_t xsec_audit_gid;
extern int xsec_enable_group;
extern int xsec_enable_log_rwxmaps;
extern int xsec_enable_mount;
extern int xsec_enable_chdir;
extern int xsec_resource_logging;
extern int xsec_enable_blackhole;
extern int xsec_lastack_retries;
extern int xsec_enable_brute;
extern int xsec_enable_harden_ipc;
extern int xsec_enable_harden_tty;
extern int xsec_lock;

extern spinlock_t grsec_alert_lock;
extern unsigned long grsec_alert_wtime;
extern unsigned long grsec_alert_fyet;

extern spinlock_t grsec_audit_lock;

extern rwlock_t grsec_exec_file_lock;

#define x_task_fullpath(tsk) ((tsk)->exec_file ? \
			x_to_filename2((tsk)->exec_file->f_path.dentry, \
			(tsk)->exec_file->f_path.mnt) : "/")

#define x_parent_task_fullpath(tsk) ((tsk)->real_parent->exec_file ? \
			x_to_filename3((tsk)->real_parent->exec_file->f_path.dentry, \
			(tsk)->real_parent->exec_file->f_path.mnt) : "/")

#define x_task_fullpath0(tsk) ((tsk)->exec_file ? \
			x_to_filename((tsk)->exec_file->f_path.dentry, \
			(tsk)->exec_file->f_path.mnt) : "/")

#define x_parent_task_fullpath0(tsk) ((tsk)->real_parent->exec_file ? \
			x_to_filename1((tsk)->real_parent->exec_file->f_path.dentry, \
			(tsk)->real_parent->exec_file->f_path.mnt) : "/")

#define proc_is_chrooted(tsk_a)  ((tsk_a)->x_is_chrooted)

#define have_same_root(tsk_a,tsk_b) ((tsk_a)->x_chroot_dentry == (tsk_b)->x_chroot_dentry)

static inline bool x_is_same_file(const struct file *file1, const struct file *file2)
{
	if (file1 && file2) {
		const struct inode *inode1 = file1->f_path.dentry->d_inode;
		const struct inode *inode2 = file2->f_path.dentry->d_inode;
		if (inode1->i_ino == inode2->i_ino && inode1->i_sb->s_dev == inode2->i_sb->s_dev)
			return true;
	}

	return false;
}

#define X_CHROOT_CAPS {{ \
	CAP_TO_MASK(CAP_LINUX_IMMUTABLE) | CAP_TO_MASK(CAP_NET_ADMIN) | \
	CAP_TO_MASK(CAP_SYS_MODULE) | CAP_TO_MASK(CAP_SYS_RAWIO) | \
	CAP_TO_MASK(CAP_SYS_PACCT) | CAP_TO_MASK(CAP_SYS_ADMIN) | \
	CAP_TO_MASK(CAP_SYS_BOOT) | CAP_TO_MASK(CAP_SYS_TIME) | \
	CAP_TO_MASK(CAP_NET_RAW) | CAP_TO_MASK(CAP_SYS_TTY_CONFIG) | \
	CAP_TO_MASK(CAP_IPC_OWNER) | CAP_TO_MASK(CAP_SETFCAP), \
	CAP_TO_MASK(CAP_SYSLOG) | CAP_TO_MASK(CAP_MAC_ADMIN) }}

#define security_learn(normal_msg,args...) \
({ \
	read_lock(&xsec_exec_file_lock); \
	x_add_learn_entry(normal_msg "\n", ## args); \
	read_unlock(&xsec_exec_file_lock); \
})

enum {
	X_DO_AUDIT,
	X_DONT_AUDIT,
	/* used for non-audit messages that we shouldn't kill the task on */
	X_DONT_AUDIT_GOOD
};

enum {
	X_TTYSNIFF,
	X_RBAC,
	X_RBAC_STR,
	X_STR_RBAC,
	X_RBAC_MODE2,
	X_RBAC_MODE3,
	X_FILENAME,
	X_SYSCTL_HIDDEN,
	X_NOARGS,
	X_ONE_INT,
	X_ONE_INT_TWO_STR,
	X_ONE_STR,
	X_STR_INT,
	X_TWO_STR_INT,
	X_TWO_INT,
	X_TWO_U64,
	X_THREE_INT,
	X_FIVE_INT_TWO_STR,
	X_TWO_STR,
	X_THREE_STR,
	X_FOUR_STR,
	X_STR_FILENAME,
	X_FILENAME_STR,
	X_FILENAME_TWO_INT,
	X_FILENAME_TWO_INT_STR,
	X_TEXTREL,
	X_PTRACE,
	X_RESOURCE,
	X_CAP,
	X_SIG,
	X_SIG2,
	X_CRASH1,
	X_CRASH2,
	X_PSACCT,
	X_RWXMAP,
	X_RWXMAPVMA
};

#define x_log_hidden_sysctl(audit, msg, str) x_log_varargs(audit, msg, X_SYSCTL_HIDDEN, str)
#define x_log_ttysniff(audit, msg, task) x_log_varargs(audit, msg, X_TTYSNIFF, task)
#define x_log_fs_rbac_generic(audit, msg, dentry, mnt) x_log_varargs(audit, msg, X_RBAC, dentry, mnt)
#define x_log_fs_rbac_str(audit, msg, dentry, mnt, str) x_log_varargs(audit, msg, X_RBAC_STR, dentry, mnt, str)
#define x_log_fs_str_rbac(audit, msg, str, dentry, mnt) x_log_varargs(audit, msg, X_STR_RBAC, str, dentry, mnt)
#define x_log_fs_rbac_mode2(audit, msg, dentry, mnt, str1, str2) x_log_varargs(audit, msg, X_RBAC_MODE2, dentry, mnt, str1, str2)
#define x_log_fs_rbac_mode3(audit, msg, dentry, mnt, str1, str2, str3) x_log_varargs(audit, msg, X_RBAC_MODE3, dentry, mnt, str1, str2, str3)
#define x_log_fs_generic(audit, msg, dentry, mnt) x_log_varargs(audit, msg, X_FILENAME, dentry, mnt)
#define x_log_noargs(audit, msg) x_log_varargs(audit, msg, X_NOARGS)
#define x_log_int(audit, msg, num) x_log_varargs(audit, msg, X_ONE_INT, num)
#define x_log_int_str2(audit, msg, num, str1, str2) x_log_varargs(audit, msg, X_ONE_INT_TWO_STR, num, str1, str2)
#define x_log_str(audit, msg, str) x_log_varargs(audit, msg, X_ONE_STR, str)
#define x_log_str_int(audit, msg, str, num) x_log_varargs(audit, msg, X_STR_INT, str, num)
#define x_log_int_int(audit, msg, num1, num2) x_log_varargs(audit, msg, X_TWO_INT, num1, num2)
#define x_log_two_u64(audit, msg, num1, num2) x_log_varargs(audit, msg, X_TWO_U64, num1, num2)
#define x_log_int3(audit, msg, num1, num2, num3) x_log_varargs(audit, msg, X_THREE_INT, num1, num2, num3)
#define x_log_int5_str2(audit, msg, num1, num2, str1, str2) x_log_varargs(audit, msg, X_FIVE_INT_TWO_STR, num1, num2, str1, str2)
#define x_log_str_str(audit, msg, str1, str2) x_log_varargs(audit, msg, X_TWO_STR, str1, str2)
#define x_log_str2_int(audit, msg, str1, str2, num) x_log_varargs(audit, msg, X_TWO_STR_INT, str1, str2, num)
#define x_log_str3(audit, msg, str1, str2, str3) x_log_varargs(audit, msg, X_THREE_STR, str1, str2, str3)
#define x_log_str4(audit, msg, str1, str2, str3, str4) x_log_varargs(audit, msg, X_FOUR_STR, str1, str2, str3, str4)
#define x_log_str_fs(audit, msg, str, dentry, mnt) x_log_varargs(audit, msg, X_STR_FILENAME, str, dentry, mnt)
#define x_log_fs_str(audit, msg, dentry, mnt, str) x_log_varargs(audit, msg, X_FILENAME_STR, dentry, mnt, str)
#define x_log_fs_int2(audit, msg, dentry, mnt, num1, num2) x_log_varargs(audit, msg, X_FILENAME_TWO_INT, dentry, mnt, num1, num2)
#define x_log_fs_int2_str(audit, msg, dentry, mnt, num1, num2, str) x_log_varargs(audit, msg, X_FILENAME_TWO_INT_STR, dentry, mnt, num1, num2, str)
#define x_log_textrel_ulong_ulong(audit, msg, str, file, ulong1, ulong2) x_log_varargs(audit, msg, X_TEXTREL, str, file, ulong1, ulong2)
#define x_log_ptrace(audit, msg, task) x_log_varargs(audit, msg, X_PTRACE, task)
#define x_log_res_ulong2_str(audit, msg, task, ulong1, str, ulong2) x_log_varargs(audit, msg, X_RESOURCE, task, ulong1, str, ulong2)
#define x_log_cap(audit, msg, task, str) x_log_varargs(audit, msg, X_CAP, task, str)
#define x_log_sig_addr(audit, msg, str, addr) x_log_varargs(audit, msg, X_SIG, str, addr)
#define x_log_sig_task(audit, msg, task, num) x_log_varargs(audit, msg, X_SIG2, task, num)
#define x_log_crash1(audit, msg, task, ulong) x_log_varargs(audit, msg, X_CRASH1, task, ulong)
#define x_log_crash2(audit, msg, task, ulong1) x_log_varargs(audit, msg, X_CRASH2, task, ulong1)
#define x_log_procacct(audit, msg, task, num1, num2, num3, num4, num5, num6, num7, num8, num9) x_log_varargs(audit, msg, X_PSACCT, task, num1, num2, num3, num4, num5, num6, num7, num8, num9)
#define x_log_rwxmap(audit, msg, str) x_log_varargs(audit, msg, X_RWXMAP, str)
#define x_log_rwxmap_vma(audit, msg, str) x_log_varargs(audit, msg, X_RWXMAPVMA, str)

void x_log_varargs(int audit, const char *msg, int argtypes, ...);

#endif

#endif