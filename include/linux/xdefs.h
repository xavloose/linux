#ifndef XDEFS_H
#define XDEFS_H

/* Begin xsec status declarations */

enum {
	X_READY = 0x01,
	X_STATUS_INIT = 0x00	// disabled state
};

/* Begin  ACL declarations */

/* Role flags */

enum {
	X_ROLE_USER = 0x0001,
	X_ROLE_GROUP = 0x0002,
	X_ROLE_DEFAULT = 0x0004,
	X_ROLE_SPECIAL = 0x0008,
	X_ROLE_AUTH = 0x0010,
	X_ROLE_NOPW = 0x0020,
	X_ROLE_GOD = 0x0040,
	X_ROLE_LEARN = 0x0080,
	X_ROLE_TPE = 0x0100,
	X_ROLE_DOMAIN = 0x0200,
	X_ROLE_PAM = 0x0400,
	X_ROLE_PERSIST = 0x0800
};

/* ACL Subject and Object mode flags */
enum {
	X_DELETED = 0x80000000
};

/* ACL Object-only mode flags */
enum {
	X_READ 	= 0x00000001,
	X_APPEND 	= 0x00000002,
	X_WRITE 	= 0x00000004,
	X_EXEC 	= 0x00000008,
	X_FIND 	= 0x00000010,
	X_INHERIT 	= 0x00000020,
	X_SETID 	= 0x00000040,
	X_CREATE 	= 0x00000080,
	X_DELETE 	= 0x00000100,
	X_LINK		= 0x00000200,
	X_AUDIT_READ 	= 0x00000400,
	X_AUDIT_APPEND = 0x00000800,
	X_AUDIT_WRITE 	= 0x00001000,
	X_AUDIT_EXEC 	= 0x00002000,
	X_AUDIT_FIND 	= 0x00004000,
	X_AUDIT_INHERIT= 0x00008000,
	X_AUDIT_SETID 	= 0x00010000,
	X_AUDIT_CREATE = 0x00020000,
	X_AUDIT_DELETE = 0x00040000,
	X_AUDIT_LINK	= 0x00080000,
	X_PTRACERD 	= 0x00100000,
	X_NOPTRACE	= 0x00200000,
	X_SUPPRESS 	= 0x00400000,
	X_NOLEARN 	= 0x00800000,
	X_INIT_TRANSFER= 0x01000000
};

#define X_AUDITS (X_AUDIT_READ | X_AUDIT_WRITE | X_AUDIT_APPEND | X_AUDIT_EXEC | \
		   X_AUDIT_FIND | X_AUDIT_INHERIT | X_AUDIT_SETID | \
		   X_AUDIT_CREATE | X_AUDIT_DELETE | X_AUDIT_LINK)

/* ACL subject-only mode flags */
enum {
	X_KILL 	= 0x00000001,
	X_VIEW 	= 0x00000002,
	X_PROTECTED 	= 0x00000004,
	X_LEARN 	= 0x00000008,
	X_OVERRIDE 	= 0x00000010,
	/* just a placeholder, this mode is only used in userspace */
	X_DUMMY 	= 0x00000020,
	X_PROTSHM	= 0x00000040,
	X_KILLPROC	= 0x00000080,
	X_KILLIPPROC	= 0x00000100,
	/* just a placeholder, this mode is only used in userspace */
	X_NOTROJAN	= 0x00000200,
	X_PROTPROCFD	= 0x00000400,
	X_PROCACCT	= 0x00000800,
	X_RELAXPTRACE	= 0x00001000,
	//X_NESTED	= 0x00002000,
	X_INHERITLEARN	= 0x00004000,
	X_PROCFIND	= 0x00008000,
	X_POVERRIDE	= 0x00010000,
	X_KERNELAUTH	= 0x00020000,
	X_ATSECURE	= 0x00040000,
	X_SHMEXEC	= 0x00080000
};

enum {
	X_PAX_ENABLE_SEGMEXEC	= 0x0001,
	X_PAX_ENABLE_PAGEEXEC	= 0x0002,
	X_PAX_ENABLE_MPROTECT	= 0x0004,
	X_PAX_ENABLE_RANDMMAP	= 0x0008,
	X_PAX_ENABLE_EMUTRAMP	= 0x0010,
	X_PAX_DISABLE_SEGMEXEC	= 0x0100,
	X_PAX_DISABLE_PAGEEXEC	= 0x0200,
	X_PAX_DISABLE_MPROTECT	= 0x0400,
	X_PAX_DISABLE_RANDMMAP	= 0x0800,
	X_PAX_DISABLE_EMUTRAMP	= 0x1000,
};

enum {
	X_ID_USER	= 0x01,
	X_ID_GROUP	= 0x02,
};

enum {
	X_ID_ALLOW	= 0x01,
	X_ID_DENY	= 0x02,
};

#define X_CRASH_RES	31
#define X_UIDTABLE_MAX 500

/* begin resource learning section */
enum {
	X_RLIM_CPU_BUMP = 60,
	X_RLIM_FSIZE_BUMP = 50000,
	X_RLIM_DATA_BUMP = 10000,
	X_RLIM_STACK_BUMP = 1000,
	X_RLIM_CORE_BUMP = 10000,
	X_RLIM_RSS_BUMP = 500000,
	X_RLIM_NPROC_BUMP = 1,
	X_RLIM_NOFILE_BUMP = 5,
	X_RLIM_MEMLOCK_BUMP = 50000,
	X_RLIM_AS_BUMP = 500000,
	X_RLIM_LOCKS_BUMP = 2,
	X_RLIM_SIGPENDING_BUMP = 5,
	X_RLIM_MSGQUEUE_BUMP = 10000,
	X_RLIM_NICE_BUMP = 1,
	X_RLIM_RTPRIO_BUMP = 1,
	X_RLIM_RTTIME_BUMP = 1000000
};

#endif