#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/xsecurity.h>
#include <linux/xinternal.h>
#include <linux/capability.h>
#include <linux/tty.h>

int x_handle_tiocsti(struct tty_struct *tty)
{
#ifdef CONFIG_XKERNSEC_HARDEN_TTY
	if (xsec_enable_harden_tty && (current->signal->tty == tty) &&
	    !capable(CAP_SYS_ADMIN)) {
		x_log_noargs(X_DONT_AUDIT, X_TIOCSTI_MSG);
		return 1;
	}
#endif
	return 0;
}
