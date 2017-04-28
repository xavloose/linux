#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/xsecurity.h>
#include <linux/xinternal.h>
#include <linux/errno.h>

void
x_log_forkfail(const int retval)
{
#ifdef CONFIG_XKERNSEC_FORKFAIL
	if (xsec_enable_forkfail && (retval == -EAGAIN || retval == -ENOMEM)) {
		switch (retval) {
			case -EAGAIN:
				x_log_str(X_DONT_AUDIT, X_FAILFORK_MSG, "EAGAIN");
				break;
			case -ENOMEM:
				x_log_str(X_DONT_AUDIT, X_FAILFORK_MSG, "ENOMEM");
				break;
		}
	}
#endif
	return;
}
