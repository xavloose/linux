#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/xinternal.h>
#include <linux/module.h>

void
x_log_timechange(void)
{
#ifdef CONFIG_XKERNSEC_TIME
	if (xsec_enable_time)
		x_log_noargs(X_DONT_AUDIT_GOOD, X_TIME_MSG);
#endif
	return;
}

EXPORT_SYMBOL_GPL(x_log_timechange);
