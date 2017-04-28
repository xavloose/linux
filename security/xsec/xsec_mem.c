#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/module.h>
#include <linux/xinternal.h>

void x_handle_msr_write(void)
{
	x_log_noargs(X_DONT_AUDIT, X_MSRWRITE_MSG);
	return;
}
EXPORT_SYMBOL_GPL(x_handle_msr_write);

void
x_handle_ioperm(void)
{
	x_log_noargs(X_DONT_AUDIT, X_IOPERM_MSG);
	return;
}

void
x_handle_iopl(void)
{
	x_log_noargs(X_DONT_AUDIT, X_IOPL_MSG);
	return;
}

void
x_handle_mem_readwrite(u64 from, u64 to)
{
	x_log_two_u64(X_DONT_AUDIT, X_MEM_READWRITE_MSG, from, to);
	return;
}

void
x_handle_vm86(void)
{
	x_log_noargs(X_DONT_AUDIT, X_VM86_MSG);
	return;
}

void
x_log_badprocpid(const char *entry)
{
	x_log_str(X_DONT_AUDIT, X_BADPROCPID_MSG, entry);
	return;
}
