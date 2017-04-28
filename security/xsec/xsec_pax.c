#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/xinternal.h>
#include <linux/xsecurity.h>

void
x_log_textrel(struct vm_area_struct * vma, bool is_textrel_rw)
{
#ifdef CONFIG_XKERNSEC_RWXMAP_LOG
	if (xsec_enable_log_rwxmaps)
		x_log_textrel_ulong_ulong(X_DONT_AUDIT, X_TEXTREL_AUDIT_MSG,
			is_textrel_rw ? "executable to writable" : "writable to executable",
			vma->vm_file, vma->vm_start, vma->vm_pgoff);
#endif
	return;
}

void x_log_ptgnustack(struct file *file)
{
#ifdef CONFIG_XKERNSEC_RWXMAP_LOG
	if (xsec_enable_log_rwxmaps)
		x_log_rwxmap(X_DONT_AUDIT, X_PTGNUSTACK_MSG, file);
#endif
	return;
}

void
x_log_rwxmmap(struct file *file)
{
#ifdef CONFIG_XKERNSEC_RWXMAP_LOG
	if (xsec_enable_log_rwxmaps)
		x_log_rwxmap(X_DONT_AUDIT, X_RWXMMAP_MSG, file);
#endif
	return;
}

void
x_log_rwxmprotect(struct vm_area_struct *vma)
{
#ifdef CONFIG_XKERNSEC_RWXMAP_LOG
	if (xsec_enable_log_rwxmaps)
		x_log_rwxmap_vma(X_DONT_AUDIT, X_RWXMPROTECT_MSG, vma);
#endif
	return;
}
