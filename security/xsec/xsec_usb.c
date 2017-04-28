#include <linux/kernel.h>
#include <linux/xinternal.h>
#include <linux/module.h>

int x_handle_new_usb(void)
{
#ifdef CONFIG_XKERNSEC_DENYUSB
	if (xsec_deny_new_usb) {
		printk(KERN_ALERT "xsec: denied insert of new USB device\n");
		return 1;
	}
#endif
	return 0;
}
EXPORT_SYMBOL_GPL(x_handle_new_usb);
