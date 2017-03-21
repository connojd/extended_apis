#include <linux/module.h>
#include <linux/kernel.h>

static int test_wbinvd_init(void)
{
	printk(KERN_INFO "test_wbinvd: loading");
	printk(KERN_INFO "test_wbinvd: executing wbinvd...");

	asm volatile("wbinvd");

	return 0;
}

static void test_wbinvd_exit(void)
{
	printk(KERN_INFO "test_wbinvd: unloading");
}

module_init(test_wbinvd_init);
module_exit(test_wbinvd_exit);
MODULE_LICENSE("GPL");
