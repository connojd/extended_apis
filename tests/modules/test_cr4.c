#include <linux/module.h>
#include <linux/kernel.h>

static int test_cr4_init(void)
{
	printk(KERN_INFO "test_cr4: loading");
	printk(KERN_INFO "test_cr4: enabling cr4.pce and cr4.umip");

        asm volatile("xor %rax, %rax");
	asm volatile("mov %cr4, %rax");
        asm volatile("xor $0x900, %rax");
        asm volatile("mov %rax, %cr4");

	return 0;
}

static void test_cr4_exit(void)
{
	printk(KERN_INFO "test_cr4: unloading");

        asm volatile("xor %rax, %rax");
	asm volatile("mov %cr4, %rax");
        asm volatile("and $0xfffffffffffff6ff, %rax");
        asm volatile("mov %rax, %cr4");
}

module_init(test_cr4_init);
module_exit(test_cr4_exit);
MODULE_LICENSE("GPL");
