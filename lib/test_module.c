// SPDX-License-Identifier: GPL-2.0-only
/*
 * This module emits "Hello, world" on printk when loaded.
 *
 * It is designed to be used for basic evaluation of the module loading
 * subsystem (for example when validating module signing/verification). It
 * lacks any extra dependencies, and will not normally be loaded by the
 * system unless explicitly requested by name.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/random.h>


int crash_test(void)
{
	printk("About to Crash!!!\n");
	printk("%lu\n", *((unsigned long *)&crash_test));
	printk("After crash!!!\n");
	return 0;
}
EXPORT_SYMBOL(crash_test);

static int __init test_module_init(void)
{
	pr_warn("Hello, world\n");

	crash_test();

	return 0;
}

module_init(test_module_init);

static void __exit test_module_exit(void)
{
	pr_warn("Goodbye\n");
}

module_exit(test_module_exit);

MODULE_AUTHOR("Kees Cook <keescook@chromium.org>");
MODULE_LICENSE("GPL");
