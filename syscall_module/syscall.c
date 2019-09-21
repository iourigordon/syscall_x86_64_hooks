#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

MODULE_LICENSE("Dual BSD/GPL");

#include "register_hook.h"

static int syscall_init(void)
{
    printk(KERN_DEBUG "%s\n",__func__);
    register_hooks();
    return 0;
}

static void syscall_exit(void)
{
    unregister_hooks();
    printk(KERN_DEBUG "%s\n",__func__);
}

module_init(syscall_init);
module_exit(syscall_exit);
