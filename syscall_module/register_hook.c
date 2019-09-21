#include <linux/kernel.h>
#include <linux/kallsyms.h>

#include "hooks_32.h"
#include "hooks_64.h"
#include "register_hook.h"

int register_hooks(void)
{
    int i;
    unsigned long ret;
    unsigned long *sys_table;

    ret = kallsyms_lookup_name((const char*)"sys_call_table");
    printk(KERN_DEBUG "%s sys_call_table address = 0x%08lx\n",__func__,ret);
    sys_table = (unsigned long*)ret;
    
    init_hooks_64();
    for (i=0;i<ORIG_MAX_64_IDX;i++) {
        replace_syscall_at_64(sys_table,i);
    }

    ret = kallsyms_lookup_name((const char*)"ia32_sys_call_table");
    printk(KERN_DEBUG "%s ia32_sys_call_table address = 0x%08lx\n",__func__,ret);
    sys_table = (unsigned long*)ret;
    
    init_hooks_32();
    for (i=0;i<ORIG_MAX_32_IDX;i++) {
        replace_syscall_at_32(sys_table,i);
    }

	return 0;
}

int unregister_hooks(void)
{
    int i;
    unsigned long ret;
    unsigned long *sys_table;

    ret = kallsyms_lookup_name((const char*)"sys_call_table");
    printk(KERN_DEBUG "%s sys_call_table address = 0x%08lX\n",__func__,ret);
    sys_table = (unsigned long*)ret;
 
    for (i=0;i<ORIG_MAX_64_IDX;i++) {
        revert_syscall_at_64(sys_table,i);
    }

    ret = kallsyms_lookup_name((const char*)"ia32_sys_call_table");
    printk(KERN_DEBUG "%s ia32_sys_call_table address = 0x%08lX\n",__func__,ret);
    sys_table = (unsigned long*)ret;
 
    for (i=0;i<ORIG_MAX_32_IDX;i++) {
        revert_syscall_at_32(sys_table,i);
    }
    return 0;
}
