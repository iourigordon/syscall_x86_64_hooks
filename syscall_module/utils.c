#include <linux/uaccess.h>
#include <linux/kernel.h>

#include "utils.h"

#define MAX_FILE_NAME 255

void print_user_string(const char* prnt_func, const char* param_name, const char __user *str)
{
    char buff[MAX_FILE_NAME];

    copy_from_user(buff,str,MAX_FILE_NAME);
    printk(KERN_DEBUG "%s: %s = %s\n", prnt_func, param_name, buff);
}

void print_user_short(const char* prnt_func, const char* param_name, unsigned short val)
{
    printk(KERN_DEBUG "%s: %s = %d\n", prnt_func, param_name, val);
}

void print_user_int(const char* prnt_func, const char* param_name, int val)
{
    printk(KERN_DEBUG "%s: %s = %d\n", prnt_func, param_name, val);
}
