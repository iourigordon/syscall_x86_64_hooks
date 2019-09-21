#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <asm/syscall_wrapper.h>

#include "utils.h"
#include "hooks_64.h"
#include "map_64_idx.h"
#include "page_access.h"

asmlinkage long (* orig_func_64[ORIG_MAX_64_IDX])(const struct pt_regs *regs);

#define HOOK_FUNC(num_args, name, ...)\
    static long __sys_##name(const struct pt_regs *regs,\
                            __MAP(num_args,__SC_LONG,__VA_ARGS__));\
    static inline long hook_sys_##name(const struct pt_regs *regs,\
                                 __MAP(num_args,__SC_DECL,__VA_ARGS__));\
    asmlinkage long __x64_hook_sys_##name(const struct pt_regs *regs)\
    {\
        return __sys_##name(regs,SC_X86_64_REGS_TO_ARGS(num_args,__VA_ARGS__));\
    }\
    static long __sys_##name(const struct pt_regs *regs,\
                            __MAP(num_args,__SC_LONG,__VA_ARGS__))\
    {\
        long ret = hook_sys_##name(regs, __MAP(num_args,__SC_CAST,__VA_ARGS__));\
        __MAP(num_args,__SC_TEST,__VA_ARGS__);\
        __PROTECT(x, ret,__MAP(num_args,__SC_ARGS,__VA_ARGS__));\
        return ret;\
    }\
static inline long hook_sys_##name(const struct pt_regs *regs,\
                                 __MAP(num_args,__SC_DECL,__VA_ARGS__))


HOOK_FUNC(2, rename, const char __user *, oldname, const char __user *, newname)
{
    printk(KERN_DEBUG "This is my hook for rename_64\n");
    return orig_func_64[ORIG_RENAME_64_IDX](regs);
}

HOOK_FUNC(4, renameat, int, olddfd, const char __user *, oldname, int, newdfd, const char __user *, newname)
{
    printk(KERN_DEBUG "This is my hook for renameat_64\n");
    return orig_func_64[ORIG_RENAMEAT_64_IDX](regs);
}

HOOK_FUNC(5, renameat2, int, olddfd, const char __user *, oldname, int, newdfd, const char __user *, newname, unsigned int, flags)
{
    printk(KERN_DEBUG "This is my hook for renameat2_64\n");
    return orig_func_64[ORIG_RENAMEAT2_64_IDX](regs);
}

HOOK_FUNC(1,unlink,const char __user *, pathname)
{
    print_user_string(__func__,"pathname",pathname);
    return orig_func_64[ORIG_UNLINK_64_IDX](regs);
}

HOOK_FUNC(3, unlinkat, int, dfd, const char __user *, pathname, int, flag)
{
    print_user_int(__func__,"dfd",dfd);
    print_user_string(__func__,"pathname",pathname);
    print_user_int(__func__,"flag",flag);
    return orig_func_64[ORIG_UNLINKAT_64_IDX](regs);
}

HOOK_FUNC(3, chown, const char __user *, filename, uid_t, user, gid_t, group)
{
    printk(KERN_DEBUG "This is my hook for chown_64\n");
    return orig_func_64[ORIG_CHOWN_64_IDX](regs);
}

HOOK_FUNC(3, fchown, unsigned int, fd, uid_t, user, gid_t, group)
{
    printk(KERN_DEBUG "This is my hook for fchown_64\n");
    return orig_func_64[ORIG_FCHOWN_64_IDX](regs);
}

HOOK_FUNC(3, lchown, const char __user *, filename, uid_t, user, gid_t, group)
{
    printk(KERN_DEBUG "This is my hook for lchown_64\n");
    return orig_func_64[ORIG_LCHOWN_64_IDX](regs);
}

HOOK_FUNC(5, fchownat, int, dfd, const char __user *, filename, uid_t, user, gid_t, group, int, flag)
{
    printk(KERN_DEBUG "This is my hook for fchownat_64\n");
    return orig_func_64[ORIG_FCHOWNAT_64_IDX](regs);
}

HOOK_FUNC(2, chmod, const char __user *, filename, umode_t, mode) 
{
    printk(KERN_DEBUG "This is my hook chmod_64\n");
    return orig_func_64[ORIG_CHMOD_64_IDX](regs);
}

HOOK_FUNC(2, fchmod, unsigned int, fd, umode_t, mode)
{
    printk(KERN_DEBUG "This is my hook fchmod_64\n");
    return orig_func_64[ORIG_FCHMOD_64_IDX](regs);
}

HOOK_FUNC(3, fchmodat, int, dfd, const char __user *, filename, umode_t, mode)
{
    printk(KERN_DEBUG "This is my hook for fchmodat_64\n");
    return orig_func_64[ORIG_FCHMODAT_64_IDX](regs);
}

HOOK_FUNC(2, link, const char __user *, oldname, const char __user *, newname)
{
    printk(KERN_DEBUG "This is my hook for link_64\n");
    return orig_func_64[ORIG_LINK_64_IDX](regs);
}

HOOK_FUNC(5, linkat, int, olddfd, const char __user *, oldname, int, newdfd, const char __user *, newname, int, flags)
{
    printk(KERN_DEBUG "This is my hook for linkat_64\n");
    return orig_func_64[ORIG_LINKAT_64_IDX](regs);
}

HOOK_FUNC(2, symlink, const char __user *, oldname, const char __user *, newname)
{
    printk(KERN_DEBUG "This is my hook for symlink_64\n");
    return orig_func_64[ORIG_SYMLINK_64_IDX](regs);
}

HOOK_FUNC(3, symlinkat, const char __user *, oldname, int, newdfd, const char __user *, newname)
{
    printk(KERN_DEBUG "This is my hook for symlinkat_64\n");
    return orig_func_64[ORIG_SYMLINKAT_64_IDX](regs);
}

HOOK_FUNC(3, open, const char __user *, filename, int, flags, umode_t, mode)
{
    print_user_string(__func__,"filename",filename);
    print_user_int(__func__,"flags",flags);
    print_user_short(__func__,"mode",mode);
    return orig_func_64[ORIG_OPEN_64_IDX](regs);
}

HOOK_FUNC(4,openat, int, dfd, const char __user *, filename, int, flags, umode_t, mode)
{
    //printk(KERN_DEBUG "This is my hook for openat_64\n");
    return orig_func_64[ORIG_OPENAT_64_IDX](regs);
}

HOOK_FUNC(2, creat, const char __user *, pathname, umode_t, mode)
{
    print_user_string(__func__,"pathname",pathname);
    print_user_short(__func__,"mode",mode);
    return orig_func_64[ORIG_CREAT_64_IDX](regs);
}

HOOK_FUNC(1, rmdir, const char __user *, pathname)
{
    print_user_string(__func__,"pathname",pathname);
    return orig_func_64[ORIG_RMDIR_64_IDX](regs);
}

int init_hooks_64(void)
{
    int i;

    for (i=0;i<ORIG_MAX_64_IDX;i++) {
        orig_func_64[i] = NULL;
    }

    return 0;
}

int replace_syscall_at_64(unsigned long *sys_call_table, int idx)
{
    int ret;

    if ((ret=map_idx_64(idx)) < 0)
        return 1;

    printk(KERN_DEBUG "%s Replacing _64 system call 0x%08lX\n",__func__,sys_call_table[ret]);
    orig_func_64[idx] = (void*)sys_call_table[ret];
    if (!make_page_writable((unsigned long)sys_call_table)) {
        switch (idx) {
            case ORIG_RENAME_64_IDX:
                sys_call_table[ret] = (unsigned long)__x64_hook_sys_rename;
                break;
            case ORIG_RENAMEAT_64_IDX:
                sys_call_table[ret] = (unsigned long)__x64_hook_sys_renameat;
                break;
            case ORIG_RENAMEAT2_64_IDX:
                sys_call_table[ret] = (unsigned long)__x64_hook_sys_renameat2;
                break;
            case ORIG_UNLINK_64_IDX:
                sys_call_table[ret] = (unsigned long)__x64_hook_sys_unlink;
                break;
            case ORIG_UNLINKAT_64_IDX:
                sys_call_table[ret] = (unsigned long)__x64_hook_sys_unlinkat;
                break;
            case ORIG_CHOWN_64_IDX:
                sys_call_table[ret] = (unsigned long)__x64_hook_sys_chown;
                break;
            case ORIG_FCHOWN_64_IDX:
                sys_call_table[ret] = (unsigned long)__x64_hook_sys_fchown;
                break;
            case ORIG_LCHOWN_64_IDX:
                sys_call_table[ret] = (unsigned long)__x64_hook_sys_lchown;
                break;
            case ORIG_FCHOWNAT_64_IDX:
                sys_call_table[ret] = (unsigned long)__x64_hook_sys_fchownat;
                break;
            case ORIG_CHMOD_64_IDX:
                sys_call_table[ret] = (unsigned long)__x64_hook_sys_chmod;
                break;
            case ORIG_FCHMOD_64_IDX:
                sys_call_table[ret] = (unsigned long)__x64_hook_sys_fchmod;
                break;
            case ORIG_FCHMODAT_64_IDX:
                sys_call_table[ret] = (unsigned long)__x64_hook_sys_fchmodat;
                break;
            case ORIG_LINK_64_IDX:
                sys_call_table[ret] = (unsigned long)__x64_hook_sys_link;
                break;
            case ORIG_LINKAT_64_IDX:
                sys_call_table[ret] = (unsigned long)__x64_hook_sys_linkat;
                break;
            case ORIG_SYMLINK_64_IDX:
                sys_call_table[ret] = (unsigned long)__x64_hook_sys_symlink;
                break;
            case ORIG_SYMLINKAT_64_IDX:
                sys_call_table[ret] = (unsigned long)__x64_hook_sys_symlinkat;
                break; 
            case ORIG_OPEN_64_IDX:
                sys_call_table[ret] = (unsigned long)__x64_hook_sys_open;
                break;
            case ORIG_OPENAT_64_IDX:
                sys_call_table[ret] = (unsigned long)__x64_hook_sys_openat;
                break;
            case ORIG_CREAT_64_IDX:
                sys_call_table[ret] = (unsigned long)__x64_hook_sys_creat;
                break;
            case ORIG_RMDIR_64_IDX:
                sys_call_table[ret] = (unsigned long)__x64_hook_sys_rmdir;
                break;
            default:
                break;    
        }
        make_page_readonly((unsigned long)sys_call_table);
        return 0;
    }
    return 1;
}

int revert_syscall_at_64(unsigned long *sys_call_table, int idx)
{
    int ret;

    if ((ret=map_idx_64(idx)) < 0)
        return 1;

    if (orig_func_64[idx] && !make_page_writable((unsigned long)sys_call_table)) {
        sys_call_table[ret] = (unsigned long)orig_func_64[idx];
        make_page_readonly((unsigned long)sys_call_table);
        return 0;
    }
    return 1;
}

