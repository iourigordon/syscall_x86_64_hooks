#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <asm/syscall_wrapper.h>

#include "utils.h"
#include "hooks_32.h"
#include "map_32_idx.h"
#include "page_access.h"

asmlinkage long (* orig_func_32[ORIG_MAX_32_IDX])(const struct pt_regs *regs);

#define HOOK_FUNC_32(num_args, name, ...)\
    static long __sys_##name(const struct pt_regs *regs,\
                            __MAP(num_args,__SC_LONG,__VA_ARGS__));\
    static inline long hook_sys_##name(const struct pt_regs *regs,\
                                 __MAP(num_args,__SC_DECL,__VA_ARGS__));\
    asmlinkage long __ia32_hook_sys_##name(const struct pt_regs *regs)\
    {\
        return __sys_##name(regs,SC_IA32_REGS_TO_ARGS(num_args,__VA_ARGS__));\
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


HOOK_FUNC_32(3, chown16, const char __user *, filename, old_uid_t, user, old_gid_t, group)
{
    printk(KERN_DEBUG "This is my hook for chown16_32\n");
    return orig_func_32[ORIG_CHOWN16_32_IDX](regs);
}

HOOK_FUNC_32(3, lchown16, const char __user *, filename, old_uid_t, user, old_gid_t, group)
{
    printk(KERN_DEBUG "This is my hook for lchown16_32\n");
    return orig_func_32[ORIG_LCHOWN16_32_IDX](regs);
}

HOOK_FUNC_32(3, fchown16, unsigned int, fd, old_uid_t, user, old_gid_t, group)
{
    printk(KERN_DEBUG "This is my hook for fchown16_32\n");
    return orig_func_32[ORIG_FCHOWN16_32_IDX](regs);
}

HOOK_FUNC_32(3, fchown, unsigned int, fd, uid_t, user, gid_t, group)
{
    printk(KERN_DEBUG "This is my hook for fchown_32\n");
    return orig_func_32[ORIG_FCHOWN_32_IDX](regs);
}

HOOK_FUNC_32(5, fchownat, int, dfd, const char __user *, filename, uid_t, user,
                gid_t, group, int, flag)
{
    printk(KERN_DEBUG "This is my hook for fchownat_32\n");
    return orig_func_32[ORIG_FCHOWNAT_32_IDX](regs);
}

HOOK_FUNC_32(3, lchown, const char __user *, filename, uid_t, user, gid_t, group)
{
    printk(KERN_DEBUG "This is my hook for lchown_32\n");
    return orig_func_32[ORIG_LCHOWN_32_IDX](regs);
}

HOOK_FUNC_32(3, chown, const char __user *, filename, uid_t, user, gid_t, group)
{
    printk(KERN_DEBUG "This is my hook for chown_32\n");
    return orig_func_32[ORIG_CHOWN_32_IDX](regs);
}

HOOK_FUNC_32(2, chmod, const char __user *, filename, umode_t, mode)
{
    printk(KERN_DEBUG "This is my hook for chmod_32\n");
    return orig_func_32[ORIG_CHMOD_32_IDX](regs);
}

HOOK_FUNC_32(2, fchmod, unsigned int, fd, umode_t, mode)
{
    printk(KERN_DEBUG "This is my hook for fchmod_32\n");
    return orig_func_32[ORIG_FCHMOD_32_IDX](regs);
}

HOOK_FUNC_32(3, fchmodat, int, dfd, const char __user *, filename, umode_t, mode)
{
    printk(KERN_DEBUG "This is my hook for fchmodat_32\n");
    return orig_func_32[ORIG_FCHMODAT_32_IDX](regs);
}

HOOK_FUNC_32(2, rename, const char __user *, oldname, const char __user *, newname)
{
    printk(KERN_DEBUG "This is my hook for rename_32\n");
    return orig_func_32[ORIG_RENAME_32_IDX](regs);
}

HOOK_FUNC_32(4, renameat, int, olddfd, const char __user *, oldname,
                int, newdfd, const char __user *, newname)
{
    printk(KERN_DEBUG "This is my hook for renameat_32\n");
    return orig_func_32[ORIG_RENAMEAT_32_IDX](regs);
}

HOOK_FUNC_32(5, renameat2, int, olddfd, const char __user *, oldname,
                int, newdfd, const char __user *, newname, unsigned int, flags)
{
    printk(KERN_DEBUG "This is my hook for renameat2_32\n");
    return orig_func_32[ORIG_RENAMEAT2_32_IDX](regs);
}

HOOK_FUNC_32(1, unlink, const char __user *, pathname)
{
    print_user_string(__func__,"pathname",pathname);
    return orig_func_32[ORIG_UNLINK_32_IDX](regs);
}

HOOK_FUNC_32(3, unlinkat, int, dfd, const char __user *, pathname, int, flag)
{
    print_user_int(__func__,"dfd",dfd);
    print_user_string(__func__,"pathname",pathname);
    print_user_int(__func__,"flag",flag);
    return orig_func_32[ORIG_UNLINKAT_32_IDX](regs);
}

HOOK_FUNC_32(2, link, const char __user *, oldname, const char __user *, newname)
{
    printk(KERN_DEBUG "This is my hook for link_32\n");
    return orig_func_32[ORIG_LINK_32_IDX](regs);
}

HOOK_FUNC_32(5, linkat, int, olddfd, const char __user *, oldname,
                int, newdfd, const char __user *, newname, int, flags)
{
    printk(KERN_DEBUG "This is my hook for linkat_32\n");
    return orig_func_32[ORIG_LINKAT_32_IDX](regs);
}

HOOK_FUNC_32(2, symlink, const char __user *, oldname, const char __user *, newname)
{
    printk(KERN_DEBUG "This is my hook for symlink_32\n");
    return orig_func_32[ORIG_SYMLINK_32_IDX](regs);
}

HOOK_FUNC_32(3, symlinkat, const char __user *, oldname,
                int, newdfd, const char __user *, newname)
{
    printk(KERN_DEBUG "This is my hook for symlinkat_32\n");
    return orig_func_32[ORIG_SYMLINKAT_32_IDX](regs);
}

HOOK_FUNC_32(3, open, const char __user *, filename, int, flags, umode_t, mode)
{
    print_user_string(__func__,"filename",filename);
    print_user_int(__func__,"flags",flags);
    print_user_short(__func__,"mode",mode);
    return orig_func_32[ORIG_OPEN_32_IDX](regs);
}

HOOK_FUNC_32(4, openat, int, dfd, const char __user *, filename, int, flags,
                umode_t, mode)
{
    printk(KERN_DEBUG "This is my hook for openat_32\n");
    return orig_func_32[ORIG_OPENAT_32_IDX](regs);
}

HOOK_FUNC_32(2, creat, const char __user *, pathname, umode_t, mode)
{
    print_user_string(__func__,"pathname",pathname);
    print_user_short(__func__,"mode",mode);
    return orig_func_32[ORIG_CREAT_32_IDX](regs);
}

HOOK_FUNC_32(1, rmdir, const char __user *, pathname)
{
    print_user_string(__func__,"pathname",pathname);
    return orig_func_32[ORIG_RMDIR_32_IDX](regs);
}

int init_hooks_32(void)
{
    int i;

    for (i=0;i<ORIG_MAX_32_IDX;i++) {
        orig_func_32[i] = NULL;
    }

    return 0;
}

int replace_syscall_at_32(unsigned long *sys_call_table, int idx)
{
    int ret;

    if ((ret=map_idx_32(idx)) < 0)
        return 1;

    printk(KERN_DEBUG "%s Replacing _32 system call 0x%08lX\n",__func__,sys_call_table[ret]);
    orig_func_32[idx] = (void*)sys_call_table[ret];
    if (!make_page_writable((unsigned long)sys_call_table)) {
        switch (idx) {
            case ORIG_RENAME_32_IDX:
                sys_call_table[ret] = (unsigned long)__ia32_hook_sys_rename;
                break;
            case ORIG_RENAMEAT_32_IDX:
                sys_call_table[ret] = (unsigned long)__ia32_hook_sys_renameat;
                break;
            case ORIG_RENAMEAT2_32_IDX:
                sys_call_table[ret] = (unsigned long)__ia32_hook_sys_renameat2;
                break;
            case ORIG_UNLINK_32_IDX:
                sys_call_table[ret] = (unsigned long)__ia32_hook_sys_unlink;
                break;
            case ORIG_UNLINKAT_32_IDX:
                sys_call_table[ret] = (unsigned long)__ia32_hook_sys_unlinkat;
                break;
            case ORIG_CHOWN16_32_IDX:
                sys_call_table[ret] = (unsigned long)__ia32_hook_sys_chown16;
                break;
            case ORIG_CHOWN_32_IDX:
                sys_call_table[ret] = (unsigned long)__ia32_hook_sys_chown;
                break;
            case ORIG_FCHOWN16_32_IDX:
                sys_call_table[ret] = (unsigned long)__ia32_hook_sys_fchown16;
                break;
            case ORIG_FCHOWN_32_IDX:
                sys_call_table[ret] = (unsigned long)__ia32_hook_sys_fchown;
                break;
            case ORIG_LCHOWN16_32_IDX:
                sys_call_table[ret] = (unsigned long)__ia32_hook_sys_lchown16;
                break;
            case ORIG_LCHOWN_32_IDX:
                sys_call_table[ret] = (unsigned long)__ia32_hook_sys_lchown;
                break;
            case ORIG_FCHOWNAT_32_IDX:
                sys_call_table[ret] = (unsigned long)__ia32_hook_sys_fchownat;
                break;
            case ORIG_CHMOD_32_IDX:
                sys_call_table[ret] = (unsigned long)__ia32_hook_sys_chmod;
                break;
            case ORIG_FCHMOD_32_IDX:
                sys_call_table[ret] = (unsigned long)__ia32_hook_sys_fchmod;
                break;
            case ORIG_FCHMODAT_32_IDX:
                sys_call_table[ret] = (unsigned long)__ia32_hook_sys_fchmodat;
                break;
            case ORIG_LINK_32_IDX:
                sys_call_table[ret] = (unsigned long)__ia32_hook_sys_link;
                break;
            case ORIG_LINKAT_32_IDX:
                sys_call_table[ret] = (unsigned long)__ia32_hook_sys_linkat;
                break;
            case ORIG_SYMLINK_32_IDX:
                sys_call_table[ret] = (unsigned long)__ia32_hook_sys_symlink;
                break;
            case ORIG_SYMLINKAT_32_IDX:
                sys_call_table[ret] = (unsigned long)__ia32_hook_sys_symlinkat;
                break;
            case ORIG_OPEN_32_IDX:
                sys_call_table[ret] = (unsigned long)__ia32_hook_sys_open;
                break;
            case ORIG_OPENAT_32_IDX:
                sys_call_table[ret] = (unsigned long)__ia32_hook_sys_openat;
                break;
            case ORIG_CREAT_32_IDX:
                sys_call_table[ret] = (unsigned long)__ia32_hook_sys_creat;
                break;
            case ORIG_RMDIR_32_IDX:
                sys_call_table[ret] = (unsigned long)__ia32_hook_sys_rmdir;
                break;
            default:
                break;    
        }
        make_page_readonly((unsigned long)sys_call_table);
        return 0;
    }
    return 1;
}

int revert_syscall_at_32(unsigned long *sys_call_table, int idx)
{
    int ret;

    if ((ret=map_idx_32(idx)) < 0)
        return 1;

    if (orig_func_32[idx] && !make_page_writable((unsigned long)sys_call_table)) {
        sys_call_table[ret] = (unsigned long)orig_func_32[idx];
        make_page_readonly((unsigned long)sys_call_table);
        return 0;
    }
    return 1;
}

