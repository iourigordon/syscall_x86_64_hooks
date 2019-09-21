#include <linux/kernel.h>
#include <asm/unistd_64.h>

#include "hooks_64.h"

int map_idx_64(int sys_idx)
{
    int ret;
    switch (sys_idx) {
        case ORIG_RENAME_64_IDX:
            ret = __NR_rename;
            break;
        case ORIG_RENAMEAT_64_IDX:
            ret = __NR_renameat;
            break;
        case ORIG_RENAMEAT2_64_IDX:
            ret = __NR_renameat2;
            break;
        case ORIG_UNLINK_64_IDX:
            ret = __NR_unlink;
            break;
        case ORIG_UNLINKAT_64_IDX:
            ret = __NR_unlinkat;
            break;
        case ORIG_CHOWN_64_IDX:
            ret = __NR_chown;
            break;
        case ORIG_FCHOWN_64_IDX:
            ret = __NR_fchown;
            break;
        case ORIG_LCHOWN_64_IDX:
            ret = __NR_lchown;
            break;
        case ORIG_FCHOWNAT_64_IDX:
            ret = __NR_fchownat;
            break;
        case ORIG_CHMOD_64_IDX:
            ret = __NR_chmod;
            break;
        case ORIG_FCHMOD_64_IDX:
            ret = __NR_fchmod;
            break;
        case ORIG_FCHMODAT_64_IDX:
            ret = __NR_fchmodat;
            break;
        case ORIG_LINK_64_IDX:
            ret = __NR_link;
            break;
        case ORIG_LINKAT_64_IDX:
            ret = __NR_linkat;
            break;
        case ORIG_SYMLINK_64_IDX:
            ret = __NR_symlink;
            break;
        case ORIG_SYMLINKAT_64_IDX:
            ret = __NR_symlinkat;
            break;
        case ORIG_OPEN_64_IDX:
            ret = __NR_open;
            break;
        case ORIG_OPENAT_64_IDX:
            ret = __NR_openat;
            break;
        case ORIG_CREAT_64_IDX:
            ret = __NR_creat;
            break;
        case ORIG_RMDIR_64_IDX:
            ret = __NR_rmdir;
            break;
        default:
            printk(KERN_DEBUG "Unknown syscall idx\n");
            ret = -1;
    }
    return ret;
}

