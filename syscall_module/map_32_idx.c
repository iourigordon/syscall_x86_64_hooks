#include <linux/kernel.h>
#include <asm/unistd_32.h>

#include "hooks_32.h"

int map_idx_32(int sys_idx)
{
    int ret;
    switch (sys_idx) {
        case ORIG_RENAME_32_IDX:
            ret = __NR_rename;
            break;
        case ORIG_RENAMEAT_32_IDX:
            ret = __NR_renameat;
            break;
        case ORIG_RENAMEAT2_32_IDX:
            ret = __NR_renameat2;
            break;
        case ORIG_UNLINK_32_IDX:
            ret = __NR_unlink;
            break;
        case ORIG_UNLINKAT_32_IDX:
            ret = __NR_unlinkat;
            break;
        case ORIG_CHOWN16_32_IDX:
            ret =__NR_chown; 
            break;
        case ORIG_CHOWN_32_IDX:
            ret = __NR_chown32;
            break;
        case ORIG_FCHOWN16_32_IDX:
            ret = __NR_fchown;
            break;
        case ORIG_FCHOWN_32_IDX:
            ret = __NR_fchown32;
            break;
        case ORIG_LCHOWN16_32_IDX:
            ret = __NR_lchown;
            break;
        case ORIG_LCHOWN_32_IDX:
            ret = __NR_lchown32;
            break;
        case ORIG_FCHOWNAT_32_IDX:
            ret = __NR_fchownat;
            break;
        case ORIG_CHMOD_32_IDX:
            ret = __NR_chmod;
            break;
        case ORIG_FCHMOD_32_IDX:
            ret = __NR_fchmod;
            break;
        case ORIG_FCHMODAT_32_IDX:
            ret = __NR_fchmodat;
            break;
        case ORIG_LINK_32_IDX:
            ret = __NR_link;
            break;
        case ORIG_LINKAT_32_IDX:
            ret = __NR_linkat;
            break;
        case ORIG_SYMLINK_32_IDX:
            ret = __NR_symlink;
            break;
        case ORIG_SYMLINKAT_32_IDX:
            ret = __NR_symlinkat;
            break;
        case ORIG_OPEN_32_IDX:
            ret = __NR_open;
            break;
        case ORIG_OPENAT_32_IDX:
            ret = __NR_openat;
            break;
        case ORIG_CREAT_32_IDX:
            ret = __NR_creat;
            break;
        case ORIG_RMDIR_32_IDX:
            ret = __NR_rmdir;
            break;
        default:
            printk(KERN_DEBUG "Unknown syscall idx\n");
            ret = -1;
    }
    return ret;
}

