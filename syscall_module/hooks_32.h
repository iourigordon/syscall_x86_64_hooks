#ifndef __HOOKS_32_H__
#define __HOOKS_32_H__

enum sys_calls_32_enum {
    ORIG_RENAME_32_IDX,
    ORIG_RENAMEAT_32_IDX,
    ORIG_RENAMEAT2_32_IDX,
    ORIG_UNLINK_32_IDX,
    ORIG_UNLINKAT_32_IDX,
    ORIG_CHOWN16_32_IDX,
    ORIG_CHOWN_32_IDX,
    ORIG_FCHOWN16_32_IDX,
    ORIG_FCHOWN_32_IDX,
    ORIG_LCHOWN16_32_IDX,
    ORIG_LCHOWN_32_IDX,
    ORIG_FCHOWNAT_32_IDX,
    ORIG_CHMOD_32_IDX,
    ORIG_FCHMOD_32_IDX,
    ORIG_FCHMODAT_32_IDX,
    ORIG_LINK_32_IDX,
    ORIG_LINKAT_32_IDX,
    ORIG_SYMLINK_32_IDX,
    ORIG_SYMLINKAT_32_IDX,
    ORIG_OPEN_32_IDX,
    ORIG_OPENAT_32_IDX,
    ORIG_CREAT_32_IDX,
    ORIG_RMDIR_32_IDX,
    ORIG_MAX_32_IDX
};

int init_hooks_32(void);
int replace_syscall_at_32(unsigned long *sys_call_table, int idx);
int revert_syscall_at_32(unsigned long *sys_call_table, int idx);

#endif

