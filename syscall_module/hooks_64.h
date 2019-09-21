#ifndef __HOOKS_64_H__
#define __HOOKS_64_H__

enum sys_calls_64_enum {
    ORIG_RENAME_64_IDX,
    ORIG_RENAMEAT_64_IDX,
    ORIG_RENAMEAT2_64_IDX,
    ORIG_UNLINK_64_IDX,
    ORIG_UNLINKAT_64_IDX,
    ORIG_CHOWN_64_IDX,
    ORIG_FCHOWN_64_IDX,
    ORIG_LCHOWN_64_IDX,
    ORIG_FCHOWNAT_64_IDX,
    ORIG_CHMOD_64_IDX,
    ORIG_FCHMOD_64_IDX,
    ORIG_FCHMODAT_64_IDX,
    ORIG_LINK_64_IDX,
    ORIG_LINKAT_64_IDX,
    ORIG_SYMLINK_64_IDX,
    ORIG_SYMLINKAT_64_IDX,
    ORIG_OPEN_64_IDX,
    ORIG_OPENAT_64_IDX,
    ORIG_CREAT_64_IDX,
    ORIG_RMDIR_64_IDX,
    ORIG_MAX_64_IDX
};

int init_hooks_64(void);
int replace_syscall_at_64(unsigned long *sys_call_table, int idx);
int revert_syscall_at_64(unsigned long *sys_call_table, int idx);

#endif
