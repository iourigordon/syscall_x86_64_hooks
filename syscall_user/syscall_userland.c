#define _GNU_SOURCE

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>

#include <stdio.h>
#include <errno.h>
#include <string.h>

#define WORK_DIR "test_dir/"
#define FILE_NAME "test.txt"
#define FILE_PATH WORK_DIR FILE_NAME

int main(int argc, char* argv[])
{
    int ret, dir_fd, file_fd;

    printf("%s: dir name: %s; mode: %d\n","SYS_mkdir",WORK_DIR,0755);
    if ((dir_fd=syscall(SYS_mkdir,WORK_DIR,0755)) < 0) {
        printf("Failed to create directory %s: %s %d\n",WORK_DIR,strerror(errno),errno);
    }
    
    //create
    printf("%s: filename: %s; mode: %d\n","SYS_creat",FILE_PATH,S_IRUSR|S_IWUSR);
    if ((file_fd=syscall(SYS_creat,FILE_PATH,S_IRUSR|S_IWUSR)) < 0) {
        printf("Failed to create file %s under %s: %s %d \n",FILE_NAME,WORK_DIR,strerror(errno),errno);
    }

    if ((ret = close(file_fd)) < 0) {
        printf("Failed to close: %s %d\n", strerror(errno),errno);
    }

    //open
    printf("%s: filepath %s: flags %d\n","SYS_open",FILE_PATH,O_RDWR);
    if ((file_fd = syscall(SYS_open,FILE_PATH,O_RDWR)) < 0) {
        printf("Failed to open %s %s %d\n",FILE_PATH,strerror(errno), errno);
    }

    if ((ret = close(file_fd)) < 0) {
        printf("Failed to close: %s %d\n", strerror(errno),errno);
    }

    //unlink
    printf("%s: filepath %s\n","SYS_unlink",FILE_PATH);
    if ((ret = syscall(SYS_unlink,FILE_PATH)) < 0) {
        printf("Failed to unlink %s: %s %d \n",FILE_PATH,strerror(errno),errno);
    }

    //openat
    //prep for openat
    printf("%s: filename %s: mode %d\n","SYS_creat",FILE_PATH,S_IRUSR|S_IWUSR);
    if ((file_fd=syscall(SYS_creat,FILE_PATH,S_IRUSR|S_IWUSR)) < 0) {
        printf("Failed to create file %s under %s: %s %d \n",FILE_NAME,WORK_DIR,strerror(errno),errno);
    }

    if ((ret = close(file_fd)) < 0) {
        printf("Failed to close: %s %d\n", strerror(errno),errno);
    }

    //real openat
    printf("%s: directory %s: flags %d\n","SYS_open",WORK_DIR,O_PATH|O_RDWR);
    if ((dir_fd = syscall(SYS_open,WORK_DIR, O_PATH|O_RDWR)) < 0) {
        printf("Failed to get desc for %s: %s %d\n",WORK_DIR,strerror(errno),errno);
    }

    printf("%s: dir_fd %d: filename %s: flags %d\n","SYS_openat",dir_fd,FILE_NAME,O_RDWR);
    if ((file_fd = syscall(SYS_openat,dir_fd,FILE_NAME,O_RDWR)) < 0) {
        printf("Failed to openat %s: %s %d\n",FILE_NAME,strerror(errno),errno);
    }

    //unlink at
    printf("%s: dir_fd %d: filename %s: flags %d\n","SYS_unlinkat",dir_fd,FILE_NAME,0);
    if ((ret = syscall(SYS_unlinkat,dir_fd,FILE_NAME,0)) < 0) {
        printf("Failed to unlinkat %s: %s %d\n",FILE_NAME,strerror(errno),errno);
    }

    //rmdir
    printf("%s: dir name %s\n","SYS_rmdir",WORK_DIR);
    if ((ret = syscall(SYS_rmdir,WORK_DIR)) < 0) {
        printf("Failed to rmdir: %s %d\n", strerror(errno),errno);
    }

    return 0;
}

