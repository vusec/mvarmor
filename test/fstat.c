#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>

int main()
{
    struct stat stat;
    int rv;
    rv = syscall(SYS_fstat, 1, &stat);
    printf("rv %d\n", rv);
    /*printf("&stat %p\n", &stat);*/
    printf(" st_dev %lu\n", stat.st_dev);
    printf(" st_ino %lu\n", stat.st_ino);
    printf(" st_mode %d\n", stat.st_mode);
    printf(" st_nlink %lu\n", stat.st_nlink);
    printf(" st_uid %d\n", stat.st_uid);
    printf(" st_gid %d\n", stat.st_gid);
    printf(" st_rdev %lu\n", stat.st_rdev);
    printf(" st_size %ld\n", stat.st_size);
    printf(" st_blksize %lu\n", stat.st_blksize);
    printf(" st_blocks %lu\n", stat.st_blocks);
    printf(" st_atim.tv_sec %lu\n", stat.st_atim.tv_sec);
    printf(" st_atim.tv_nsec %lu\n", stat.st_atim.tv_nsec);
    printf(" st_mtim.tv_sec %lu\n", stat.st_mtim.tv_sec);
    printf(" st_mtim.tv_nsec %lu\n", stat.st_mtim.tv_nsec);
    printf(" st_ctim.tv_sec %lu\n", stat.st_ctim.tv_sec);
    printf(" st_ctim.tv_nsec %lu\n", stat.st_ctim.tv_nsec);
    return 0;
}
