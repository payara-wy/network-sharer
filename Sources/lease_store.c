/* Prepare a private, root-owned DHCP lease store without following links. */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef NETWORKSHARER_LEASE_PARENT
#define NETWORKSHARER_LEASE_PARENT "/private/var/db"
#endif
#ifndef NETWORKSHARER_EXPECTED_UID
#define NETWORKSHARER_EXPECTED_UID 0
#endif
#define DIRECTORY "com.local.lansharer"
#define FILE_NAME "dhcp-leases.ini"

static int safe_directory(int fd,mode_t forbidden) {
    struct stat st;
    return !fstat(fd,&st) && S_ISDIR(st.st_mode) && st.st_uid==NETWORKSHARER_EXPECTED_UID &&
           !(st.st_mode&forbidden);
}
int main(void) {
    if (geteuid()!=NETWORKSHARER_EXPECTED_UID) return 1;
    umask(077);
    int parent=open(NETWORKSHARER_LEASE_PARENT,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (parent<0 || !safe_directory(parent,0022)) { if (parent>=0) close(parent); return 1; }
    if (mkdirat(parent,DIRECTORY,0700) && errno!=EEXIST) { close(parent); return 1; }
    int directory=openat(parent,DIRECTORY,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    close(parent);
    if (directory<0 || !safe_directory(directory,0077)) { if (directory>=0) close(directory); return 1; }
    int file=openat(directory,FILE_NAME,O_RDWR|O_CREAT|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC,0600);
    struct stat st;
    int safe=file>=0 && !fstat(file,&st) && S_ISREG(st.st_mode) &&
             st.st_uid==NETWORKSHARER_EXPECTED_UID && st.st_nlink==1 && !(st.st_mode&0077);
    if (file>=0) close(file);
    close(directory);
    if (!safe) return 1;
    char path[PATH_MAX];
    int length=snprintf(path,sizeof(path),"%s/%s/%s",NETWORKSHARER_LEASE_PARENT,DIRECTORY,FILE_NAME);
    if (length<0 || (size_t)length>=sizeof(path)) return 1;
    puts(path);
    return 0;
}
