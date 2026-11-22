/* Test-only interposer: count file-write syscalls, never payload contents. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdatomic.h>
#include <pthread.h>

static void report(void);
static void *sample_thread(void *unused) {
    (void)unused;
    for (;;) { report(); usleep(1000000); }
    return NULL;
}
__attribute__((constructor)) static void start_sampler(void) {
    pthread_t thread;
    if (!pthread_create(&thread,NULL,sample_thread,NULL)) pthread_detach(thread);
}

static _Atomic long opens,writes,writevs,pwrites,fsyncs,renames,unlinks,mkdirs,rmdirs;
static _Atomic long file_writes,file_bytes;
static int (*real_fcntl)(int,int,...);
static int fd_is_file(int fd) {
    if (!real_fcntl) real_fcntl=dlsym(RTLD_NEXT,"fcntl");
    if (!real_fcntl) return 0;
    return real_fcntl(fd,F_GETFL,0)>=0 && lseek(fd,0,SEEK_CUR)>=0;
}
static _Atomic long bytes;
static int (*real_open)(const char *,int,...);
static int (*real_openat)(int,const char *,int,...);
static ssize_t (*real_write)(int,const void *,size_t);
static ssize_t (*real_writev)(int,const struct iovec *,int);
static ssize_t (*real_pwrite)(int,const void *,size_t,off_t);
static int (*real_fsync)(int),(*real_rename)(const char *,const char *);
static int (*real_unlink)(const char *),(*real_mkdir)(const char *,mode_t),(*real_rmdir)(const char *);
static void init(void) {
    real_open=dlsym(RTLD_NEXT,"open");real_openat=dlsym(RTLD_NEXT,"openat");
    real_write=dlsym(RTLD_NEXT,"write");real_writev=dlsym(RTLD_NEXT,"writev");
    real_pwrite=dlsym(RTLD_NEXT,"pwrite");real_fsync=dlsym(RTLD_NEXT,"fsync");
    real_rename=dlsym(RTLD_NEXT,"rename");real_unlink=dlsym(RTLD_NEXT,"unlink");
    real_mkdir=dlsym(RTLD_NEXT,"mkdir");real_rmdir=dlsym(RTLD_NEXT,"rmdir");
}
__attribute__((destructor)) static void report(void) {
    char buffer[256];int n=snprintf(buffer,sizeof(buffer),
        "AUDIT_IO opens=%ld writes=%ld writevs=%ld pwrites=%ld bytes=%lld fsyncs=%ld renames=%ld unlinks=%ld mkdirs=%ld rmdirs=%ld file_writes=%ld file_bytes=%lld\n",
        opens,writes,writevs,pwrites,(long long)bytes,fsyncs,renames,unlinks,mkdirs,rmdirs,file_writes,(long long)file_bytes);
    (void)write(1,buffer,(size_t)n);
}
int open(const char *path,int flags,...) {
    if (!real_open) init();
    mode_t mode=0; if (flags&O_CREAT) { va_list args;va_start(args,flags);mode=va_arg(args,int);va_end(args); }
    if ((flags&(O_WRONLY|O_RDWR)) || (flags&O_TRUNC)) opens++;
    return real_open(path,flags,mode);
}
int openat(int dir,const char *path,int flags,...) {
    if (!real_openat) init();
    mode_t mode=0; if (flags&O_CREAT) { va_list args;va_start(args,flags);mode=va_arg(args,int);va_end(args); }
    if ((flags&(O_WRONLY|O_RDWR)) || (flags&O_TRUNC)) opens++;
    return real_openat(dir,path,flags,mode);
}
ssize_t write(int fd,const void *buffer,size_t size) {
    if (!real_write) init();ssize_t result=real_write(fd,buffer,size);
    if(result>0) { writes++;bytes+=result; if (fd_is_file(fd)) { file_writes++;file_bytes+=result; } } return result;
}
ssize_t writev(int fd,const struct iovec *iov,int count) {
    if (!real_writev) init();ssize_t result=real_writev(fd,iov,count);
    if(result>0) { writevs++;bytes+=result; if (fd_is_file(fd)) { file_writes++;file_bytes+=result; } } return result;
}
ssize_t pwrite(int fd,const void *buffer,size_t size,off_t offset) {
    if (!real_pwrite) init();ssize_t result=real_pwrite(fd,buffer,size,offset);
    if(result>0) { pwrites++;bytes+=result; if (fd_is_file(fd)) { file_writes++;file_bytes+=result; } } return result;
}
int fsync(int fd) { if(!real_fsync)init();int r=real_fsync(fd);if(!r)fsyncs++;return r; }
int rename(const char *from,const char *to) { if(!real_rename)init();int r=real_rename(from,to);if(!r)renames++;return r; }
int unlink(const char *path) { if(!real_unlink)init();int r=real_unlink(path);if(!r)unlinks++;return r; }
int mkdir(const char *path,mode_t mode) { if(!real_mkdir)init();int r=real_mkdir(path,mode);if(!r)mkdirs++;return r; }
int rmdir(const char *path) { if(!real_rmdir)init();int r=real_rmdir(path);if(!r)rmdirs++;return r; }
