/* Durable private lease state for the standalone network core. */
#include "standalone_leases.h"
#include <CommonCrypto/CommonDigest.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define STATE_FILE "dhcp-leases-v2.bin"
#define LOCK_FILE "dhcp-leases-v2.lock"
#define PAYLOAD_SIZE (1+2+243*12)
#define HEADER_SIZE 16
#define DIGEST_SIZE CC_SHA256_DIGEST_LENGTH
struct lease_store {
    int dir,lock;
    /* Compare only the lease table: ip_id in the snapshot changes on every
     * outgoing packet and must not defeat duplicate suppression. */
    unsigned char last[PAYLOAD_SIZE];
    int has_last;
};
/* Snapshot layout: end marker (1), ip_id (2), then 243 lease records (12). */
#define LEASE_TABLE_OFFSET (1+2)
#define LEASE_TABLE_SIZE (243*12)
struct buffer { unsigned char bytes[PAYLOAD_SIZE]; size_t offset; int failed; };
static slirp_ssize_t collect(const void *data,size_t len,void *opaque) {
    struct buffer *b=opaque;
    if (len>sizeof(b->bytes)-b->offset) { b->failed=1; return -1; }
    memcpy(b->bytes+b->offset,data,len); b->offset+=len; return (slirp_ssize_t)len;
}
static slirp_ssize_t supply(void *data,size_t len,void *opaque) {
    struct buffer *b=opaque;
    if (len>sizeof(b->bytes)-b->offset) { b->failed=1; return -1; }
    memcpy(data,b->bytes+b->offset,len); b->offset+=len; return (slirp_ssize_t)len;
}
static int regular_private(int fd) {
    struct stat st;
    return !fstat(fd,&st) && S_ISREG(st.st_mode) && st.st_uid==geteuid() &&
           st.st_nlink==1 && !(st.st_mode&0077);
}
static int full_read(int fd,void *data,size_t len) {
    size_t off=0;
    while (off<len) { ssize_t n=read(fd,(char *)data+off,len-off); if (n<0 && errno==EINTR) continue; if (n<=0) return 0; off+=(size_t)n; }
    return 1;
}
static int full_write(int fd,const void *data,size_t len) {
    size_t off=0;
    while (off<len) { ssize_t n=write(fd,(const char *)data+off,len-off); if (n<0 && errno==EINTR) continue; if (n<=0) return 0; off+=(size_t)n; }
    return 1;
}
static int remove_abandoned_temps(int dir) {
    int scan=dup(dir); if (scan<0) return 0;
    DIR *entries=fdopendir(scan); if (!entries) { close(scan); return 0; }
    int ok=1,changed=0; struct dirent *entry;
    while ((entry=readdir(entries))) {
        const char *name=entry->d_name;
        if (strlen(name)!=24 || strncmp(name,".lease-",7) || name[15]!='-' ||
            strspn(name+7,"0123456789abcdef")!=8 || strspn(name+16,"0123456789abcdef")!=8) continue;
        struct stat st;
        if (fstatat(dir,name,&st,AT_SYMLINK_NOFOLLOW) || !S_ISREG(st.st_mode) ||
            st.st_uid!=geteuid() || st.st_nlink!=1 || unlinkat(dir,name,0)) { ok=0; break; }
        changed=1;
    }
    closedir(entries);
    return ok && (!changed || fsync(dir)==0);
}
static int load_state(int dir,Slirp *slirp) {
    int fd=openat(dir,STATE_FILE,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
    if (fd<0) return errno==ENOENT;
    struct stat st; unsigned char file[HEADER_SIZE+PAYLOAD_SIZE+DIGEST_SIZE],digest[DIGEST_SIZE];
    int ok=regular_private(fd) && !fstat(fd,&st) && st.st_size==(off_t)sizeof(file) && full_read(fd,file,sizeof(file));
    close(fd);
    if (!ok || memcmp(file,"NSLEASE1",8)) return 0;
    uint32_t size,version; memcpy(&size,file+8,4); memcpy(&version,file+12,4);
    size=ntohl(size); version=ntohl(version);
    if (size!=PAYLOAD_SIZE || version!=(uint32_t)slirp_state_version() || file[HEADER_SIZE]!=0) return 0;
    CC_SHA256(file,HEADER_SIZE+PAYLOAD_SIZE,digest);
    if (memcmp(digest,file+HEADER_SIZE+PAYLOAD_SIZE,DIGEST_SIZE)) return 0;
    struct buffer b={0}; memcpy(b.bytes,file+HEADER_SIZE,PAYLOAD_SIZE);
    return slirp_state_load(slirp,(int)version,supply,&b)==0 && !b.failed && b.offset==PAYLOAD_SIZE;
}
struct lease_store *lease_open(const char *directory,Slirp *slirp) {
    if (!directory || !slirp) return NULL;
    int dir=open(directory,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (dir<0) return NULL;
    struct stat st;
    if (fstat(dir,&st) || !S_ISDIR(st.st_mode) || st.st_uid!=geteuid() || (st.st_mode&0077)) { close(dir); errno=EPERM; return NULL; }
    int lock=openat(dir,LOCK_FILE,O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK,0600);
    if (lock<0 || !regular_private(lock) || flock(lock,LOCK_EX|LOCK_NB)) { if (lock>=0) close(lock); close(dir); return NULL; }
    if (!remove_abandoned_temps(dir) || !load_state(dir,slirp)) { close(lock); close(dir); errno=EINVAL; return NULL; }
    struct lease_store *s=malloc(sizeof(*s));
    if (!s) { close(lock); close(dir); return NULL; }
    *s=(struct lease_store){.dir=dir,.lock=lock}; return s;
}
int lease_commit(struct lease_store *s,Slirp *slirp) {
    if (!s || !slirp) { errno=EINVAL; return 0; }
    struct buffer b={0};
    if (slirp_state_save(slirp,collect,&b) || b.failed || b.offset!=PAYLOAD_SIZE || b.bytes[0]!=0) { errno=EINVAL; return 0; }
    struct timespec now={0}; (void)clock_gettime(CLOCK_MONOTONIC,&now);
    /* The persisted file already holds this exact lease table: no fsync needed. */
    if (s->has_last && !memcmp(b.bytes+LEASE_TABLE_OFFSET,s->last+LEASE_TABLE_OFFSET,LEASE_TABLE_SIZE)) return 1;
    unsigned char file[HEADER_SIZE+PAYLOAD_SIZE+DIGEST_SIZE]; memcpy(file,"NSLEASE1",8);
    uint32_t value=htonl(PAYLOAD_SIZE); memcpy(file+8,&value,4);
    value=htonl((uint32_t)slirp_state_version()); memcpy(file+12,&value,4);
    memcpy(file+HEADER_SIZE,b.bytes,PAYLOAD_SIZE);
    CC_SHA256(file,HEADER_SIZE+PAYLOAD_SIZE,file+HEADER_SIZE+PAYLOAD_SIZE);
    char name[64]; int fd=-1;
    for (int i=0;i<10 && fd<0;i++) {
        snprintf(name,sizeof(name),".lease-%08x-%08x",arc4random(),arc4random());
        fd=openat(s->dir,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
        if (fd<0 && errno!=EEXIST) return 0;
    }
    if (fd<0) return 0;
    int ok=full_write(fd,file,sizeof(file)) && fsync(fd)==0;
    if (close(fd)) ok=0;
    if (ok && renameat(s->dir,name,s->dir,STATE_FILE)) ok=0;
    if (ok && fsync(s->dir)) ok=0;
    if (!ok) { int saved=errno; unlinkat(s->dir,name,0); errno=saved; return 0; }
    memcpy(s->last,b.bytes,PAYLOAD_SIZE); s->has_last=1;
    return 1;
}
void lease_close(struct lease_store *s) { if (s) { close(s->lock); close(s->dir); free(s); } }
