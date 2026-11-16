/* Relocate only this experimental daemon's config, log and IPC names. */
#include <CoreFoundation/CoreFoundation.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "parent_guard.h"

__attribute__((constructor)) static void hotspot_guard_daemon_parent(void) {
    if (!hotspot_start_parent_guard()) _exit(125);
}

static const char *map_path(const char *path, char out[PATH_MAX]) {
    const char *dir=getenv("NAPTD_CONFIG_DIR");
    const char *prefix="/Library/Preferences/Parallels";
    if (!path || !dir || dir[0]!='/') return path;
    size_t n=strlen(prefix);
    if (!strncmp(path,prefix,n) && (!path[n] || path[n]=='/')) {
        if (snprintf(out,PATH_MAX,"%s%s",dir,path+n)>=PATH_MAX) return path;
        return out;
    }
    if (!strcmp(path,"/Library/Logs/parallels.log")) {
        return "/dev/null";
    }
    return path;
}
static int mapped_open(const char *path, int flags, ...) {
    mode_t mode=0; char out[PATH_MAX];
    if (flags&O_CREAT) { va_list ap; va_start(ap,flags); mode=(mode_t)va_arg(ap,int); va_end(ap); }
    return (int)syscall(SYS_open,map_path(path,out),flags,mode);
}
static FILE *mapped_fopen(const char *path,const char *mode) {
    if (!mode || !mode[0]) return NULL;
    int flags;
    if (mode[0]=='r') flags=O_RDONLY;
    else if (mode[0]=='w') flags=O_WRONLY|O_CREAT|O_TRUNC;
    else if (mode[0]=='a') flags=O_WRONLY|O_CREAT|O_APPEND;
    else return NULL;
    if (strchr(mode,'+')) flags=(flags&~O_ACCMODE)|O_RDWR;
    if (strchr(mode,'x')) flags|=O_EXCL;
    if (strchr(mode,'e')) flags|=O_CLOEXEC;
    char out[PATH_MAX]; int fd=(int)syscall(SYS_open,map_path(path,out),flags,0666);
    if (fd<0) return NULL;
    char normalized[3]={mode[0],0,0}; if (strchr(mode,'+')) normalized[1]='+';
    FILE *file=fdopen(fd,normalized); if (!file) close(fd); return file;
}
static int mapped_stat(const char *path,struct stat *st) {
    char out[PATH_MAX]; return (int)syscall(SYS_stat64,map_path(path,out),st);
}
static int mapped_lstat(const char *path,struct stat *st) {
    char out[PATH_MAX]; return (int)syscall(SYS_lstat64,map_path(path,out),st);
}
static int mapped_access(const char *path,int mode) {
    char out[PATH_MAX]; return (int)syscall(SYS_access,map_path(path,out),mode);
}

/* Optional proxy mode: direct IP egress is denied by the daemon's sandbox.
 * TCP connects go to a local relay with an authenticated destination header;
 * UDP DNS goes to its local DNS-over-TCP relay. Other UDP stays blocked. */
#define RELAY_TOKEN_LEN 32
#define DNS_HEADER_LEN (4+RELAY_TOKEN_LEN)
#define DNS_PAYLOAD_MAX 4096
#define UDP_HEADER_LEN (4+RELAY_TOKEN_LEN+4+2)
#define UDP_PAYLOAD_MAX 60000
#define DNS_FD_MAX 8192
static pthread_mutex_t dns_lock=PTHREAD_MUTEX_INITIALIZER;
static struct sockaddr_in dns_original[DNS_FD_MAX];
static unsigned char dns_valid[DNS_FD_MAX];
static int relay_config(uint16_t *tcp,uint16_t *dns,const char **token) {
    const char *t=getenv("NAPTD_RELAY_TCP"), *d=getenv("NAPTD_RELAY_DNS"), *s=getenv("NAPTD_RELAY_TOKEN");
    if (!t || !d || !s || strlen(s)!=RELAY_TOKEN_LEN) return 0;
    char *te=NULL,*de=NULL; unsigned long tv=strtoul(t,&te,10),dv=strtoul(d,&de,10);
    if (*te || *de || tv<1 || tv>65535 || dv<1 || dv>65535) return 0;
    *tcp=(uint16_t)tv; *dns=(uint16_t)dv; *token=s; return 1;
}
static int socket_type(int fd) {
    int type=0; socklen_t len=sizeof(type);
    return getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&len)==0 ? type : 0;
}
static struct sockaddr_in relay_address(uint16_t port) {
    struct sockaddr_in a={.sin_len=sizeof(a),.sin_family=AF_INET,.sin_port=htons(port),.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    return a;
}
static void remember_dns(int fd,const struct sockaddr_in *addr) {
    if (fd<0 || fd>=DNS_FD_MAX) return;
    pthread_mutex_lock(&dns_lock); dns_original[fd]=*addr; dns_valid[fd]=1; pthread_mutex_unlock(&dns_lock);
}
static int is_dns_fd(int fd) {
    if (fd<0 || fd>=DNS_FD_MAX) return 0;
    pthread_mutex_lock(&dns_lock); int result=dns_valid[fd]; pthread_mutex_unlock(&dns_lock); return result;
}
static int get_udp_destination(int fd,struct sockaddr_in *address) {
    if (fd<0 || fd>=DNS_FD_MAX) return 0;
    pthread_mutex_lock(&dns_lock); int valid=dns_valid[fd]; if (valid) *address=dns_original[fd]; pthread_mutex_unlock(&dns_lock); return valid;
}
static int udp_header(uint8_t header[UDP_HEADER_LEN],const char *token,const struct sockaddr_in *destination) {
    int dns=ntohs(destination->sin_port)==53;
    const char *mode=getenv("NAPTD_RELAY_MODE");
    if (!dns && (!mode || strcmp(mode,"direct"))) { errno=EACCES; return -1; }
    memcpy(header,dns ? "DNS1" : "UDP1",4); memcpy(header+4,token,RELAY_TOKEN_LEN);
    if (dns) return DNS_HEADER_LEN;
    memcpy(header+4+RELAY_TOKEN_LEN,&destination->sin_addr.s_addr,4);
    memcpy(header+4+RELAY_TOKEN_LEN+4,&destination->sin_port,2);
    return UDP_HEADER_LEN;
}
static int unwrap_udp(int fd,const uint8_t *packet,ssize_t n,const char *token,struct sockaddr_in *source) {
    if (n<DNS_HEADER_LEN || memcmp(packet+4,token,RELAY_TOKEN_LEN)) { errno=EPROTO; return -1; }
    if (!memcmp(packet,"DNS1",4)) {
        if (!get_udp_destination(fd,source)) { errno=EPROTO; return -1; }
        return DNS_HEADER_LEN;
    }
    if (!memcmp(packet,"UDP1",4) && n>=UDP_HEADER_LEN) {
        const char *mode=getenv("NAPTD_RELAY_MODE"); if (!mode || strcmp(mode,"direct")) { errno=EPROTO; return -1; }
        *source=relay_address(0); memcpy(&source->sin_addr.s_addr,packet+4+RELAY_TOKEN_LEN,4); memcpy(&source->sin_port,packet+4+RELAY_TOKEN_LEN+4,2);
        return UDP_HEADER_LEN;
    }
    errno=EPROTO; return -1;
}
static int mapped_connect(int fd,const struct sockaddr *address,socklen_t length) {
    uint16_t tcp,dns; const char *token;
    if (!relay_config(&tcp,&dns,&token) || !address || length<sizeof(struct sockaddr_in) || address->sa_family!=AF_INET)
        return (int)syscall(SYS_connect,fd,address,length);
    const struct sockaddr_in *destination=(const struct sockaddr_in *)address;
    int type=socket_type(fd);
    if (type==SOCK_DGRAM) {
        uint8_t header[UDP_HEADER_LEN]; if (udp_header(header,token,destination)<0) return -1;
        struct sockaddr_in target=relay_address(dns); remember_dns(fd,destination);
        return (int)syscall(SYS_connect,fd,&target,sizeof(target));
    }
    if (type!=SOCK_STREAM) return (int)syscall(SYS_connect,fd,address,length);
    if (destination->sin_addr.s_addr==htonl(INADDR_LOOPBACK) && (ntohs(destination->sin_port)==tcp || ntohs(destination->sin_port)==dns))
        return (int)syscall(SYS_connect,fd,address,length);
    int flags=fcntl(fd,F_GETFL,0); if (flags<0) return -1;
    if (fcntl(fd,F_SETFL,flags|O_NONBLOCK)<0) return -1;
    struct sockaddr_in target=relay_address(tcp); int result=(int)syscall(SYS_connect,fd,&target,sizeof(target));
    if (result<0 && errno!=EINPROGRESS && errno!=EWOULDBLOCK) { int e=errno; (void)fcntl(fd,F_SETFL,flags); errno=e; return -1; }
    struct pollfd p={.fd=fd,.events=POLLOUT};
    if (result<0) {
        int ready; do { ready=poll(&p,1,1500); } while (ready<0 && errno==EINTR);
        if (ready<=0) { int e=ready==0 ? ETIMEDOUT : errno; (void)fcntl(fd,F_SETFL,flags); errno=e; return -1; }
        int error=0; socklen_t n=sizeof(error);
        if (getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&n) || error) { int e=error ? error : errno; (void)fcntl(fd,F_SETFL,flags); errno=e; return -1; }
    }
    uint8_t header[4+RELAY_TOKEN_LEN+4+2];
    memcpy(header,"NAT1",4); memcpy(header+4,token,RELAY_TOKEN_LEN);
    memcpy(header+4+RELAY_TOKEN_LEN,&destination->sin_addr.s_addr,4);
    memcpy(header+4+RELAY_TOKEN_LEN+4,&destination->sin_port,2);
    int one=1; (void)setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one));
    size_t offset=0;
    while (offset<sizeof(header)) {
        ssize_t n=send(fd,header+offset,sizeof(header)-offset,0);
        if (n>0) { offset+=(size_t)n; continue; }
        if (n<0 && errno==EINTR) continue;
        if (n<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) {
            int ready; do { ready=poll(&p,1,1500); } while (ready<0 && errno==EINTR);
            if (ready>0) continue;
            if (ready==0) errno=ETIMEDOUT;
        }
        int e=n<0 ? errno : EIO; (void)fcntl(fd,F_SETFL,flags); errno=e; return -1;
    }
    (void)fcntl(fd,F_SETFL,flags); return 0;
}
static ssize_t mapped_sendmsg(int fd,const struct msghdr *message,int flags) {
    if (fd<0) { errno=EBADF; return -1; }
    uint16_t tcp,dns; const char *token;
    if (relay_config(&tcp,&dns,&token) && message && socket_type(fd)==SOCK_DGRAM) {
        int redirect=0; struct sockaddr_in destination={0},target=relay_address(dns); struct msghdr copy=*message;
        if (message->msg_name && message->msg_namelen>=sizeof(struct sockaddr_in)) {
            const struct sockaddr_in *original=(const struct sockaddr_in *)message->msg_name;
            if (original->sin_family==AF_INET) {
                destination=*original; remember_dns(fd,original); copy.msg_name=&target; copy.msg_namelen=sizeof(target); redirect=1;
            }
        } else if (!message->msg_name && get_udp_destination(fd,&destination)) redirect=1;
        if (redirect) {
            if (message->msg_iovlen<0 || message->msg_iovlen>32) { errno=EMSGSIZE; return -1; }
            uint8_t header[UDP_HEADER_LEN]; int header_len=udp_header(header,token,&destination); if (header_len<0) return -1;
            struct iovec iov[33]; iov[0].iov_base=header; iov[0].iov_len=(size_t)header_len;
            if (message->msg_iovlen) memcpy(iov+1,message->msg_iov,(size_t)message->msg_iovlen*sizeof(struct iovec));
            copy.msg_iov=iov; copy.msg_iovlen=message->msg_iovlen+1; copy.msg_control=NULL; copy.msg_controllen=0;
            ssize_t n=sendmsg(fd,&copy,flags); return n<0 ? n : (n>=header_len ? n-header_len : -1);
        }
    }
    return sendmsg(fd,message,flags);
}
static ssize_t mapped_recvmsg(int fd,struct msghdr *message,int flags) {
    if (fd<0) { errno=EBADF; return -1; }
    uint16_t tcp,dns; const char *token;
    if (relay_config(&tcp,&dns,&token) && message && is_dns_fd(fd) && socket_type(fd)==SOCK_DGRAM) {
        if (message->msg_iovlen<0 || message->msg_iovlen>32) { errno=EMSGSIZE; return -1; }
        uint8_t packet[UDP_HEADER_LEN+UDP_PAYLOAD_MAX]; struct iovec io={.iov_base=packet,.iov_len=sizeof(packet)};
        struct msghdr copy=*message; copy.msg_iov=&io; copy.msg_iovlen=1;
        ssize_t n=recvmsg(fd,&copy,flags); if (n<0) return n;
        if ((size_t)n>sizeof(packet)) { n=(ssize_t)sizeof(packet); copy.msg_flags|=MSG_TRUNC; }
        struct sockaddr_in source={0}; int header_len=unwrap_udp(fd,packet,n,token,&source); if (header_len<0) return -1;
        size_t remaining=(size_t)n-(size_t)header_len, copied=0;
        for (int i=0;i<message->msg_iovlen && remaining;i++) {
            size_t count=message->msg_iov[i].iov_len<remaining ? message->msg_iov[i].iov_len : remaining;
            memcpy(message->msg_iov[i].iov_base,packet+header_len+copied,count); copied+=count; remaining-=count;
        }
        message->msg_flags=copy.msg_flags | (remaining ? MSG_TRUNC : 0); message->msg_controllen=copy.msg_controllen; message->msg_namelen=copy.msg_namelen;
        if (message->msg_name && message->msg_namelen>=sizeof(struct sockaddr_in)) {
            struct sockaddr_in *actual=(struct sockaddr_in *)message->msg_name;
            if (actual->sin_family==AF_INET && actual->sin_addr.s_addr==htonl(INADDR_LOOPBACK) && ntohs(actual->sin_port)==dns) {
                *actual=source;
            }
        }
        return (ssize_t)copied;
    }
    return recvmsg(fd,message,flags);
}
static ssize_t mapped_send(int fd,const void *data,size_t length,int flags) {
    if (fd<0) { errno=EBADF; return -1; }
    uint16_t tcp,dns; const char *token;
    if (relay_config(&tcp,&dns,&token) && is_dns_fd(fd) && socket_type(fd)==SOCK_DGRAM) {
        struct sockaddr_in destination; if (!get_udp_destination(fd,&destination)) { errno=EACCES; return -1; }
        uint8_t header[UDP_HEADER_LEN]; int header_len=udp_header(header,token,&destination); if (header_len<0) return -1;
        struct iovec iov[2]={{.iov_base=header,.iov_len=(size_t)header_len},{.iov_base=(void *)data,.iov_len=length}};
        struct msghdr message={.msg_iov=iov,.msg_iovlen=2};
        ssize_t n=sendmsg(fd,&message,flags); return n<0 ? n : (n>=header_len ? n-header_len : -1);
    }
    return send(fd,data,length,flags);
}
static ssize_t mapped_recv(int fd,void *data,size_t length,int flags) {
    if (fd<0) { errno=EBADF; return -1; }
    uint16_t tcp,dns; const char *token;
    if (relay_config(&tcp,&dns,&token) && is_dns_fd(fd) && socket_type(fd)==SOCK_DGRAM) {
        uint8_t packet[UDP_HEADER_LEN+UDP_PAYLOAD_MAX]; ssize_t n=recv(fd,packet,sizeof(packet),flags);
        if (n<0) return n;
        if ((size_t)n>sizeof(packet)) n=(ssize_t)sizeof(packet);
        struct sockaddr_in source; int header_len=unwrap_udp(fd,packet,n,token,&source); if (header_len<0) return -1;
        size_t count=(size_t)n-(size_t)header_len; if (count>length) count=length; memcpy(data,packet+header_len,count); return (ssize_t)count;
    }
    return recv(fd,data,length,flags);
}
static ssize_t mapped_sendto(int fd,const void *data,size_t length,int flags,const struct sockaddr *address,socklen_t address_len) {
    if (fd<0) { errno=EBADF; return -1; }
    uint16_t tcp,dns; const char *token;
    if (relay_config(&tcp,&dns,&token) && socket_type(fd)==SOCK_DGRAM) {
        struct iovec io={.iov_base=(void *)data,.iov_len=length};
        struct msghdr message={.msg_name=(void *)address,.msg_namelen=address_len,.msg_iov=&io,.msg_iovlen=1};
        return mapped_sendmsg(fd,&message,flags);
    }
    return sendto(fd,data,length,flags,address,address_len);
}
static ssize_t mapped_recvfrom(int fd,void *data,size_t length,int flags,struct sockaddr *address,socklen_t *address_len) {
    if (fd<0) { errno=EBADF; return -1; }
    uint16_t tcp,dns; const char *token;
    if (relay_config(&tcp,&dns,&token) && is_dns_fd(fd) && socket_type(fd)==SOCK_DGRAM) {
        struct iovec io={.iov_base=data,.iov_len=length};
        struct msghdr message={.msg_name=address,.msg_namelen=address_len ? *address_len : 0,.msg_iov=&io,.msg_iovlen=1};
        ssize_t n=mapped_recvmsg(fd,&message,flags); if (address_len) *address_len=message.msg_namelen; return n;
    }
    return recvfrom(fd,data,length,flags,address,address_len);
}
static int mapped_close(int fd) {
    if (fd>=0 && fd<DNS_FD_MAX) { pthread_mutex_lock(&dns_lock); dns_valid[fd]=0; pthread_mutex_unlock(&dns_lock); }
    return close(fd);
}
static CFStringRef replacement_name(CFStringRef name) {
    const char *env=NULL;
    if (name && CFEqual(name,CFSTR("com.parallels.disp.net.ipc"))) env=getenv("NAPTD_DISPATCHER_PORT");
    else if (name && CFEqual(name,CFSTR("com.parallels.naptd.ipc"))) env=getenv("NAPTD_SERVICE_PORT");
    return env && *env ? CFStringCreateWithCString(kCFAllocatorDefault,env,kCFStringEncodingUTF8) : NULL;
}
static CFMessagePortRef mapped_remote(CFAllocatorRef allocator,CFStringRef name) __attribute__((cf_returns_retained));
static CFMessagePortRef mapped_remote(CFAllocatorRef allocator,CFStringRef name) {
    CFStringRef replacement=replacement_name(name);
    CFMessagePortRef result=CFMessagePortCreateRemote(allocator,replacement ? replacement : name);
    if (replacement) CFRelease(replacement);
    return result;
}
static CFMessagePortRef mapped_local(CFAllocatorRef allocator,CFStringRef name,CFMessagePortCallBack callout,CFMessagePortContext *context,Boolean *shouldFreeInfo) __attribute__((cf_returns_retained));
static CFMessagePortRef mapped_local(CFAllocatorRef allocator,CFStringRef name,CFMessagePortCallBack callout,CFMessagePortContext *context,Boolean *shouldFreeInfo) {
    CFStringRef replacement=replacement_name(name);
    CFMessagePortRef result=CFMessagePortCreateLocal(allocator,replacement ? replacement : name,callout,context,shouldFreeInfo);
    if (replacement) CFRelease(replacement);
    return result;
}
#ifndef NETWORKSHARER_TEST_NO_INTERPOSE
#define INTERPOSE(newfunc,oldfunc) \
  __attribute__((used)) static struct { const void *replacement; const void *original; } \
  interpose_##oldfunc __attribute__((section("__DATA,__interpose"))) = \
  { (const void *)(uintptr_t)&newfunc,(const void *)(uintptr_t)&oldfunc }
INTERPOSE(mapped_open,open);
INTERPOSE(mapped_fopen,fopen);
INTERPOSE(mapped_stat,stat);
INTERPOSE(mapped_lstat,lstat);
INTERPOSE(mapped_access,access);
INTERPOSE(mapped_connect,connect);
INTERPOSE(mapped_sendmsg,sendmsg);
INTERPOSE(mapped_recvmsg,recvmsg);
INTERPOSE(mapped_send,send);
INTERPOSE(mapped_recv,recv);
INTERPOSE(mapped_sendto,sendto);
INTERPOSE(mapped_recvfrom,recvfrom);
INTERPOSE(mapped_close,close);
INTERPOSE(mapped_remote,CFMessagePortCreateRemote);
INTERPOSE(mapped_local,CFMessagePortCreateLocal);
#endif
