/* Local-only relay: outbound sockets use either the selected interface or SOCKS5. */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include "parent_guard.h"

#define TOKEN_LEN 32
#define HEADER_LEN (4+TOKEN_LEN+4+2)
#define DNS_HEADER_LEN (4+TOKEN_LEN)
#define BUF_SIZE 32768
#define DNS_MAX 4096
#define TCP_WORKER_MAX 192
#define DNS_WORKER_MAX 32
#define UDP_FLOW_MAX 256
#define UDP_HEADER_LEN (4+TOKEN_LEN+4+2)
#define UDP_PAYLOAD_MAX 60000
static uint16_t proxy_port;
static char secret[TOKEN_LEN+1];
static int direct_mode=0;
static char upstream_name[IFNAMSIZ];
static unsigned int upstream_index=0;
static struct in_addr upstream_address;
static unsigned long upstream_generation=0;
static time_t upstream_checked=0;
static int upstream_valid=0,upstream_initialized=0;
static pthread_mutex_t upstream_lock=PTHREAD_MUTEX_INITIALIZER;
static struct in_addr resolver_addresses[2];
static int resolver_count=0;
static uint8_t username[255],password[255];
static size_t username_len=0,password_len=0;
static pthread_mutex_t worker_lock=PTHREAD_MUTEX_INITIALIZER;
static unsigned tcp_workers=0,dns_workers=0;
/* Optional SOCKS5 listener for devices on the same LAN (for example a phone
 * whose Wi-Fi is not authenticated). It only ever binds to the selected
 * physical Wi-Fi address, never to every interface. */
static int lan_port=0;
static int lan_auth=0;
static uint8_t lan_username[255],lan_password[255];
static size_t lan_username_len=0,lan_password_len=0;
static char lan_interface[IFNAMSIZ];
typedef struct { int fd; int control; int active; struct sockaddr_in client; uint32_t destination; uint16_t port; time_t last; uint64_t order; unsigned long generation; } udp_flow;
static udp_flow flows[UDP_FLOW_MAX];
static uint64_t flow_order=0;

static int reserve_worker(int dns) {
    pthread_mutex_lock(&worker_lock);
    unsigned *workers=dns ? &dns_workers : &tcp_workers;
    int allowed=*workers<(dns ? DNS_WORKER_MAX : TCP_WORKER_MAX);
    if (allowed) (*workers)++;
    pthread_mutex_unlock(&worker_lock); return allowed;
}
static void release_worker(int dns) {
    pthread_mutex_lock(&worker_lock);
    unsigned *workers=dns ? &dns_workers : &tcp_workers;
    (*workers)--;
    pthread_mutex_unlock(&worker_lock);
}
/* Refresh the physical interface, never substituting the system default route. */
static int upstream_snapshot(unsigned int *index,struct in_addr *address,unsigned long *generation,int force) {
    struct timespec now={0}; (void)clock_gettime(CLOCK_MONOTONIC,&now);
    pthread_mutex_lock(&upstream_lock);
    if (force || !upstream_initialized || now.tv_sec-upstream_checked>=2) {
        unsigned int found_index=if_nametoindex(upstream_name); struct in_addr found_address={0};
        struct ifaddrs *list=NULL; int found=0;
        if (found_index && !getifaddrs(&list)) {
            for (struct ifaddrs *p=list;p;p=p->ifa_next) {
                if (p->ifa_addr && p->ifa_addr->sa_family==AF_INET && !strcmp(p->ifa_name,upstream_name)) {
                    found_address=((struct sockaddr_in *)p->ifa_addr)->sin_addr; found=1; break;
                }
            }
            freeifaddrs(list);
        }
        if (found!=upstream_valid || (found && (found_index!=upstream_index || found_address.s_addr!=upstream_address.s_addr)))
            upstream_generation++;
        upstream_index=found_index; upstream_address=found_address; upstream_valid=found;
        upstream_checked=now.tv_sec; upstream_initialized=1;
    }
    int ok=upstream_valid;
    if (ok) { if (index) *index=upstream_index; if (address) *address=upstream_address; if (generation) *generation=upstream_generation; }
    pthread_mutex_unlock(&upstream_lock);
    return ok;
}
static int read_all(int fd,void *buf,size_t n) {
    uint8_t *p=buf;
    while (n) { ssize_t r=recv(fd,p,n,0); if (r<=0) { if (r<0 && errno==EINTR) continue; return 0; } p+=r; n-=(size_t)r; }
    return 1;
}
/* Handshake bytes must arrive within one absolute deadline; per-recv timeouts
 * alone let a slow client hold a slot indefinitely. */
static int read_handshake(int fd,void *buf,size_t n,const struct timespec *deadline) {
    uint8_t *p=buf;
    while (n) {
        struct timespec now={0}; (void)clock_gettime(CLOCK_MONOTONIC,&now);
        long remaining=(deadline->tv_sec-now.tv_sec)*1000+(deadline->tv_nsec-now.tv_nsec)/1000000;
        if (remaining<=0) return 0;
        struct timeval timeout={.tv_sec=remaining/1000,.tv_usec=(remaining%1000)*1000};
        (void)setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
        ssize_t r=recv(fd,p,n,0);
        if (r>0) { p+=r; n-=(size_t)r; continue; }
        if (r<0 && errno==EINTR) continue;
        return 0;
    }
    return 1;
}
static int write_all(int fd,const void *buf,size_t n) {
    const uint8_t *p=buf;
    while (n) { ssize_t r=send(fd,p,n,0); if (r<=0) { if (r<0 && errno==EINTR) continue; return 0; } p+=r; n-=(size_t)r; }
    return 1;
}
static void clear_bytes(void *buffer,size_t length) {
    volatile unsigned char *p=buffer;
    while (length--) *p++=0;
}
static int connect_timed(int fd, const struct sockaddr_in *address, int seconds) {
    int flags=fcntl(fd,F_GETFL,0);
    if (flags<0 || fcntl(fd,F_SETFL,flags|O_NONBLOCK)) return 0;
    int result=connect(fd,(const struct sockaddr *)address,sizeof(*address));
    if (result && errno!=EINPROGRESS && errno!=EWOULDBLOCK) return 0;
    if (result) {
        struct pollfd wait={.fd=fd,.events=POLLOUT};
        do { result=poll(&wait,1,seconds*1000); } while (result<0 && errno==EINTR);
        int error=0; socklen_t length=sizeof(error);
        if (result<=0 || getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&length) || error) return 0;
    }
    return fcntl(fd,F_SETFL,flags)==0;
}
static int proxy_socket(int seconds) {
    int fd=socket(AF_INET,SOCK_STREAM,0); if (fd<0) return -1;
    struct timeval timeout={.tv_sec=seconds,.tv_usec=0};
    (void)setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    (void)setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
    struct sockaddr_in addr={.sin_len=sizeof(addr),.sin_family=AF_INET,.sin_port=htons(proxy_port),.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    if (!connect_timed(fd,&addr,seconds)) { close(fd); return -1; }
    uint8_t hello[]={5,1,0}; uint8_t reply[2];
    if (username_len) hello[2]=2;
    if (!write_all(fd,hello,sizeof(hello)) || !read_all(fd,reply,sizeof(reply)) || reply[0]!=5 || reply[1]!=hello[2]) { close(fd); return -1; }
    if (username_len) {
        uint8_t auth[3+255+255]; size_t n=0;
        auth[n++]=1; auth[n++]=(uint8_t)username_len; memcpy(auth+n,username,username_len); n+=username_len;
        auth[n++]=(uint8_t)password_len; memcpy(auth+n,password,password_len); n+=password_len;
        int ok=write_all(fd,auth,n) && read_all(fd,reply,sizeof(reply)) && reply[0]==1 && reply[1]==0;
        clear_bytes(auth,sizeof(auth));
        if (!ok) { close(fd); return -1; }
    }
    return fd;
}
#include "upstream_udp.h"

static int direct_socket(int kind,uint32_t address,uint16_t port,int seconds,unsigned long *generation) {
    for (int attempt=0;attempt<2;attempt++) {
        unsigned int index; struct in_addr source; unsigned long current_generation;
        if (!upstream_snapshot(&index,&source,&current_generation,attempt)) return -1;
        int fd=socket(AF_INET,kind,0); if (fd<0) return -1;
        struct timeval timeout={.tv_sec=seconds,.tv_usec=0};
        (void)setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
        (void)setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
        struct sockaddr_in local={.sin_len=sizeof(local),.sin_family=AF_INET,.sin_port=0,.sin_addr=source};
        struct sockaddr_in remote={.sin_len=sizeof(remote),.sin_family=AF_INET,.sin_port=port,.sin_addr.s_addr=address};
        if (setsockopt(fd,IPPROTO_IP,IP_BOUND_IF,&index,sizeof(index)) || bind(fd,(struct sockaddr *)&local,sizeof(local))) {
            int saved=errno; close(fd); errno=saved;
            if (!attempt && (saved==EADDRNOTAVAIL || saved==ENXIO || saved==ENETDOWN)) continue;
            return -1;
        }
        if (!connect_timed(fd,&remote,seconds)) { close(fd); return -1; }
        if (generation) *generation=current_generation;
        return fd;
    }
    return -1;
}
static int target_socket(uint32_t address,uint16_t port,int seconds) {
    if (direct_mode) return direct_socket(SOCK_STREAM,address,port,seconds,NULL);
    int fd=proxy_socket(seconds); if (fd<0) return -1;
    uint8_t request[10]={5,1,0,1}; memcpy(request+4,&address,4); memcpy(request+8,&port,2);
    uint8_t response[4], discarded[258];
    if (!write_all(fd,request,sizeof(request)) || !read_all(fd,response,sizeof(response)) || response[0]!=5 || response[1]!=0) { close(fd); return -1; }
    size_t n=0;
    if (response[3]==1) n=4;
    else if (response[3]==4) n=16;
    else if (response[3]==3) { uint8_t len; if (!read_all(fd,&len,1)) { close(fd); return -1; } n=len; }
    else { close(fd); return -1; }
    if (!read_all(fd,discarded,n+2)) { close(fd); return -1; }
    return fd;
}
typedef struct { uint8_t bytes[BUF_SIZE]; size_t start,len; int eof,shutdown_sent; } buffer;
/* A relay carries long-lived TCP sessions; an idle peer is not a failed one.
 * Let the kernel keep it alive, discard only entries the guest closed. */
static void configure_long_lived(int fd) {
    int keep=1,idle=60,interval=10,count=3;
    (void)setsockopt(fd,SOL_SOCKET,SO_KEEPALIVE,&keep,sizeof(keep));
    (void)setsockopt(fd,IPPROTO_TCP,TCP_KEEPALIVE,&idle,sizeof(idle));
    (void)setsockopt(fd,IPPROTO_TCP,TCP_KEEPINTVL,&interval,sizeof(interval));
    (void)setsockopt(fd,IPPROTO_TCP,TCP_KEEPCNT,&count,sizeof(count));
}
static void relay(int client,int remote) {
    int a=fcntl(client,F_GETFL,0), b=fcntl(remote,F_GETFL,0);
    if (a<0 || b<0 || fcntl(client,F_SETFL,a|O_NONBLOCK) || fcntl(remote,F_SETFL,b|O_NONBLOCK)) return;
    configure_long_lived(client); configure_long_lived(remote);
    buffer cr={0}, rc={0};
    for (;;) {
        if (cr.eof && cr.len==0 && !cr.shutdown_sent) { shutdown(remote,SHUT_WR); cr.shutdown_sent=1; }
        if (rc.eof && rc.len==0 && !rc.shutdown_sent) { shutdown(client,SHUT_WR); rc.shutdown_sent=1; }
        if (cr.eof && rc.eof && !cr.len && !rc.len) break;
        if (cr.start && cr.start+cr.len==BUF_SIZE) { memmove(cr.bytes,cr.bytes+cr.start,cr.len); cr.start=0; }
        if (rc.start && rc.start+rc.len==BUF_SIZE) { memmove(rc.bytes,rc.bytes+rc.start,rc.len); rc.start=0; }
        struct pollfd fds[2]={{.fd=client},{.fd=remote}};
        if (!cr.eof && cr.start+cr.len<BUF_SIZE) fds[0].events|=POLLIN;
        if (rc.len) fds[0].events|=POLLOUT;
        if (!rc.eof && rc.start+rc.len<BUF_SIZE) fds[1].events|=POLLIN;
        if (cr.len) fds[1].events|=POLLOUT;
        int r=poll(fds,2,30000); if (r==0) continue; if (r<0) { if (errno==EINTR) continue; break; }
        if (fds[0].revents&(POLLERR|POLLNVAL) || fds[1].revents&(POLLERR|POLLNVAL)) break;
        if (fds[0].revents&(POLLIN|POLLHUP)) {
            ssize_t n=recv(client,cr.bytes+cr.start+cr.len,BUF_SIZE-cr.start-cr.len,0);
            if (n>0) cr.len+=(size_t)n; else if (n==0) cr.eof=1; else if (errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR) break;
        }
        if (fds[1].revents&(POLLIN|POLLHUP)) {
            ssize_t n=recv(remote,rc.bytes+rc.start+rc.len,BUF_SIZE-rc.start-rc.len,0);
            if (n>0) rc.len+=(size_t)n; else if (n==0) rc.eof=1; else if (errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR) break;
        }
        if ((fds[1].revents&POLLOUT) && cr.len) {
            ssize_t n=send(remote,cr.bytes+cr.start,cr.len,0);
            if (n>0) { cr.start+=(size_t)n; cr.len-=(size_t)n; if (!cr.len) cr.start=0; }
            else if (n<0 && errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR) break;
        }
        if ((fds[0].revents&POLLOUT) && rc.len) {
            ssize_t n=send(client,rc.bytes+rc.start,rc.len,0);
            if (n>0) { rc.start+=(size_t)n; rc.len-=(size_t)n; if (!rc.len) rc.start=0; }
            else if (n<0 && errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR) break;
        }
    }
}
static int dns_exchange(const uint8_t *query,size_t query_size,uint8_t *reply,size_t *reply_size) {
    if (query_size<12 || query_size>DNS_MAX) return 0;
    uint8_t framed[2+DNS_MAX]={(uint8_t)(query_size>>8),(uint8_t)query_size};
    uint8_t saved_error[DNS_MAX]; size_t saved_error_size=0;
    memcpy(framed+2,query,query_size);
    for (int i=0;i<resolver_count;i++) {
        int remote=target_socket(resolver_addresses[i].s_addr,htons(53),2);
        if (remote<0) continue;
        struct timeval timeout={.tv_sec=2,.tv_usec=0};
        (void)setsockopt(remote,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
        (void)setsockopt(remote,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
        uint8_t sizebuf[2];
        int ok=write_all(remote,framed,2+query_size) && read_all(remote,sizebuf,2);
        size_t n=ok ? (((size_t)sizebuf[0]<<8)|sizebuf[1]) : 0;
        ok=ok && n>=12 && n<=DNS_MAX && read_all(remote,reply,n);
        close(remote);
        if (!ok || reply[0]!=query[0] || reply[1]!=query[1] || !(reply[2]&0x80)) continue;
        unsigned rcode=reply[3]&0x0f;
        if ((rcode==2 || rcode==5) && i+1<resolver_count) {
            memcpy(saved_error,reply,n); saved_error_size=n; continue;
        }
        *reply_size=n; return 1;
    }
    if (saved_error_size) { memcpy(reply,saved_error,saved_error_size); *reply_size=saved_error_size; return 1; }
    return 0;
}
static void serve_dns_tcp(int client) {
    uint8_t query[DNS_MAX],reply[2+DNS_MAX],sizebuf[2];
    while (read_all(client,sizebuf,2)) {
        size_t n=((size_t)sizebuf[0]<<8)|sizebuf[1], response_size=0;
        if (n<12 || n>DNS_MAX || !read_all(client,query,n) || !dns_exchange(query,n,reply+2,&response_size)) break;
        reply[0]=(uint8_t)(response_size>>8); reply[1]=(uint8_t)response_size;
        if (!write_all(client,reply,2+response_size)) break;
    }
}
static void *serve_tcp(void *arg) {
    int client=(int)(intptr_t)arg; struct timeval timeout={.tv_sec=5};
    (void)setsockopt(client,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    uint8_t header[HEADER_LEN];
    if (read_all(client,header,sizeof(header)) && !memcmp(header,"NAT1",4) && !memcmp(header+4,secret,TOKEN_LEN)) {
        uint32_t address; uint16_t port; memcpy(&address,header+4+TOKEN_LEN,4); memcpy(&port,header+4+TOKEN_LEN+4,2);
        if (ntohs(port)==53) serve_dns_tcp(client);
        else {
            int remote=target_socket(address,port,7);
            if (remote>=0) { relay(client,remote); close(remote); }
        }
    }
    close(client); release_worker(0); return NULL;
}
typedef struct { int fd; struct sockaddr_in peer; socklen_t peer_len; size_t size; uint8_t data[DNS_MAX]; } dns_task;
static void *serve_dns(void *arg) {
    dns_task *task=arg;
    uint8_t reply[DNS_HEADER_LEN+DNS_MAX]; size_t n=0;
    if (dns_exchange(task->data,task->size,reply+DNS_HEADER_LEN,&n)) {
        memcpy(reply,"DNS1",4); memcpy(reply+4,secret,TOKEN_LEN);
        (void)sendto(task->fd,reply,DNS_HEADER_LEN+n,0,(struct sockaddr *)&task->peer,task->peer_len);
    }
    free(task); release_worker(1); return NULL;
}
static int local_socket(int kind,uint16_t *port) {
    int fd=socket(AF_INET,kind,0); if (fd<0) return -1;
    struct sockaddr_in addr={.sin_len=sizeof(addr),.sin_family=AF_INET,.sin_port=0,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    if (bind(fd,(struct sockaddr *)&addr,sizeof(addr))) { close(fd); return -1; }
    socklen_t n=sizeof(addr); if (getsockname(fd,(struct sockaddr *)&addr,&n)) { close(fd); return -1; }
    *port=ntohs(addr.sin_port); return fd;
}
static int read_auth_file(void) {
    const char *path=getenv("NAPTD_PROXY_AUTH_FILE");
    if (!path || !*path) return 1;
    FILE *f=fopen(path,"rb"); if (!f) return 0;
    int u=fgetc(f); if (u==EOF) { fclose(f); return 0; }
    username_len=(size_t)u;
    if (username_len && fread(username,1,username_len,f)!=username_len) { fclose(f); return 0; }
    int p=fgetc(f); if (p==EOF) { fclose(f); return 0; }
    password_len=(size_t)p;
    if (password_len && fread(password,1,password_len,f)!=password_len) { fclose(f); return 0; }
    int extra=fgetc(f); fclose(f);
    return extra==EOF && ((username_len==0 && password_len==0) || (username_len>0 && password_len>0));
}
/* ---------- LAN SOCKS5 service (phone -> Mac -> upstream) ----------
 * The listener binds only to the selected Wi-Fi address, never to every
 * interface. Credentials are mandatory: without them any device on the same
 * network could use the Mac's already-authenticated connection. */
enum { LAN_HANDSHAKE, LAN_TCP, LAN_UDP };
static const unsigned lan_limits[3]={48,192,32};
static pthread_mutex_t lan_worker_lock=PTHREAD_MUTEX_INITIALIZER;
static unsigned lan_workers[3];
static int lan_tcp_listener=-1;
static struct in_addr lan_bound_address;
static int lan_reserve_worker(void) {
    pthread_mutex_lock(&lan_worker_lock);
    int allowed=lan_workers[LAN_HANDSHAKE]<lan_limits[LAN_HANDSHAKE];
    if (allowed) lan_workers[LAN_HANDSHAKE]++;
    pthread_mutex_unlock(&lan_worker_lock); return allowed;
}
/* Long-lived TCP/UDP sessions must not consume the handshake budget or starve
 * the other protocol. All three budgets remain bounded. */
static int lan_promote_worker(int kind) {
    pthread_mutex_lock(&lan_worker_lock);
    int allowed=lan_workers[kind]<lan_limits[kind];
    if (allowed) { lan_workers[LAN_HANDSHAKE]--; lan_workers[kind]++; }
    pthread_mutex_unlock(&lan_worker_lock); return allowed;
}
static void lan_release_worker(int kind) {
    pthread_mutex_lock(&lan_worker_lock);
    if (lan_workers[kind]) lan_workers[kind]--;
    pthread_mutex_unlock(&lan_worker_lock);
}
/* Read the current IPv4 address of the selected physical Wi-Fi interface. */
static int lan_wifi_address(struct in_addr *out) {
    struct ifaddrs *list=NULL; int found=0;
    if (!lan_interface[0] || getifaddrs(&list)) return 0;
    for (struct ifaddrs *p=list;p;p=p->ifa_next) {
        if (p->ifa_addr && p->ifa_addr->sa_family==AF_INET && !strcmp(p->ifa_name,lan_interface)) {
            *out=((struct sockaddr_in *)p->ifa_addr)->sin_addr; found=1; break;
        }
    }
    freeifaddrs(list);
    return found;
}
static int dns_skip_name(const uint8_t *packet,size_t length,size_t *offset) {
    size_t position=*offset, steps=0;
    for (;;) {
        if (position>=length || steps++>length) return 0;
        uint8_t label=packet[position++];
        if (!label) break;
        if ((label&0xc0)==0xc0) { if (position>=length) return 0; position++; break; }
        if (label&0xc0) return 0;
        if (position+label>length) return 0;
        position+=label;
    }
    *offset=position; return 1;
}
/* Resolve one IPv4 address through the configured resolvers and upstream mode. */
static int resolve_ipv4_name_ttl(const char *name,struct in_addr *out,uint32_t *ttl) {
    if (ttl) *ttl=0;
    size_t name_length=strlen(name);
    if (!name_length || name_length>253) return 0;
    uint8_t query[DNS_MAX]; size_t length=0;
    query[length++]=(uint8_t)(arc4random()>>24); query[length++]=(uint8_t)(arc4random()>>24);
    query[length++]=1; query[length++]=0;
    query[length++]=0; query[length++]=1; query[length++]=0; query[length++]=0;
    query[length++]=0; query[length++]=0; query[length++]=0; query[length++]=0;
    const char *part=name;
    for (;;) {
        const char *dot=strchr(part,'.');
        size_t label=dot ? (size_t)(dot-part) : strlen(part);
        if (!label || label>63 || length+1+label+5>DNS_MAX) return 0;
        for (size_t i=0;i<label;i++) {
            unsigned char c=(unsigned char)part[i];
            if (c<=32 || c>=127 || c=='\\' || c=='/') return 0;
        }
        query[length++]=(uint8_t)label; memcpy(query+length,part,label); length+=label;
        if (!dot) break;
        part=dot+1;
        if (!*part) return 0;
    }
    query[length++]=0;
    query[length++]=0; query[length++]=1; query[length++]=0; query[length++]=1;
    uint8_t reply[DNS_MAX]; size_t reply_length=0;
    if (!dns_exchange(query,length,reply,&reply_length)) return 0;
    if (reply_length<12 || reply[0]!=query[0] || reply[1]!=query[1] || (reply[3]&0x0f)) return 0;
    unsigned questions=((unsigned)reply[4]<<8)|reply[5], answers=((unsigned)reply[6]<<8)|reply[7];
    size_t offset=12;
    for (unsigned i=0;i<questions;i++) {
        if (!dns_skip_name(reply,reply_length,&offset) || offset+4>reply_length) return 0;
        offset+=4;
    }
    uint32_t minimum_ttl=UINT32_MAX;
    for (unsigned i=0;i<answers && i<64;i++) {
        if (!dns_skip_name(reply,reply_length,&offset) || offset+10>reply_length) return 0;
        unsigned type=((unsigned)reply[offset]<<8)|reply[offset+1];
        unsigned klass=((unsigned)reply[offset+2]<<8)|reply[offset+3];
        uint32_t record_ttl=((uint32_t)reply[offset+4]<<24)|((uint32_t)reply[offset+5]<<16)|
                            ((uint32_t)reply[offset+6]<<8)|reply[offset+7];
        unsigned size=((unsigned)reply[offset+8]<<8)|reply[offset+9];
        offset+=10;
        if (offset+size>reply_length) return 0;
        if (klass==1 && (type==1 || type==5) && record_ttl<minimum_ttl) minimum_ttl=record_ttl;
        if (type==1 && klass==1 && size==4) {
            memcpy(out,reply+offset,4);
            if (ttl) *ttl=minimum_ttl;
            return 1;
        }
        offset+=size;
    }
    return 0;
}
static int resolve_ipv4_name(const char *name,struct in_addr *out) {
    return resolve_ipv4_name_ttl(name,out,NULL);
}
/* Send a SOCKS5 CONNECT with a domain name to the configured upstream proxy. */
static int proxy_connect_name(const char *name,uint16_t port,int seconds) {
    size_t length=strlen(name);
    if (!length || length>253) return -1;
    int fd=proxy_socket(seconds); if (fd<0) return -1;
    uint8_t request[4+1+255+2]; size_t n=0;
    request[n++]=5; request[n++]=1; request[n++]=0; request[n++]=3;
    request[n++]=(uint8_t)length; memcpy(request+n,name,length); n+=length;
    request[n++]=(uint8_t)(port>>8); request[n++]=(uint8_t)(port&0xff);
    uint8_t response[4],discarded[258]; size_t skip=0;
    if (!write_all(fd,request,n) || !read_all(fd,response,4) || response[0]!=5 || response[1]!=0) { close(fd); return -1; }
    if (response[3]==1) skip=4;
    else if (response[3]==4) skip=16;
    else if (response[3]==3) { uint8_t size; if (!read_all(fd,&size,1)) { close(fd); return -1; } skip=size; }
    else { close(fd); return -1; }
    if (!read_all(fd,discarded,skip+2)) { close(fd); return -1; }
    return fd;
}
/* Refuse loopback and the unspecified address as LAN-side destinations. */
static int lan_target_allowed(uint32_t address) {
    uint32_t host=ntohl(address);
    return host && (host>>24)!=127;
}
static int lan_connect_ip(uint32_t address,uint16_t port) {
    if (!port || !lan_target_allowed(address)) return -1;
    /* target_socket expects the port in network byte order, as on the wire. */
    return target_socket(address,htons(port),7);
}
static int lan_connect_name(const char *name,size_t length,uint16_t port) {
    if (!length || length>253 || !port) return -1;
    char clean[254]; memcpy(clean,name,length); clean[length]=0;
    for (size_t i=0;i<length;i++) {
        unsigned char c=(unsigned char)clean[i];
        if (c<=32 || c>=127 || c=='\\' || c=='/') return -1;
    }
    if (!direct_mode) return proxy_connect_name(clean,port,7);
    struct in_addr resolved;
    if (!resolve_ipv4_name(clean,&resolved) || !lan_target_allowed(resolved.s_addr)) return -1;
    return target_socket(resolved.s_addr,htons(port),7);
}
static int lan_reply(int client,uint8_t code,const uint8_t *address,uint16_t port) {
    uint8_t reply[10]={5,code,0,1,0,0,0,0,0,0};
    if (address) memcpy(reply+4,address,4);
    reply[8]=(uint8_t)(port>>8); reply[9]=(uint8_t)(port&0xff);
    return write_all(client,reply,sizeof(reply));
}
static int lan_credentials_match(const uint8_t *user,size_t user_length,const uint8_t *password,size_t password_length) {
    if (user_length!=lan_username_len || password_length!=lan_password_len) return 0;
    unsigned char difference=0;
    for (size_t i=0;i<user_length;i++) difference|=(unsigned char)(user[i]^lan_username[i]);
    for (size_t i=0;i<password_length;i++) difference|=(unsigned char)(password[i]^lan_password[i]);
    return difference==0;
}
#include "lan_udp.h"

static void *serve_lan(void *arg) {
    int client=(int)(intptr_t)arg, worker_kind=LAN_HANDSHAKE;
    struct timeval timeout={.tv_sec=10,.tv_usec=0};
    int noSignal=1;
    (void)setsockopt(client,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    (void)setsockopt(client,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
    (void)setsockopt(client,SOL_SOCKET,SO_NOSIGPIPE,&noSignal,sizeof(noSignal));
    struct timespec deadline={0}; (void)clock_gettime(CLOCK_MONOTONIC,&deadline);
    deadline.tv_sec+=10;
    uint8_t head[2+255];
    if (!read_handshake(client,head,2,&deadline) || head[0]!=5 || !head[1]) goto done;
    size_t methods=head[1];
    if (!read_handshake(client,head+2,methods,&deadline)) goto done;
    { int wanted=lan_auth ? 2 : 0, offered=0;
      for (size_t i=0;i<methods;i++) if (head[2+i]==wanted) offered=1;
      if (!offered) { uint8_t reject[2]={5,0xff}; (void)write_all(client,reject,2); goto done; }
      uint8_t selection[2]={5,(uint8_t)wanted};
      if (!write_all(client,selection,2)) goto done;
    }
    if (lan_auth) {
        uint8_t version=0,user_length=0,password_length=0,user[255],password[255];
        int ok=read_handshake(client,&version,1,&deadline) && version==1 && read_handshake(client,&user_length,1,&deadline) && user_length>0 &&
               read_handshake(client,user,user_length,&deadline) && read_handshake(client,&password_length,1,&deadline) && password_length>0 &&
               read_handshake(client,password,password_length,&deadline) && lan_credentials_match(user,user_length,password,password_length);
        clear_bytes(user,255); clear_bytes(password,255);
        uint8_t result[2]={1,(uint8_t)(ok?0:1)};
        if (!write_all(client,result,2) || !ok) goto done;
    }
    uint8_t request[4];
    if (!read_handshake(client,request,4,&deadline) || request[0]!=5 || request[2]!=0) goto done;
    { int command=request[1], atyp=request[3];
      uint8_t address[4]={0}, name[256]; size_t name_length=0;
      if (atyp==1) { if (!read_handshake(client,address,4,&deadline)) goto done; }
      else if (atyp==3) {
          uint8_t size=0;
          if (!read_handshake(client,&size,1,&deadline) || !size || !read_handshake(client,name,size,&deadline)) goto done;
          name[size]=0; name_length=size;
      } else if (atyp==4) { uint8_t skip6[16]; if (!read_handshake(client,skip6,16,&deadline)) goto done; }
      else { (void)lan_reply(client,8,NULL,0); goto done; }
      uint8_t port_bytes[2];
      if (!read_handshake(client,port_bytes,2,&deadline)) goto done;
      uint16_t port=(uint16_t)(((unsigned)port_bytes[0]<<8)|port_bytes[1]);
      if (command==1) {
          if (!lan_promote_worker(LAN_TCP)) { (void)lan_reply(client,1,NULL,0); goto done; }
          worker_kind=LAN_TCP;
          int remote=-1;
          if (atyp==1) { uint32_t destination; memcpy(&destination,address,4); remote=lan_connect_ip(destination,port); }
          else if (atyp==3) remote=lan_connect_name((const char *)name,name_length,port);
          if (remote<0) { (void)lan_reply(client,5,NULL,0); goto done; }
          if (!lan_reply(client,0,NULL,0)) { close(remote); goto done; }
          relay(client,remote);
          close(remote);
      } else if (command==3) {
          if (atyp!=1) { (void)lan_reply(client,8,NULL,0); goto done; }
          if (!lan_promote_worker(LAN_UDP)) { (void)lan_reply(client,1,NULL,0); goto done; }
          worker_kind=LAN_UDP;
          uint32_t requested; memcpy(&requested,address,4);
          serve_lan_association(client,requested,htons(port));
      } else {
          (void)lan_reply(client,7,NULL,0);
      }
    }
done:
    close(client); lan_release_worker(worker_kind); return NULL;
}
static int lan_bind_tcp(struct in_addr address) {
    int fd=socket(AF_INET,SOCK_STREAM,0); if (fd<0) return -1;
    int one=1;
    (void)setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
    struct sockaddr_in local={.sin_len=sizeof(local),.sin_family=AF_INET,.sin_port=htons((uint16_t)lan_port),.sin_addr=address};
    if (bind(fd,(struct sockaddr *)&local,sizeof(local)) || listen(fd,64)) { close(fd); return -1; }
    return fd;
}
static void *serve_lan_tcp(void *arg) {
    (void)arg;
    for (;;) {
        struct in_addr current;
        if (!lan_wifi_address(&current)) {
            if (lan_tcp_listener>=0) { close(lan_tcp_listener); lan_tcp_listener=-1; }
            sleep(2); continue;
        }
        if (lan_tcp_listener<0 || current.s_addr!=lan_bound_address.s_addr) {
            if (lan_tcp_listener>=0) close(lan_tcp_listener);
            lan_tcp_listener=lan_bind_tcp(current);
            if (lan_tcp_listener>=0) lan_bound_address=current;
            if (lan_tcp_listener<0) { sleep(2); continue; }
        }
        struct pollfd wait={.fd=lan_tcp_listener,.events=POLLIN};
        int ready=poll(&wait,1,2000);
        if (ready>0 && (wait.revents&POLLIN)) {
            struct sockaddr_in peer={0}; socklen_t length=sizeof(peer);
            int fd=accept(lan_tcp_listener,(struct sockaddr *)&peer,&length);
            if (fd>=0) {
                if (!lan_reserve_worker()) close(fd);
                else {
                    pthread_t thread;
                    if (pthread_create(&thread,NULL,serve_lan,(void *)(intptr_t)fd)) { close(fd); lan_release_worker(LAN_HANDSHAKE); }
                    else pthread_detach(thread);
                }
            }
        } else if (ready<0 && errno!=EINTR) sleep(1);
    }
    return NULL;
}
static int read_lan_auth_file(void) {
    const char *path=getenv("NAPTD_LAN_AUTH_FILE");
    if (!path || !*path) return 0;
    FILE *f=fopen(path,"rb"); if (!f) return 0;
    int u=fgetc(f);
    if (u<=0 || u==EOF) { fclose(f); return 0; }
    lan_username_len=(size_t)u;
    if (fread(lan_username,1,lan_username_len,f)!=lan_username_len) { fclose(f); return 0; }
    int p=fgetc(f);
    if (p<=0 || p==EOF) { fclose(f); return 0; }
    lan_password_len=(size_t)p;
    if (fread(lan_password,1,lan_password_len,f)!=lan_password_len) { fclose(f); return 0; }
    int extra=fgetc(f); fclose(f);
    return extra==EOF;
}
/* Called before gateway_ready so a failure is reported to the controller. */
static int lan_start(void) {
    if (!lan_port) return 1;
    if (!lan_interface[0] || !read_lan_auth_file()) { fputs("lan_auth_unavailable\n",stderr); return 0; }
    lan_auth=1;
    struct in_addr current;
    if (!lan_wifi_address(&current)) { fputs("lan_wifi_unavailable\n",stderr); return 0; }
    lan_tcp_listener=lan_bind_tcp(current);
    if (lan_tcp_listener<0) { fputs("lan_port_unavailable\n",stderr); return 0; }
    lan_bound_address=current;
    pthread_t thread;
    if (pthread_create(&thread,NULL,serve_lan_tcp,NULL)) { fputs("lan_thread_failed\n",stderr); close(lan_tcp_listener); lan_tcp_listener=-1; return 0; }
    pthread_detach(thread);
    return 1;
}
static void close_flow(int i) {
    if (flows[i].active) {
        close(flows[i].fd);
        if (flows[i].control>=0) close(flows[i].control);
    }
    memset(&flows[i],0,sizeof(flows[i]));
}
static int get_flow(struct sockaddr_in peer,uint32_t address,uint16_t port) {
    unsigned long generation=0;
    if (direct_mode && !upstream_snapshot(NULL,NULL,&generation,0)) return -1;
    int free_slot=-1,oldest_slot=-1;
    for (int i=0;i<UDP_FLOW_MAX;i++) {
        if (flows[i].active && ((direct_mode && flows[i].generation!=generation) ||
            (!direct_mode && !control_alive(flows[i].control)))) close_flow(i);
        if (!flows[i].active) { if (free_slot<0) free_slot=i; continue; }
        if (flows[i].client.sin_addr.s_addr==peer.sin_addr.s_addr && flows[i].client.sin_port==peer.sin_port &&
            flows[i].destination==address && flows[i].port==port) return i;
        if (oldest_slot<0 || flows[i].order<flows[oldest_slot].order) oldest_slot=i;
    }
    if (free_slot<0 && oldest_slot>=0) { close_flow(oldest_slot); free_slot=oldest_slot; }
    if (free_slot<0) return -1;
    int fd=-1,control=-1;
    if (direct_mode) {
        fd=direct_socket(SOCK_DGRAM,address,port,2,&generation);
    } else {
        proxy_udp transport;
        if (!proxy_udp_open(&transport)) return -1;
        fd=transport.fd; control=transport.control;
    }
    if (fd<0) return -1;
    int flags=fcntl(fd,F_GETFL,0);
    if (flags<0 || fcntl(fd,F_SETFL,flags|O_NONBLOCK)) { close(fd); if(control>=0)close(control); return -1; }
    flows[free_slot]=(udp_flow){.fd=fd,.control=control,.active=1,.client=peer,.destination=address,.port=port,
                                .last=time(NULL),.order=++flow_order,.generation=generation};
    return free_slot;
}
int main(int argc,char **argv) {
    if (!hotspot_start_parent_guard()) return 5;
    const char *provided=getenv("NAPTD_RELAY_TOKEN");
    if (argc!=3 || !provided || strlen(provided)!=TOKEN_LEN) return 2;
    const char *configured[2]={getenv("NAPTD_DNS_SERVER"),getenv("NAPTD_DNS_SECONDARY")};
    if (!configured[0] || !*configured[0]) configured[0]="1.1.1.1";
    for (int i=0;i<2;i++) {
        if (!configured[i] || !*configured[i] || !strcmp(configured[i],"-")) continue;
        struct in_addr parsed;
        if (inet_pton(AF_INET,configured[i],&parsed)!=1) { fputs("invalid_dns_server\n",stderr); return 2; }
        uint32_t value=ntohl(parsed.s_addr);
        if ((value>>24)==0 || (value>>24)==127 || (value>>24)>=224) { fputs("invalid_dns_server\n",stderr); return 2; }
        if (resolver_count==0 || parsed.s_addr!=resolver_addresses[0].s_addr) resolver_addresses[resolver_count++]=parsed;
    }
    if (!resolver_count) return 2;
    if (!strcmp(argv[1],"direct")) {
        direct_mode=1;
        if (!*argv[2] || strlen(argv[2])>=sizeof(upstream_name)) return 2;
        memcpy(upstream_name,argv[2],strlen(argv[2])+1);
        if (!upstream_snapshot(NULL,NULL,NULL,1)) { fputs("wifi_unavailable\n",stderr); return 2; }
    } else if (!strcmp(argv[1],"socks5")) {
        char *end=NULL; unsigned long port=strtoul(argv[2],&end,10); if (*end || port<1 || port>65535 || !read_auth_file()) return 2;
        proxy_port=(uint16_t)port;
    } else return 2;
    memcpy(secret,provided,TOKEN_LEN); signal(SIGPIPE,SIG_IGN); setvbuf(stdout,NULL,_IONBF,0);
    /* NAPTD_LAN_PORT opens a SOCKS5 listener on the selected Wi-Fi address for
     * devices on the same LAN; NAPTD_LAN_AUTH_FILE holds its mandatory credentials. */
    { const char *text=getenv("NAPTD_LAN_PORT");
      if (text && *text) {
          char *end=NULL; unsigned long value=strtoul(text,&end,10);
          if (*end || value<1 || value>65535) { fputs("invalid_lan_port\n",stderr); return 2; }
          lan_port=(int)value;
          const char *iface=getenv("NAPTD_LAN_INTERFACE");
          if (!iface || !*iface || strlen(iface)>=sizeof(lan_interface) || strncmp(iface,"en",2)) { fputs("invalid_lan_interface\n",stderr); return 2; }
          memcpy(lan_interface,iface,strlen(iface)+1);
      }
    }
    if (!direct_mode) { int test=proxy_socket(7); if (test<0) { fputs("proxy_unavailable_or_auth_failed\n",stderr); return 3; } close(test); }
    if (!lan_start()) return 3;
    uint16_t tcp_port=0,dns_port=0; int tcp=local_socket(SOCK_STREAM,&tcp_port), dns=local_socket(SOCK_DGRAM,&dns_port);
    if (tcp<0 || dns<0 || listen(tcp,128)) { perror("local_relay"); return 4; }
    if (lan_port) printf("gateway_ready:%u:%u:%d\n",tcp_port,dns_port,lan_port);
    else printf("gateway_ready:%u:%u\n",tcp_port,dns_port);
    for (;;) {
        struct pollfd fds[2+UDP_FLOW_MAX]={{.fd=tcp,.events=POLLIN},{.fd=dns,.events=POLLIN}};
        int slots[UDP_FLOW_MAX], count=2;
        for (int i=0;i<UDP_FLOW_MAX;i++) if (flows[i].active) { slots[count-2]=i; fds[count++]=(struct pollfd){.fd=flows[i].fd,.events=POLLIN}; }
        int r=poll(fds,(nfds_t)count,5000); if (r<0) { if (errno==EINTR) continue; break; }
        time_t now=time(NULL);
        for (int j=2;j<count;j++) {
            int i=slots[j-2]; if (!flows[i].active || flows[i].fd!=fds[j].fd) continue;
            if (fds[j].revents&POLLIN) {
                uint8_t reply[UDP_HEADER_LEN+UDP_PAYLOAD_MAX]; ssize_t n;
                if (direct_mode) {
                    struct iovec iov={.iov_base=reply+UDP_HEADER_LEN,.iov_len=UDP_PAYLOAD_MAX};
                    struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1};
                    n=recvmsg(flows[i].fd,&msg,0);
                    if (n>=0 && (msg.msg_flags&MSG_TRUNC)) n=-1;
                } else {
                    proxy_udp transport={.fd=flows[i].fd,.control=flows[i].control};
                    uint32_t source=0; uint16_t port=0;
                    n=proxy_udp_receive(&transport,&source,&port,reply+UDP_HEADER_LEN,UDP_PAYLOAD_MAX);
                    if (n>=0 && (source!=flows[i].destination || port!=flows[i].port || !control_alive(flows[i].control))) n=-1;
                }
                if (n>=0) {
                    memcpy(reply,"UDP1",4); memcpy(reply+4,secret,TOKEN_LEN);
                    memcpy(reply+4+TOKEN_LEN,&flows[i].destination,4); memcpy(reply+4+TOKEN_LEN+4,&flows[i].port,2);
                    (void)sendto(dns,reply,UDP_HEADER_LEN+(size_t)n,0,(struct sockaddr *)&flows[i].client,sizeof(flows[i].client)); flows[i].last=now; flows[i].order=++flow_order;
                }
            }
            if (fds[j].revents&(POLLERR|POLLNVAL) || now-flows[i].last>120 || (!direct_mode && !control_alive(flows[i].control))) close_flow(i);
        }
        if (fds[0].revents&POLLIN) {
            struct sockaddr_in peer={0}; socklen_t len=sizeof(peer); int fd=accept(tcp,(struct sockaddr *)&peer,&len);
            if (fd>=0) {
                if (peer.sin_addr.s_addr!=htonl(INADDR_LOOPBACK) || !reserve_worker(0)) close(fd);
                else { pthread_t thread; if (pthread_create(&thread,NULL,serve_tcp,(void *)(intptr_t)fd)) { close(fd); release_worker(0); } else pthread_detach(thread); }
            }
        }
        if (fds[1].revents&POLLIN) {
            struct sockaddr_in peer={0}; socklen_t peer_len=sizeof(peer); uint8_t data[UDP_HEADER_LEN+UDP_PAYLOAD_MAX];
            ssize_t n=recvfrom(dns,data,sizeof(data),0,(struct sockaddr *)&peer,&peer_len);
            if (n<DNS_HEADER_LEN || peer.sin_addr.s_addr!=htonl(INADDR_LOOPBACK) || memcmp(data+4,secret,TOKEN_LEN)) continue;
            if (!memcmp(data,"DNS1",4) && n>=DNS_HEADER_LEN+12 && n<=DNS_HEADER_LEN+DNS_MAX) {
                dns_task *task=calloc(1,sizeof(*task)); if (!task) continue;
                task->fd=dns; task->peer=peer; task->peer_len=peer_len;
                if (!reserve_worker(1)) free(task);
                else { task->size=(size_t)n-DNS_HEADER_LEN; memcpy(task->data,data+DNS_HEADER_LEN,task->size); pthread_t thread; if (pthread_create(&thread,NULL,serve_dns,task)) { free(task); release_worker(1); } else pthread_detach(thread); }
            } else if (!memcmp(data,"UDP1",4) && n>=UDP_HEADER_LEN) {
                uint32_t address; uint16_t port; memcpy(&address,data+4+TOKEN_LEN,4); memcpy(&port,data+4+TOKEN_LEN+4,2);
                /* Hold the same destination policy as the framed caller. */
                if (!port || !lan_target_allowed(address)) continue; int slot=get_flow(peer,address,port);
                if (slot>=0) {
                    proxy_udp transport={.fd=flows[slot].fd,.control=flows[slot].control};
                    ssize_t sent=direct_mode ? send(flows[slot].fd,data+UDP_HEADER_LEN,(size_t)n-UDP_HEADER_LEN,0)
                        : proxy_udp_send(&transport,address,port,data+UDP_HEADER_LEN,(size_t)n-UDP_HEADER_LEN);
                    if (sent>=0) { flows[slot].last=now; flows[slot].order=++flow_order; }
                }
            }
        }
    }
    close(tcp); close(dns); return 0;
}
