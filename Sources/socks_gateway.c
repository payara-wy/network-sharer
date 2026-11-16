/* Local-only relay: outbound sockets use either the selected interface or SOCKS5. */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
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
typedef struct { int fd; int active; struct sockaddr_in client; uint32_t destination; uint16_t port; time_t last; uint64_t order; unsigned long generation; } udp_flow;
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
static void relay(int client,int remote) {
    int a=fcntl(client,F_GETFL,0), b=fcntl(remote,F_GETFL,0);
    if (a<0 || b<0 || fcntl(client,F_SETFL,a|O_NONBLOCK) || fcntl(remote,F_SETFL,b|O_NONBLOCK)) return;
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
        int r=poll(fds,2,300000); if (r<=0) { if (r<0 && errno==EINTR) continue; break; }
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
static void close_flow(int i) { if (flows[i].active) close(flows[i].fd); memset(&flows[i],0,sizeof(flows[i])); }
static int get_flow(struct sockaddr_in peer,uint32_t address,uint16_t port) {
    unsigned long generation;
    if (!upstream_snapshot(NULL,NULL,&generation,0)) return -1;
    int free_slot=-1,oldest_slot=-1;
    for (int i=0;i<UDP_FLOW_MAX;i++) {
        if (flows[i].active && flows[i].generation!=generation) close_flow(i);
        if (!flows[i].active) { if (free_slot<0) free_slot=i; continue; }
        if (flows[i].client.sin_addr.s_addr==peer.sin_addr.s_addr && flows[i].client.sin_port==peer.sin_port && flows[i].destination==address && flows[i].port==port) return i;
        if (oldest_slot<0 || flows[i].order<flows[oldest_slot].order) oldest_slot=i;
    }
    if (free_slot<0 && oldest_slot>=0) { close_flow(oldest_slot); free_slot=oldest_slot; }
    if (free_slot<0) return -1;
    int fd=direct_socket(SOCK_DGRAM,address,port,7,&generation); if (fd<0) return -1;
    int flags=fcntl(fd,F_GETFL,0); if (flags<0 || fcntl(fd,F_SETFL,flags|O_NONBLOCK)) { close(fd); return -1; }
    flows[free_slot]=(udp_flow){.fd=fd,.active=1,.client=peer,.destination=address,.port=port,.last=time(NULL),.order=++flow_order,.generation=generation};
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
    if (!direct_mode) { int test=proxy_socket(7); if (test<0) { fputs("proxy_unavailable_or_auth_failed\n",stderr); return 3; } close(test); }
    uint16_t tcp_port=0,dns_port=0; int tcp=local_socket(SOCK_STREAM,&tcp_port), dns=local_socket(SOCK_DGRAM,&dns_port);
    if (tcp<0 || dns<0 || listen(tcp,128)) { perror("local_relay"); return 4; }
    printf("gateway_ready:%u:%u\n",tcp_port,dns_port);
    for (;;) {
        struct pollfd fds[2+UDP_FLOW_MAX]={{.fd=tcp,.events=POLLIN},{.fd=dns,.events=POLLIN}};
        int slots[UDP_FLOW_MAX], count=2;
        for (int i=0;i<UDP_FLOW_MAX;i++) if (flows[i].active) { slots[count-2]=i; fds[count++]=(struct pollfd){.fd=flows[i].fd,.events=POLLIN}; }
        int r=poll(fds,(nfds_t)count,5000); if (r<0) { if (errno==EINTR) continue; break; }
        time_t now=time(NULL);
        for (int j=2;j<count;j++) {
            int i=slots[j-2]; if (!flows[i].active || flows[i].fd!=fds[j].fd) continue;
            if (fds[j].revents&POLLIN) {
                uint8_t reply[UDP_HEADER_LEN+UDP_PAYLOAD_MAX]; ssize_t n=recv(flows[i].fd,reply+UDP_HEADER_LEN,UDP_PAYLOAD_MAX,0);
                if (n>=0) {
                    memcpy(reply,"UDP1",4); memcpy(reply+4,secret,TOKEN_LEN);
                    memcpy(reply+4+TOKEN_LEN,&flows[i].destination,4); memcpy(reply+4+TOKEN_LEN+4,&flows[i].port,2);
                    (void)sendto(dns,reply,UDP_HEADER_LEN+(size_t)n,0,(struct sockaddr *)&flows[i].client,sizeof(flows[i].client)); flows[i].last=now; flows[i].order=++flow_order;
                }
            }
            if (fds[j].revents&(POLLERR|POLLNVAL) || now-flows[i].last>120) close_flow(i);
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
            } else if (direct_mode && !memcmp(data,"UDP1",4) && n>UDP_HEADER_LEN) {
                uint32_t address; uint16_t port; memcpy(&address,data+4+TOKEN_LEN,4); memcpy(&port,data+4+TOKEN_LEN+4,2);
                if (!port) continue; int slot=get_flow(peer,address,port);
                if (slot>=0) { ssize_t sent=send(flows[slot].fd,data+UDP_HEADER_LEN,(size_t)n-UDP_HEADER_LEN,0); if (sent>=0) { flows[slot].last=now; flows[slot].order=++flow_order; } }
            }
        }
    }
    close(tcp); close(dns); return 0;
}
