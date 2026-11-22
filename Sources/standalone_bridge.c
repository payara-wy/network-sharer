/* Experimental independent Ethernet-to-slirp bridge.
 * The --fd mode is for isolated, unprivileged packet tests only. */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <libslirp.h>
#include <networksharer_hosts.h>
#include "parent_guard.h"
#include "standalone_leases.h"

#define MAX_FRAME 65536
#define MAX_POLL 4096
struct bridge {
    int fd, is_bpf;
    struct pollfd pollfds[MAX_POLL];
    int count;
    Slirp *slirp;
    struct lease_store *leases;
    int lease_error;
};
static volatile sig_atomic_t stopping;
static void stop(int sig) { (void)sig; stopping=1; }
/* Reject DHCP from any local host interface, including one that appeared
 * after a cable replug. Do not change its system network configuration. */
static int host_dhcp_request(const uint8_t *p,size_t len) {
    if (len<14+20+8+34 || p[12]!=8 || p[13]!=0 || (p[14]>>4)!=4 || p[23]!=17) return 0;
    size_t ihl=(size_t)(p[14]&15)*4;
    if (ihl<20 || len<14+ihl+8+34) return 0;
    /* Noninitial fragments cannot contain a valid UDP header. */
    if ((p[20]&0x1f) || p[21]) return 0;
    const uint8_t *udp=p+14+ihl,*bootp=udp+8;
    if (udp[0]!=0 || udp[1]!=68 || udp[2]!=0 || udp[3]!=67 ||
        bootp[0]!=1 || bootp[1]!=1 || bootp[2]!=6) return 0;
    return ns_host_mac_excluded(p+6,bootp+28);
}
static int is_dhcp_reply(const uint8_t *p,size_t len) {
    if (len<14+20+8 || p[12]!=8 || p[13]!=0) return 0;
    size_t ihl=(size_t)(p[14]&15)*4;
    if (ihl<20 || len<14+ihl+8 || p[23]!=17) return 0;
    const uint8_t *udp=p+14+ihl;
    return udp[0]==0 && udp[1]==67 && udp[2]==0 && udp[3]==68;
}
static slirp_ssize_t send_packet(const void *buf,size_t len,void *opaque) {
    struct bridge *b=opaque;
    /* Persist before transmitting an offer or ACK, including if the GUI dies. */
    if (b->leases && is_dhcp_reply(buf,len) && !lease_commit(b->leases,b->slirp)) {
        b->lease_error=1; stopping=1; return -1;
    }
    ssize_t n=b->is_bpf ? write(b->fd,buf,len) : send(b->fd,buf,len,0);
    return n<0 ? -1 : n;
}
static void guest_error(const char *msg,void *opaque) { (void)opaque; fprintf(stderr,"guest error: %.200s\n",msg); }
static int64_t clock_ns(void *opaque) {
    (void)opaque; struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC,&ts)) return 0;
    return (int64_t)ts.tv_sec*1000000000LL+ts.tv_nsec;
}
/* IPv6 is disabled, so the RA timer is never scheduled. */
static void *timer_new(SlirpTimerCb cb,void *cb_opaque,void *opaque) { (void)cb;(void)cb_opaque;(void)opaque; return NULL; }
static void timer_free(void *timer,void *opaque) { (void)timer;(void)opaque; }
static void timer_mod(void *timer,int64_t when,void *opaque) { (void)timer;(void)when;(void)opaque; }
static void notify(void *opaque) { (void)opaque; }
static void reg_socket(slirp_os_socket fd,void *opaque) { (void)fd;(void)opaque; }
static int add_poll(slirp_os_socket fd,int events,void *opaque) {
    struct bridge *b=opaque;
    if (b->count>=MAX_POLL) return -1;
    int i=b->count++; b->pollfds[i].fd=fd; b->pollfds[i].events=0; b->pollfds[i].revents=0;
    if (events&SLIRP_POLL_IN) b->pollfds[i].events|=POLLIN;
    if (events&SLIRP_POLL_OUT) b->pollfds[i].events|=POLLOUT;
    if (events&SLIRP_POLL_PRI) b->pollfds[i].events|=POLLPRI;
    return i;
}
static int get_revents(int i,void *opaque) {
    struct bridge *b=opaque;
    if (i<0 || i>=b->count) return SLIRP_POLL_ERR;
    int e=b->pollfds[i].revents, r=0;
    if (e&POLLIN) r|=SLIRP_POLL_IN;
    if (e&POLLOUT) r|=SLIRP_POLL_OUT;
    if (e&POLLPRI) r|=SLIRP_POLL_PRI;
    if (e&POLLERR) r|=SLIRP_POLL_ERR;
    if (e&(POLLHUP|POLLNVAL)) r|=SLIRP_POLL_HUP;
    return r;
}
static int open_bpf(const char *name) {
    int fd=-1;
    for (int i=0;i<256;i++) {
        char path[32]; snprintf(path,sizeof(path),"/dev/bpf%d",i);
        fd=open(path,O_RDWR|O_CLOEXEC); if (fd>=0) break;
        if (errno!=EBUSY) return -1;
    }
    if (fd<0) return -1;
    struct ifreq req={0}; unsigned one=1,zero=0;
    if (strlen(name)>=sizeof(req.ifr_name)) { close(fd); errno=EINVAL; return -1; }
    strcpy(req.ifr_name,name);
    if (ioctl(fd,BIOCSETIF,&req) || ioctl(fd,BIOCIMMEDIATE,&one) ||
        ioctl(fd,BIOCSHDRCMPLT,&one) || ioctl(fd,BIOCPROMISC,NULL) ||
        ioctl(fd,BIOCSSEESENT,&zero)) { close(fd); return -1; }
    return fd;
}
static void handle_bpf(Slirp *slirp,const uint8_t *data,size_t len) {
    const size_t minhdr=offsetof(struct bpf_hdr,bh_hdrlen)+sizeof(((struct bpf_hdr *)0)->bh_hdrlen);
    for (size_t off=0;off<=len && len-off>=minhdr;) {
        struct bpf_hdr h={0}; memcpy(&h,data+off,minhdr);
        if (h.bh_hdrlen<minhdr || h.bh_hdrlen>len-off || h.bh_caplen>len-off-h.bh_hdrlen) break;
        const uint8_t *frame=data+off+h.bh_hdrlen;
        if (h.bh_caplen==h.bh_datalen && h.bh_caplen>=14 && h.bh_caplen<=MAX_FRAME &&
            !host_dhcp_request(frame,h.bh_caplen))
            slirp_input(slirp,frame,(int)h.bh_caplen);
        size_t step=BPF_WORDALIGN((size_t)h.bh_hdrlen+h.bh_caplen);
        if (!step || step>len-off) break;
        off+=step;
    }
}
int main(int argc,char **argv) {
    if (!hotspot_start_parent_guard()) return 5;
    if ((argc!=3 && argc!=5) || (strcmp(argv[1],"--fd") && strcmp(argv[1],"--interface")) ||
        (argc==5 && strcmp(argv[3],"--lease-dir"))) {
        fputs("usage: standalone_bridge (--fd n | --interface fethN) [--lease-dir directory]\n",stderr); return 2;
    }
    struct bridge b={0};
    if (!strcmp(argv[1],"--fd")) {
        char *end=NULL; long fd=strtol(argv[2],&end,10);
        if (!end || *end || fd<0 || fd>INT32_MAX) return 2;
        b.fd=(int)fd;
    } else {
        if (strncmp(argv[2],"feth",4) || !argv[2][4] || strspn(argv[2]+4,"0123456789")!=strlen(argv[2]+4)) return 2;
        b.fd=open_bpf(argv[2]); b.is_bpf=1;
        if (b.fd<0) { perror("bpf"); return 3; }
    }
    unsigned size=MAX_FRAME;
    if (b.is_bpf && ioctl(b.fd,BIOCGBLEN,&size)) { perror("BIOCGBLEN"); return 3; }
    if (size<2048 || size>1024*1024) return 3;
    uint8_t *buffer=malloc(size); if (!buffer) return 3;
    SlirpCb cb={.send_packet=send_packet,.guest_error=guest_error,.clock_get_ns=clock_ns,
        .timer_new=timer_new,.timer_free=timer_free,.timer_mod=timer_mod,.notify=notify,
        .register_poll_socket=reg_socket,.unregister_poll_socket=reg_socket};
    SlirpConfig cfg={.version=6,.in_enabled=true,.in6_enabled=false,.disable_host_loopback=true,.disable_dns=true,.enable_emu=false};
    inet_pton(AF_INET,"172.30.79.0",&cfg.vnetwork);
    inet_pton(AF_INET,"255.255.255.0",&cfg.vnetmask);
    inet_pton(AF_INET,"172.30.79.1",&cfg.vhost);
    inet_pton(AF_INET,"172.30.79.10",&cfg.vdhcp_start);
    const char *dns=getenv("NAPTD_DNS_SERVER");
    if (!dns || !*dns) dns="172.30.79.2";
    if (inet_pton(AF_INET,dns,&cfg.vnameserver)!=1) { free(buffer); close(b.fd); return 2; }
    Slirp *slirp=slirp_new(&cfg,&cb,&b);
    if (!slirp) { free(buffer); return 4; }
    b.slirp=slirp;
    if (argc==5 && !(b.leases=lease_open(argv[4],slirp))) {
        perror("lease store"); slirp_cleanup(slirp); free(buffer); close(b.fd); return 4;
    }
    signal(SIGINT,stop); signal(SIGTERM,stop); signal(SIGPIPE,SIG_IGN);
    fputs("bridge_ready\n",stdout); fflush(stdout);
    while (!stopping) {
        b.count=1; b.pollfds[0]=(struct pollfd){.fd=b.fd,.events=POLLIN};
        uint32_t timeout=1000; slirp_pollfds_fill_socket(slirp,&timeout,add_poll,&b);
        if (timeout>1000) timeout=1000;
        int ready=poll(b.pollfds,(nfds_t)b.count,(int)timeout);
        if (ready<0 && errno!=EINTR) break;
        if (ready>0 && (b.pollfds[0].revents&POLLIN)) {
            ssize_t n=read(b.fd,buffer,size);
            if (n>0) { if (b.is_bpf) handle_bpf(slirp,buffer,(size_t)n); else if (!host_dhcp_request(buffer,(size_t)n)) slirp_input(slirp,buffer,(int)n); }
            else if (n==0 || errno!=EINTR) break;
        }
        slirp_pollfds_poll(slirp,ready<0,get_revents,&b);
    }
    lease_close(b.leases); slirp_cleanup(slirp); free(buffer); close(b.fd); return b.lease_error ? 5 : 0;
}
