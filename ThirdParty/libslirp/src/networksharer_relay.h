/* Network Sharer local relay transport. Outbound traffic fails closed. */
#ifndef NETWORKSHARER_RELAY_H
#define NETWORKSHARER_RELAY_H
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#define NS_TOKEN_LEN 32
#define NS_DNS_HEADER 36
#define NS_UDP_HEADER 42
#define NS_UDP_MAX 60000

static int ns_relay_config(uint16_t *tcp, uint16_t *udp, const char **token, int *direct) {
    const char *t=getenv("NAPTD_RELAY_TCP"), *u=getenv("NAPTD_RELAY_DNS");
    const char *s=getenv("NAPTD_RELAY_TOKEN"), *mode=getenv("NAPTD_RELAY_MODE");
    if (!t || !u || !s || strlen(s)!=NS_TOKEN_LEN || !mode ||
        (strcmp(mode,"direct") && strcmp(mode,"socks5"))) { errno=EACCES; return -1; }
    for (size_t i=0;i<NS_TOKEN_LEN;i++) if (!((s[i]>='0' && s[i]<='9') || (s[i]>='a' && s[i]<='f'))) { errno=EACCES; return -1; }
    char *e1=NULL,*e2=NULL; unsigned long x=strtoul(t,&e1,10),y=strtoul(u,&e2,10);
    if (!*t || *e1 || !*u || *e2 || x<1 || x>65535 || y<1 || y>65535) { errno=EACCES; return -1; }
    *tcp=(uint16_t)x; *udp=(uint16_t)y; *token=s; *direct=!strcmp(mode,"direct"); return 0;
}
static struct sockaddr_in ns_local(uint16_t port) {
    struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(port),.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
#ifdef __APPLE__
    a.sin_len=sizeof(a);
#endif
    return a;
}
static int ns_token_equal(const uint8_t *a,const char *b) {
    unsigned char d=0; for (size_t i=0;i<NS_TOKEN_LEN;i++) d|=(unsigned char)(a[i]^b[i]); return d==0;
}
static int ns_tcp_start(struct socket *so) {
    uint16_t tcp,udp; const char *token; int direct;
    if (so->so_ffamily!=AF_INET || ns_relay_config(&tcp,&udp,&token,&direct)) { errno=EACCES; return -1; }
    (void)udp; (void)direct;
    uint32_t ip=ntohl(so->so_faddr.s_addr);
    if ((ip>>24)==127 || (ip>>24)==0 || (ip>>24)>=224 || !so->so_fport) { errno=EACCES; return -1; }
    memcpy(so->ns_relay_header,"NAT1",4); memcpy(so->ns_relay_header+4,token,NS_TOKEN_LEN);
    memcpy(so->ns_relay_header+36,&so->so_faddr.s_addr,4); memcpy(so->ns_relay_header+40,&so->so_fport,2);
    so->ns_relay_offset=0; so->ns_relay_pending=1;
    struct sockaddr_in target=ns_local(tcp);
    int one=1; (void)setsockopt(so->s,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one));
    int r=connect(so->s,(struct sockaddr *)&target,sizeof(target));
    if (r==0) { errno=EINPROGRESS; return -1; }
    return r;
}
/* Called on POLLOUT until the entire header has been sent. */
static int ns_tcp_finish(struct socket *so) {
    if (!so->ns_relay_pending) return 1;
    int error=0; socklen_t len=sizeof(error);
    if (getsockopt(so->s,SOL_SOCKET,SO_ERROR,&error,&len)<0) return -1;
    if (error) { errno=error; return -1; }
    while (so->ns_relay_offset<NS_UDP_HEADER) {
        ssize_t n=send(so->s,so->ns_relay_header+so->ns_relay_offset,NS_UDP_HEADER-so->ns_relay_offset,0);
        if (n>0) { so->ns_relay_offset+=(unsigned)n; continue; }
        if (n<0 && errno==EINTR) continue;
        if (n<0 && (errno==EAGAIN || errno==EWOULDBLOCK || errno==ENOTCONN)) return 0;
        if (!n) errno=EPIPE;
        return -1;
    }
    so->ns_relay_pending=0; return 1;
}
static int ns_udp_send(struct socket *so,const void *data,size_t size) {
    uint16_t tcp,udp; const char *token; int direct;
    if (so->so_ffamily!=AF_INET || ns_relay_config(&tcp,&udp,&token,&direct)) { errno=EACCES; return -1; }
    (void)tcp;
    uint32_t ip=ntohl(so->so_faddr.s_addr);
    if ((ip>>24)==127 || (ip>>24)==0 || (ip>>24)>=224 || !so->so_fport || size>NS_UDP_MAX) { errno=EACCES; return -1; }
    int dns=ntohs(so->so_fport)==53;
    if (dns && (size<12 || size>4096)) { errno=EMSGSIZE; return -1; }
    if (!dns && size>NS_UDP_MAX-10) { errno=EMSGSIZE; return -1; }
    uint8_t header[NS_UDP_HEADER]; memcpy(header,dns?"DNS1":"UDP1",4); memcpy(header+4,token,NS_TOKEN_LEN);
    size_t hlen=dns?NS_DNS_HEADER:NS_UDP_HEADER;
    if (!dns) { memcpy(header+36,&so->so_faddr.s_addr,4); memcpy(header+40,&so->so_fport,2); }
    struct sockaddr_in target=ns_local(udp);
    struct iovec iov[2]={{.iov_base=header,.iov_len=hlen},{.iov_base=(void *)data,.iov_len=size}};
    struct msghdr msg={.msg_name=&target,.msg_namelen=sizeof(target),.msg_iov=iov,.msg_iovlen=2};
    ssize_t sent=sendmsg(so->s,&msg,0);
    if (sent<0) return -1;
    if ((size_t)sent!=hlen+size) { errno=EIO; return -1; }
    return (int)size;
}
static int ns_udp_recv(struct socket *so,void *buf,size_t size,struct sockaddr_storage *addr,socklen_t *addrlen) {
    uint16_t tcp,udp; const char *token; int direct;
    if (ns_relay_config(&tcp,&udp,&token,&direct)) { errno=EACCES; return -1; }
    (void)tcp;
    uint8_t packet[NS_UDP_HEADER+NS_UDP_MAX]; struct sockaddr_in peer={0}; socklen_t plen=sizeof(peer);
    ssize_t n=recvfrom(so->s,packet,sizeof(packet),0,(struct sockaddr *)&peer,&plen);
    if (n<0) return -1;
    if (n<NS_DNS_HEADER || peer.sin_family!=AF_INET || peer.sin_addr.s_addr!=htonl(INADDR_LOOPBACK) ||
        peer.sin_port!=htons(udp) || !ns_token_equal(packet+4,token)) { errno=EAGAIN; return -1; }
    struct sockaddr_in source={.sin_family=AF_INET};
#ifdef __APPLE__
    source.sin_len=sizeof(source);
#endif
    size_t hlen;
    if (!memcmp(packet,"DNS1",4) && so->so_fport==htons(53)) {
        hlen=NS_DNS_HEADER; source=so->fhost.sin;
    } else if (n>=NS_UDP_HEADER && !memcmp(packet,"UDP1",4)) {
        hlen=NS_UDP_HEADER; memcpy(&source.sin_addr.s_addr,packet+36,4); memcpy(&source.sin_port,packet+40,2);
    } else { errno=EAGAIN; return -1; }
    if ((size_t)n-hlen>size) { errno=EMSGSIZE; return -1; }
    memcpy(buf,packet+hlen,(size_t)n-hlen); memset(addr,0,sizeof(*addr)); memcpy(addr,&source,sizeof(source)); *addrlen=sizeof(source);
    return (int)((size_t)n-hlen);
}
#endif
