/* Local socket tests for the user-mode network core's relay framing. */
#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
struct socket {
    int s; uint8_t ns_relay_header[42]; unsigned ns_relay_offset; bool ns_relay_pending;
    union { struct sockaddr_in sin; } fhost;
};
#define so_ffamily fhost.sin.sin_family
#define so_faddr fhost.sin.sin_addr
#define so_fport fhost.sin.sin_port
#include "../ThirdParty/libslirp/src/networksharer_relay.h"
static int server(int type, uint16_t *port) {
    int fd=socket(AF_INET,type,0); assert(fd>=0);
    struct sockaddr_in a=ns_local(0); assert(bind(fd,(struct sockaddr *)&a,sizeof(a))==0);
    socklen_t n=sizeof(a); assert(getsockname(fd,(struct sockaddr *)&a,&n)==0); *port=ntohs(a.sin_port);
    if (type==SOCK_STREAM) assert(listen(fd,4)==0);
    return fd;
}
static void set_port(const char *key,uint16_t port) { char p[8]; snprintf(p,sizeof(p),"%u",port); assert(!setenv(key,p,1)); }
static struct socket target(int type) {
    struct socket s={0}; s.s=socket(AF_INET,type,0); assert(s.s>=0);
    s.so_ffamily=AF_INET; s.so_fport=htons(443); assert(inet_pton(AF_INET,"8.8.8.8",&s.so_faddr)==1);
    return s;
}
int main(void) {
    uint16_t tcpport,udpport; int tcp=server(SOCK_STREAM,&tcpport),udp=server(SOCK_DGRAM,&udpport);
    set_port("NAPTD_RELAY_TCP",tcpport); set_port("NAPTD_RELAY_DNS",udpport);
    setenv("NAPTD_RELAY_TOKEN","0123456789abcdef0123456789abcdef",1); setenv("NAPTD_RELAY_MODE","direct",1);
    struct socket s=target(SOCK_STREAM); assert(!fcntl(s.s,F_SETFL,O_NONBLOCK));
    int r=ns_tcp_start(&s); assert(r==-1 && errno==EINPROGRESS);
    struct pollfd p={.fd=s.s,.events=POLLOUT}; assert(poll(&p,1,1000)==1); assert(ns_tcp_finish(&s)==1);
    int accepted=accept(tcp,NULL,NULL); assert(accepted>=0); uint8_t b[200]={0}; assert(read(accepted,b,42)==42);
    assert(!memcmp(b,"NAT10123456789abcdef0123456789abcdef",36)); assert(!memcmp(b+36,&s.so_faddr.s_addr,4)); assert(!memcmp(b+40,&s.so_fport,2));
    close(accepted); close(s.s);
    s=target(SOCK_DGRAM); const char *message="test"; assert(ns_udp_send(&s,message,4)==4);
    struct sockaddr_in peer={0}; socklen_t peerlen=sizeof(peer); assert(recvfrom(udp,b,sizeof(b),0,(struct sockaddr *)&peer,&peerlen)==46);
    assert(!memcmp(b,"UDP1",4) && !memcmp(b+42,"test",4));
    assert(sendto(udp,b,46,0,(struct sockaddr *)&peer,peerlen)==46);
    struct sockaddr_storage source={0}; socklen_t slen=sizeof(source); char result[32]={0};
    assert(ns_udp_recv(&s,result,sizeof(result),&source,&slen)==4 && !memcmp(result,"test",4));
    struct sockaddr_in *a=(struct sockaddr_in *)&source; assert(a->sin_addr.s_addr==s.so_faddr.s_addr && a->sin_port==s.so_fport);
    /* The gateway owns UDP egress; the framing layer must not reject upstream mode. */
    setenv("NAPTD_RELAY_MODE","socks5",1); assert(ns_udp_send(&s,message,4)==4);
    peerlen=sizeof(peer); assert(recvfrom(udp,b,sizeof(b),0,(struct sockaddr *)&peer,&peerlen)==46);
    assert(!memcmp(b,"UDP1",4) && !memcmp(b+42,"test",4));
    assert(sendto(udp,b,46,0,(struct sockaddr *)&peer,peerlen)==46);
    assert(ns_udp_recv(&s,result,sizeof(result),&source,&slen)==4 && !memcmp(result,"test",4));
    setenv("NAPTD_RELAY_MODE","direct",1);
    s.so_fport=htons(53); uint8_t query[12]={0}; assert(ns_udp_send(&s,query,sizeof(query))==12);
    peerlen=sizeof(peer); assert(recvfrom(udp,b,sizeof(b),0,(struct sockaddr *)&peer,&peerlen)==48 && !memcmp(b,"DNS1",4));
    b[4]^=1; assert(sendto(udp,b,48,0,(struct sockaddr *)&peer,peerlen)==48);
    assert(ns_udp_recv(&s,result,sizeof(result),&source,&slen)<0 && errno==EAGAIN);
    b[4]^=1; assert(sendto(udp,b,48,0,(struct sockaddr *)&peer,peerlen)==48);
    assert(ns_udp_recv(&s,result,sizeof(result),&source,&slen)==12);
    unsetenv("NAPTD_RELAY_TOKEN"); assert(ns_udp_send(&s,query,sizeof(query))<0 && errno==EACCES);
    close(s.s); close(tcp); close(udp); puts("TCP framing, UDP, DNS, authentication and proxy fail-closed checks passed");
    return 0;
}
