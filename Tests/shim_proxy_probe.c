#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static uint16_t u16(const uint8_t *p) { return (uint16_t)((p[0]<<8)|p[1]); }
static size_t skipname(const uint8_t *p,size_t n,size_t i) {
    while (i<n) { uint8_t c=p[i++]; if ((c&0xc0)==0xc0) return i+1; if (!c) return i; i+=c; }
    return n+1;
}
int main(void) {
    setvbuf(stdout,NULL,_IONBF,0);
    uint8_t q[]={0x51,0x93,1,0,0,1,0,0,0,0,0,0,7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
    int udp=socket(AF_INET,SOCK_DGRAM,0); if (udp<0) return 2;
    struct timeval tv={.tv_sec=12}; (void)setsockopt(udp,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
    struct sockaddr_in dns={.sin_len=sizeof(dns),.sin_family=AF_INET,.sin_port=htons(53),.sin_addr.s_addr=inet_addr("8.8.8.8")};
    struct iovec io={.iov_base=q,.iov_len=sizeof(q)}; struct msghdr out={.msg_name=&dns,.msg_namelen=sizeof(dns),.msg_iov=&io,.msg_iovlen=1};
    if (sendmsg(udp,&out,0)!=(ssize_t)sizeof(q)) { perror("dns_sendmsg"); return 3; }
    uint8_t reply[4096]; struct sockaddr_in from={0}; struct iovec rio={.iov_base=reply,.iov_len=sizeof(reply)};
    struct msghdr in={.msg_name=&from,.msg_namelen=sizeof(from),.msg_iov=&rio,.msg_iovlen=1};
    ssize_t len=recvmsg(udp,&in,0); if (len<12 || reply[0]!=q[0] || reply[1]!=q[1]) { perror("dns_recvmsg"); return 4; }
    if (from.sin_addr.s_addr!=dns.sin_addr.s_addr || from.sin_port!=dns.sin_port) { puts("dns_source_mismatch"); return 5; }
    size_t off=12; unsigned qd=u16(reply+4),an=u16(reply+6); uint32_t dest=0;
    for (unsigned i=0;i<qd;i++) { off=skipname(reply,(size_t)len,off); if (off+4>(size_t)len) return 6; off+=4; }
    for (unsigned i=0;i<an;i++) {
        off=skipname(reply,(size_t)len,off); if (off+10>(size_t)len) return 6;
        uint16_t type=u16(reply+off),cls=u16(reply+off+2),n=u16(reply+off+8); off+=10;
        if (off+n>(size_t)len) return 6; if (type==1 && cls==1 && n==4) { memcpy(&dest,reply+off,4); break; } off+=n;
    }
    if (!dest) return 7;
    puts("dns_proxy_and_source:ok");
    struct sockaddr_in blocked={.sin_len=sizeof(blocked),.sin_family=AF_INET,.sin_port=htons(44444),.sin_addr.s_addr=inet_addr("1.1.1.1")};
    out.msg_name=&blocked;
    if (sendmsg(udp,&out,0)>=0) { puts("udp_leaked"); return 8; }
    puts("non_dns_udp_blocked:ok"); close(udp);
    int tcp=socket(AF_INET,SOCK_STREAM,0); if (tcp<0) return 9;
    int fl=fcntl(tcp,F_GETFL,0); if (fl<0 || fcntl(tcp,F_SETFL,fl|O_NONBLOCK)) return 10;
    struct sockaddr_in target={.sin_len=sizeof(target),.sin_family=AF_INET,.sin_port=htons(80),.sin_addr.s_addr=dest};
    if (connect(tcp,(struct sockaddr *)&target,sizeof(target))) { perror("tcp_connect"); return 11; }
    const char request[]="GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    if (send(tcp,request,sizeof(request)-1,0)!=(ssize_t)(sizeof(request)-1)) { perror("tcp_send"); return 12; }
    struct pollfd p={.fd=tcp,.events=POLLIN}; if (poll(&p,1,12000)<=0) { puts("tcp_timeout"); return 13; }
    char response[128]={0}; ssize_t n=recv(tcp,response,sizeof(response)-1,0);
    if (n<12 || strncmp(response,"HTTP/1.1 200",12)) { printf("tcp_bad_response:%s\n",response); return 14; }
    puts("tcp_proxy_nonblocking:ok"); close(tcp); return 0;
}
