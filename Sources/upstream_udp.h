/* SOCKS5 UDP transport to the selected local proxy. No direct fallback.
 * Included after proxy_socket/read_all/write_all in socks_gateway.c. */
#ifndef LANSHARER_UPSTREAM_UDP_H
#define LANSHARER_UPSTREAM_UDP_H
#include <sys/uio.h>

typedef struct { int fd, control; } proxy_udp;
static const proxy_udp proxy_udp_empty = { .fd=-1, .control=-1 };
static pthread_mutex_t udp_open_lock=PTHREAD_MUTEX_INITIALIZER;
static time_t udp_open_second;
static unsigned udp_open_count;

static int udp_open_allowed(void) {
    struct timespec now; clock_gettime(CLOCK_MONOTONIC,&now);
    pthread_mutex_lock(&udp_open_lock);
    if (now.tv_sec!=udp_open_second) { udp_open_second=now.tv_sec; udp_open_count=0; }
    int ok=udp_open_count<16;
    if (ok) udp_open_count++;
    pthread_mutex_unlock(&udp_open_lock);
    return ok;
}
static void proxy_udp_close(proxy_udp *transport) {
    if (transport->fd>=0) close(transport->fd);
    if (transport->control>=0) close(transport->control);
    *transport=proxy_udp_empty;
}
static int control_alive(int fd) {
    struct pollfd p={.fd=fd,.events=POLLIN};
    int result=poll(&p,1,0);
    /* No application bytes are valid on an established SOCKS control stream. */
    return result==0 || (result<0 && errno==EINTR);
}
static int proxy_udp_open(proxy_udp *transport) {
    *transport=proxy_udp_empty;
    if (!udp_open_allowed()) { errno=EAGAIN; return 0; }
    int fd=socket(AF_INET,SOCK_DGRAM,0);
    if (fd<0) return 0;
    transport->fd=fd;
    struct sockaddr_in local={.sin_len=sizeof(local),.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    socklen_t size=sizeof(local);
    if (bind(fd,(struct sockaddr *)&local,sizeof(local)) || getsockname(fd,(struct sockaddr *)&local,&size)) goto fail;
    transport->control=proxy_socket(2);
    if (transport->control<0) goto fail;
    /* Some upstreams reject a zero port: bind first, advertise the actual endpoint. */
    uint8_t request[10]={5,3,0,1},response[4];
    memcpy(request+4,&local.sin_addr.s_addr,4); memcpy(request+8,&local.sin_port,2);
    if (!write_all(transport->control,request,10) || !read_all(transport->control,response,4) ||
        response[0]!=5 || response[1]!=0 || response[2]!=0) goto fail;
    struct sockaddr_in relay={.sin_len=sizeof(relay),.sin_family=AF_INET};
    if (response[3]==1) {
        if (!read_all(transport->control,&relay.sin_addr.s_addr,4)) goto fail;
        if (!relay.sin_addr.s_addr) relay.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    } else if (response[3]==3) {
        uint8_t length=0; char name[256];
        if (!read_all(transport->control,&length,1) || !length || !read_all(transport->control,name,length)) goto fail;
        name[length]=0;
        if (length==9 && !memcmp(name,"localhost",9)) relay.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        else if (strlen(name)!=length || inet_pton(AF_INET,name,&relay.sin_addr)!=1) goto fail;
    } else goto fail;
    /* Keep the existing localhost-only outbound sandbox guarantee. */
    if ((ntohl(relay.sin_addr.s_addr)>>24)!=127 || !read_all(transport->control,&relay.sin_port,2) || !relay.sin_port) goto fail;
    if (connect(fd,(struct sockaddr *)&relay,sizeof(relay))) goto fail;
    int flags=fcntl(fd,F_GETFL,0);
    if (flags<0 || fcntl(fd,F_SETFL,flags|O_NONBLOCK)) goto fail;
    return 1;
fail:
    proxy_udp_close(transport); return 0;
}
/* Address and port are always in network order. */
static ssize_t proxy_udp_send(proxy_udp *transport,uint32_t address,uint16_t port,const void *data,size_t size) {
    if (transport->fd<0 || size>UDP_PAYLOAD_MAX || !control_alive(transport->control)) { errno=ENOTCONN; return -1; }
    uint8_t header[10]={0,0,0,1}; memcpy(header+4,&address,4); memcpy(header+8,&port,2);
    struct iovec iov[2]={{.iov_base=header,.iov_len=10},{.iov_base=(void *)data,.iov_len=size}};
    struct msghdr message={.msg_iov=iov,.msg_iovlen=2};
    ssize_t n=sendmsg(transport->fd,&message,0);
    if (n<0) return -1;
    if ((size_t)n!=size+10) { errno=EIO; return -1; }
    return (ssize_t)size;
}
static ssize_t proxy_udp_receive(proxy_udp *transport,uint32_t *address,uint16_t *port,void *data,size_t capacity) {
    uint8_t packet[10+UDP_PAYLOAD_MAX];
    struct iovec iov={.iov_base=packet,.iov_len=sizeof(packet)};
    struct msghdr message={.msg_iov=&iov,.msg_iovlen=1};
    ssize_t n=recvmsg(transport->fd,&message,0);
    if (n<0) return -1;
    /* connected UDP already filters the relay's source IP and port. */
    if ((message.msg_flags&MSG_TRUNC) || n<10 || packet[0] || packet[1] || packet[2] || packet[3]!=1 || (size_t)n-10>capacity) {
        errno=EAGAIN; return -1;
    }
    memcpy(address,packet+4,4); memcpy(port,packet+8,2);
    if (!*port) { errno=EAGAIN; return -1; }
    memcpy(data,packet+10,(size_t)n-10);
    return n-10;
}
#endif
