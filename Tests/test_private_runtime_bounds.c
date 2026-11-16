/* Exercise the actual packet interposition functions under AddressSanitizer. */
#define NETWORKSHARER_TEST_NO_INTERPOSE 1
#include "../Sources/private_runtime.c"
#include <assert.h>

int main(void) {
    const char *token="0123456789abcdef0123456789abcdef";
    setenv("NAPTD_RELAY_TOKEN",token,1);
    setenv("NAPTD_RELAY_TCP","10101",1);
    setenv("NAPTD_RELAY_DNS","10102",1);
    setenv("NAPTD_RELAY_MODE","direct",1);
    int pair[2]; assert(socketpair(AF_UNIX,SOCK_DGRAM,0,pair)==0);
    struct sockaddr_in destination={.sin_len=sizeof(destination),.sin_family=AF_INET,.sin_port=htons(53),.sin_addr.s_addr=inet_addr("192.0.2.1")};
    remember_dns(pair[0],&destination);
    unsigned char packet[UDP_HEADER_LEN+UDP_PAYLOAD_MAX];
    memset(packet,0,sizeof(packet)); memcpy(packet,"DNS1",4); memcpy(packet+4,token,RELAY_TOKEN_LEN);
    for (size_t i=DNS_HEADER_LEN;i<sizeof(packet);i++) packet[i]=(unsigned char)i;
    unsigned char a[9],b[7]; memset(a,0xa5,sizeof(a)); memset(b,0xa5,sizeof(b));
    struct iovec iov[2]={{a+1,7},{b+1,5}};
    struct msghdr msg={.msg_iov=iov,.msg_iovlen=2};
    assert(send(pair[1],packet,DNS_HEADER_LEN+25,0)==DNS_HEADER_LEN+25);
    assert(mapped_recvmsg(pair[0],&msg,0)==12 && (msg.msg_flags&MSG_TRUNC));
    assert(a[0]==0xa5 && a[8]==0xa5 && b[0]==0xa5 && b[6]==0xa5);
    for (size_t i=0;i<7;i++) assert(a[i+1]==packet[DNS_HEADER_LEN+i]);
    for (size_t i=0;i<5;i++) assert(b[i+1]==packet[DNS_HEADER_LEN+7+i]);
    packet[4]^=1;
    assert(send(pair[1],packet,DNS_HEADER_LEN+3,0)==DNS_HEADER_LEN+3);
    errno=0; assert(mapped_recvmsg(pair[0],&msg,0)==-1 && errno==EPROTO);
    packet[4]^=1;
    assert(send(pair[1],packet,DNS_HEADER_LEN-1,0)==DNS_HEADER_LEN-1);
    errno=0; assert(mapped_recvmsg(pair[0],&msg,0)==-1 && errno==EPROTO);
    struct msghdr too_many={.msg_name=&destination,.msg_namelen=sizeof(destination),.msg_iov=iov,.msg_iovlen=33};
    errno=0; assert(mapped_sendmsg(pair[0],&too_many,0)==-1 && errno==EMSGSIZE);
    assert(mapped_close(pair[0])==0 && !is_dns_fd(pair[0]));
    assert(close(pair[1])==0);
    puts("Packet truncation, invalid headers, iovec bounds and descriptor reuse passed");
    return 0;
}
