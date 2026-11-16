/* Simulate a kernel reporting a datagram larger than the supplied receive buffer. */
#define NETWORKSHARER_TEST_NO_INTERPOSE 1
#define recvmsg test_recvmsg
#include "../Sources/private_runtime.c"
#undef recvmsg
#include <assert.h>

ssize_t test_recvmsg(int fd,struct msghdr *message,int flags) {
    (void)fd; (void)flags;
    unsigned char *p=message->msg_iov[0].iov_base; size_t n=message->msg_iov[0].iov_len;
    memset(p,0x31,n); memcpy(p,"DNS1",4); memcpy(p+4,"0123456789abcdef0123456789abcdef",32);
    message->msg_flags=MSG_TRUNC;
    return (ssize_t)n+1234;
}
int main(void) {
    setenv("NAPTD_RELAY_TOKEN","0123456789abcdef0123456789abcdef",1);
    setenv("NAPTD_RELAY_TCP","10101",1); setenv("NAPTD_RELAY_DNS","10102",1);
    int pair[2]; assert(socketpair(AF_UNIX,SOCK_DGRAM,0,pair)==0);
    struct sockaddr_in destination={.sin_len=sizeof(destination),.sin_family=AF_INET,.sin_port=htons(53),.sin_addr.s_addr=inet_addr("192.0.2.1")};
    remember_dns(pair[0],&destination);
    unsigned char output[UDP_HEADER_LEN+UDP_PAYLOAD_MAX+2000]; memset(output,0xa5,sizeof(output));
    struct iovec iov={.iov_base=output,.iov_len=sizeof(output)};
    struct msghdr message={.msg_iov=&iov,.msg_iovlen=1};
    ssize_t n=mapped_recvmsg(pair[0],&message,0);
    assert(n==(ssize_t)(UDP_HEADER_LEN+UDP_PAYLOAD_MAX-DNS_HEADER_LEN));
    assert(message.msg_flags&MSG_TRUNC);
    for (size_t i=(size_t)n;i<sizeof(output);i++) assert(output[i]==0xa5);
    mapped_close(pair[0]); close(pair[1]);
    puts("Oversized reported datagram was clamped without an out-of-bounds read");
    return 0;
}
