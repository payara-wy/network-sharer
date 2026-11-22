/* Audit-only TCP stress: half-close with a slow reader and tiny socket buffers. */
#define main gateway_main_for_test
#include "../Sources/socks_gateway.c"
#undef main
#include <assert.h>

struct relay_pair { int client,remote; };
static void *run_relay(void *arg) {
    struct relay_pair *p=arg; relay(p->client,p->remote); close(p->client);close(p->remote);return NULL;
}
static void *writer(void *arg) {
    int fd=(int)(intptr_t)arg;
    uint8_t bytes[4096]; for(size_t i=0;i<sizeof(bytes);i++)bytes[i]=(uint8_t)i;
    for(int i=0;i<1024;i++)assert(write_all(fd,bytes,sizeof(bytes)));
    assert(shutdown(fd,SHUT_WR)==0);
    return NULL;
}
int main(void) {
    signal(SIGPIPE,SIG_IGN); alarm(25);
    for(int iteration=0;iteration<3;iteration++) {
        int a[2],b[2];assert(!socketpair(AF_UNIX,SOCK_STREAM,0,a));assert(!socketpair(AF_UNIX,SOCK_STREAM,0,b));
        int small=4096;
        setsockopt(a[0],SOL_SOCKET,SO_RCVBUF,&small,sizeof(small));
        setsockopt(a[1],SOL_SOCKET,SO_SNDBUF,&small,sizeof(small));
        struct relay_pair p={a[1],b[1]};pthread_t runner,sender;
        assert(!pthread_create(&runner,NULL,run_relay,&p));
        assert(!pthread_create(&sender,NULL,writer,(void *)(intptr_t)b[0]));
        assert(!shutdown(a[0],SHUT_WR));
        struct timespec delay={.tv_sec=0,.tv_nsec=200000000};nanosleep(&delay,NULL);
        uint8_t data[256];size_t received=0;ssize_t n;
        while((n=recv(a[0],data,sizeof(data),0))>0) {
            for(ssize_t i=0;i<n;i++)assert(data[i]==(uint8_t)(received+(size_t)i));
            received+=(size_t)n;
        }
        assert(n==0 && received==4096u*1024);
        pthread_join(sender,NULL);pthread_join(runner,NULL);
        close(a[0]);close(b[0]);
    }
    puts("PASS TCP slow-reader backpressure + half-close: 3 x 4 MiB byte-exact");
}
