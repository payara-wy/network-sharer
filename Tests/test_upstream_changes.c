/* Run the gateway's real interface cache against a changing fake Wi-Fi. */
#define if_nametoindex test_if_nametoindex
#define getifaddrs test_getifaddrs
#define freeifaddrs test_freeifaddrs
#define clock_gettime test_clock_gettime
#define main gateway_main_for_test
#include "../Sources/socks_gateway.c"
#undef main
#undef clock_gettime
#undef freeifaddrs
#undef getifaddrs
#undef if_nametoindex

#include <assert.h>
static time_t simulated_time=100;
static int online=1;
static const char *simulated_address="192.0.2.10";

unsigned int test_if_nametoindex(const char *name) { return online && !strcmp(name,"en0") ? 7 : 0; }
int test_getifaddrs(struct ifaddrs **out) {
    static struct ifaddrs item; static struct sockaddr_in addr;
    memset(&item,0,sizeof(item)); memset(&addr,0,sizeof(addr));
    addr.sin_len=sizeof(addr); addr.sin_family=AF_INET;
    assert(inet_pton(AF_INET,simulated_address,&addr.sin_addr)==1);
    item.ifa_name="en0"; item.ifa_addr=(struct sockaddr *)&addr; *out=&item;
    return 0;
}
void test_freeifaddrs(struct ifaddrs *value) { (void)value; }
int test_clock_gettime(clockid_t clock,struct timespec *value) { (void)clock; value->tv_sec=simulated_time; value->tv_nsec=0; return 0; }

int main(void) {
    strcpy(upstream_name,"en0");
    unsigned int index=0; struct in_addr address; unsigned long initial=0,next=0;
    assert(upstream_snapshot(&index,&address,&initial,1));
    assert(index==7 && address.s_addr==inet_addr("192.0.2.10"));
    simulated_address="192.0.2.99"; simulated_time++;
    assert(upstream_snapshot(&index,&address,&next,0));
    assert(address.s_addr==inet_addr("192.0.2.10") && next==initial);
    simulated_time++;
    assert(upstream_snapshot(&index,&address,&next,0));
    assert(address.s_addr==inet_addr("192.0.2.99") && next>initial);
    unsigned long after_change=next;
    online=0; simulated_time+=2;
    assert(!upstream_snapshot(&index,&address,&next,0));
    online=1; simulated_time+=2;
    assert(upstream_snapshot(&index,&address,&next,0));
    assert(address.s_addr==inet_addr("192.0.2.99") && next>after_change);
    puts("Wi-Fi address change, disconnect and reconnect refresh the selected interface");
    return 0;
}
