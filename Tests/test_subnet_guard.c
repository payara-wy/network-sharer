#define NETWORKSHARER_TEST_SUBNET 1
#include "../Sources/subnet_guard.c"
#include <assert.h>

int main(void) {
    assert(overlaps_shared_subnet(0xac1e4d02u,0xffffff00u));
    assert(overlaps_shared_subnet(0xac1e0102u,0xffff0000u));
    assert(overlaps_shared_subnet(0xac1e4dfeu,0xffffffffu));
    assert(!overlaps_shared_subnet(0xac1f0102u,0xffff0000u));
    assert(!overlaps_shared_subnet(0xc0a84705u,0xffffff00u));
    assert(!overlaps_shared_subnet(0xc0a84705u,0));
    assert(!overlaps_shared_subnet(0xac1e4d02u,0xff00ff00u));
    puts("IPv4 interface subnet overlap: exact, wider, host and unrelated networks passed");
    return 0;
}
