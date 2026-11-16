/* Reject overlap with an existing interface's actual IPv4 network. */
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>

static int overlaps_shared_subnet(uint32_t address,uint32_t mask) {
    const uint32_t shared=0xac1e4d00u, shared_mask=0xffffff00u;
    if (!mask) return 0;
    uint32_t inverse=~mask;
    if (inverse && (inverse & (inverse+1))) return 0;
    uint32_t common=mask & shared_mask;
    return (address & common)==(shared & common);
}

#ifndef NETWORKSHARER_TEST_SUBNET
int main(void) {
    struct ifaddrs *interfaces=NULL;
    if (getifaddrs(&interfaces)) { perror("getifaddrs"); return 2; }
    int conflict=0;
    for (struct ifaddrs *p=interfaces;p;p=p->ifa_next) {
        if (!p->ifa_addr || !p->ifa_netmask || p->ifa_addr->sa_family!=AF_INET || !(p->ifa_flags & IFF_UP)) continue;
        uint32_t address=ntohl(((struct sockaddr_in *)p->ifa_addr)->sin_addr.s_addr);
        uint32_t mask=ntohl(((struct sockaddr_in *)p->ifa_netmask)->sin_addr.s_addr);
        if (overlaps_shared_subnet(address,mask)) { puts(p->ifa_name); conflict=1; break; }
    }
    freeifaddrs(interfaces);
    return conflict;
}
#endif
