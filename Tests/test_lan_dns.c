/* DNS queue lifecycle, bound, cache TTL and expiry with deterministic time. */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>
#include <stdio.h>
static time_t tick=100;
static int calls;
static uint32_t answer_ttl=10;
static pthread_mutex_t fixture_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t fixture_ready=PTHREAD_COND_INITIALIZER;
static int held=0,entered=0;
static int fake_clock(clockid_t clock,struct timespec *out) {
    (void)clock; out->tv_sec=tick; out->tv_nsec=0; return 0;
}
static int resolve_ipv4_name_ttl(const char *name,struct in_addr *out,uint32_t *ttl) {
    (void)name;
    pthread_mutex_lock(&fixture_lock);
    entered=1; pthread_cond_broadcast(&fixture_ready);
    while (held) pthread_cond_wait(&fixture_ready,&fixture_lock);
    pthread_mutex_unlock(&fixture_lock);
    calls++; out->s_addr=0x0100007f; *ttl=answer_ttl; return 1;
}
#define clock_gettime fake_clock
#include "../Sources/lan_dns.h"
#undef clock_gettime
static void receive_job(lan_dns_queue *q) {
    struct pollfd fd={.fd=q->notify[0],.events=POLLIN};
    assert(poll(&fd,1,2000)==1);
    uint8_t byte; assert(read(q->notify[0],&byte,1)==1);
    lan_dns_job *job=lan_dns_take(q); assert(job && job->resolved && job->size==3);
    assert(!memcmp(job->data,"abc",3)); free(job);
}
int main(void) {
    lan_dns_queue *q=lan_dns_create(); assert(q);
    assert(lan_dns_submit(q,"test.example",htons(80),(uint8_t *)"abc",3)); receive_job(q); assert(calls==1);
    assert(lan_dns_submit(q,"test.example",htons(81),(uint8_t *)"abc",3)); receive_job(q); assert(calls==1);
    tick=111;
    assert(lan_dns_submit(q,"test.example",htons(80),(uint8_t *)"abc",3)); receive_job(q); assert(calls==2);
    answer_ttl=0;
    assert(lan_dns_submit(q,"nocache.example",htons(80),(uint8_t *)"abc",3)); receive_job(q);
    assert(lan_dns_submit(q,"nocache.example",htons(80),(uint8_t *)"abc",3)); receive_job(q); assert(calls==4);
    lan_dns_destroy(q);
    q=lan_dns_create(); assert(q);
    held=1; entered=0;
    assert(lan_dns_submit(q,"held.example",htons(80),(uint8_t *)"abc",3));
    pthread_mutex_lock(&fixture_lock);
    while (!entered) pthread_cond_wait(&fixture_ready,&fixture_lock);
    pthread_mutex_unlock(&fixture_lock);
    for (int i=1;i<LAN_DNS_PENDING;i++) assert(lan_dns_submit(q,"held.example",htons(80),(uint8_t *)"abc",3));
    assert(!lan_dns_submit(q,"overflow.example",htons(80),(uint8_t *)"abc",3));
    pthread_mutex_lock(&fixture_lock); held=0; pthread_cond_broadcast(&fixture_ready); pthread_mutex_unlock(&fixture_lock);
    for (int i=0;i<LAN_DNS_PENDING;i++) receive_job(q);
    assert(q->count==0);
    lan_dns_destroy(q);
    puts("PASS DNS cache TTL/expiry/zero-TTL, 16-job bound, completion and queue teardown");
}
