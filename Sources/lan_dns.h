/* Bounded, per-association DNS work. Resolution must not stall UDP forwarding.
 * The association owns this queue and joins its worker before freeing it. */
#ifndef LANSHARER_LAN_DNS_H
#define LANSHARER_LAN_DNS_H
#define LAN_DNS_PENDING 16

typedef struct lan_dns_job {
    struct lan_dns_job *next;
    char name[256];
    uint32_t address;
    uint16_t port;
    int resolved;
    size_t size;
    uint8_t data[];
} lan_dns_job;

typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t ready;
    pthread_t worker;
    int notify[2],stopping;
    unsigned count;
    lan_dns_job *pending,*pending_tail,*done,*done_tail;
    struct { char name[256]; uint32_t address; time_t expires; } cache[LAN_DNS_PENDING];
    unsigned cache_next;
} lan_dns_queue;

static void *lan_dns_worker(void *argument) {
    lan_dns_queue *q=argument;
    for (;;) {
        pthread_mutex_lock(&q->lock);
        while (!q->stopping && !q->pending) pthread_cond_wait(&q->ready,&q->lock);
        if (q->stopping) { pthread_mutex_unlock(&q->lock); break; }
        lan_dns_job *job=q->pending;
        q->pending=job->next;
        if (!q->pending) q->pending_tail=NULL;
        pthread_mutex_unlock(&q->lock);
        struct in_addr address={0}; uint32_t ttl=0;
        struct timespec now; clock_gettime(CLOCK_MONOTONIC,&now);
        for (int i=0;i<LAN_DNS_PENDING;i++) {
            if (q->cache[i].expires>now.tv_sec && !strcmp(q->cache[i].name,job->name)) {
                address.s_addr=q->cache[i].address; job->resolved=1; break;
            }
        }
        if (!job->resolved) {
            job->resolved=resolve_ipv4_name_ttl(job->name,&address,&ttl);
            if (job->resolved && ttl) {
                unsigned slot=q->cache_next++ % LAN_DNS_PENDING;
                strcpy(q->cache[slot].name,job->name);
                q->cache[slot].address=address.s_addr;
                clock_gettime(CLOCK_MONOTONIC,&now);
                q->cache[slot].expires=now.tv_sec+(ttl<60 ? ttl : 60);
            }
        }
        job->address=address.s_addr; job->next=NULL;
        pthread_mutex_lock(&q->lock);
        if (q->done_tail) q->done_tail->next=job; else q->done=job;
        q->done_tail=job;
        pthread_mutex_unlock(&q->lock);
        uint8_t signal=1;
        (void)write(q->notify[1],&signal,1);
    }
    return NULL;
}
static lan_dns_queue *lan_dns_create(void) {
    lan_dns_queue *q=calloc(1,sizeof(*q));
    if (!q) return NULL;
    if (pipe(q->notify)) { free(q); return NULL; }
    for (int i=0;i<2;i++) {
        int flags=fcntl(q->notify[i],F_GETFL,0);
        if (flags<0 || fcntl(q->notify[i],F_SETFL,flags|O_NONBLOCK)) goto fail_pipe;
        (void)fcntl(q->notify[i],F_SETFD,FD_CLOEXEC);
    }
    if (pthread_mutex_init(&q->lock,NULL)) goto fail_pipe;
    if (pthread_cond_init(&q->ready,NULL)) goto fail_mutex;
    if (pthread_create(&q->worker,NULL,lan_dns_worker,q)) goto fail_cond;
    return q;
fail_cond:
    pthread_cond_destroy(&q->ready);
fail_mutex:
    pthread_mutex_destroy(&q->lock);
fail_pipe:
    close(q->notify[0]); close(q->notify[1]); free(q); return NULL;
}
static int lan_dns_submit(lan_dns_queue *q,const char *name,uint16_t port,const uint8_t *data,size_t size) {
    pthread_mutex_lock(&q->lock);
    if (q->count>=LAN_DNS_PENDING) { pthread_mutex_unlock(&q->lock); return 0; }
    lan_dns_job *job=calloc(1,sizeof(*job)+size);
    if (!job) { pthread_mutex_unlock(&q->lock); return 0; }
    memcpy(job->name,name,strlen(name)+1); job->port=port; job->size=size;
    memcpy(job->data,data,size);
    if (q->pending_tail) q->pending_tail->next=job; else q->pending=job;
    q->pending_tail=job; q->count++;
    pthread_cond_signal(&q->ready);
    pthread_mutex_unlock(&q->lock); return 1;
}
static lan_dns_job *lan_dns_take(lan_dns_queue *q) {
    if (!q) return NULL;
    pthread_mutex_lock(&q->lock);
    lan_dns_job *job=q->done;
    if (job) {
        q->done=job->next; job->next=NULL; q->count--;
        if (!q->done) q->done_tail=NULL;
    }
    pthread_mutex_unlock(&q->lock); return job;
}
static void lan_dns_destroy(lan_dns_queue *q) {
    if (!q) return;
    pthread_mutex_lock(&q->lock);
    q->stopping=1; pthread_cond_signal(&q->ready);
    pthread_mutex_unlock(&q->lock);
    pthread_join(q->worker,NULL);
    lan_dns_job *lists[2]={q->pending,q->done};
    for (int i=0;i<2;i++) while (lists[i]) {
        lan_dns_job *next=lists[i]->next; free(lists[i]); lists[i]=next;
    }
    close(q->notify[0]); close(q->notify[1]);
    pthread_cond_destroy(&q->ready); pthread_mutex_destroy(&q->lock); free(q);
}
#endif
