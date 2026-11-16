#ifndef HOTSPOT_PARENT_GUARD_H
#define HOTSPOT_PARENT_GUARD_H

#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

static void *hotspot_watch_parent(void *arg) {
    pid_t expected=(pid_t)(intptr_t)arg;
    while (getppid()==expected) sleep(2);
    _exit(0);
    return NULL;
}

/* Optional so standalone diagnostics and existing tests can run normally. */
static int hotspot_start_parent_guard(void) {
    const char *text=getenv("NAPTD_CONTROLLER_PID");
    if (!text || !*text) return 1;
    char *end=NULL;
    long value=strtol(text,&end,10);
    if (*end || value<2 || value>INT_MAX || getppid()!=(pid_t)value) return 0;
    pthread_t thread;
    if (pthread_create(&thread,NULL,hotspot_watch_parent,(void *)(intptr_t)value)) return 0;
    pthread_detach(thread);
    return 1;
}
#endif
