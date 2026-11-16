#include <libproc.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>

int main(int argc,char **argv) {
    if (argc!=2) return 1;
    struct rusage_info_v4 info={0};
    if (proc_pid_rusage(atoi(argv[1]),RUSAGE_INFO_V4,(rusage_info_t *)&info)) return 2;
    printf("%llu %llu %llu\n",(unsigned long long)info.ri_diskio_bytesread,
           (unsigned long long)info.ri_diskio_byteswritten,(unsigned long long)info.ri_logical_writes);
    return 0;
}
