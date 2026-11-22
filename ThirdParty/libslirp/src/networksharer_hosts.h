/* Local interface identity list shared by the DHCP and Ethernet filters. */
#ifndef NETWORKSHARER_HOSTS_H
#define NETWORKSHARER_HOSTS_H
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int ns_hex(unsigned char c) {
    if (c >= '0' && c <= '9') return c-'0';
    if (c >= 'a' && c <= 'f') return c-'a'+10;
    if (c >= 'A' && c <= 'F') return c-'A'+10;
    return -1;
}

/* Return 1 for a local MAC or an invalid identity file, 0 for a client.
 * The private directory and file are written atomically by the controller. */
static int ns_host_mac_excluded(const uint8_t mac[6],const uint8_t *second) {
    const char *path=getenv("NAPTD_HOST_MAC_FILE");
    if (!path || path[0]!='/' || !mac) return 1;
    int fd=open(path,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if (fd<0) return 1;
    struct stat st;
    if (fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_uid!=geteuid() ||
        st.st_nlink!=1 || (st.st_mode&0077) || st.st_size<18 || st.st_size>32768) {
        close(fd); return 1;
    }
    FILE *file=fdopen(fd,"r");
    if (!file) { close(fd); return 1; }
    char line[20]; int excluded=0,valid=1,count=0;
    while (fgets(line,sizeof(line),file)) {
        size_t len=strlen(line); uint8_t parsed[6];
        if (len!=18 || line[17]!='\n') { valid=0; break; }
        for (int i=0;i<6;i++) {
            int a=ns_hex((unsigned char)line[i*3]), b=ns_hex((unsigned char)line[i*3+1]);
            if (a<0 || b<0 || (i<5 && line[i*3+2]!=':')) { valid=0; break; }
            parsed[i]=(uint8_t)(a*16+b);
        }
        if (!valid) break;
        if (!memcmp(parsed,mac,6) || (second && !memcmp(parsed,second,6))) excluded=1;
        count++;
    }
    if (ferror(file)) valid=0;
    fclose(file);
    return !valid || !count || excluded;
}
#endif
