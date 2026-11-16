/* Minimal DHCP client for a disposable feth pair; no host DHCP settings change. */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

static void put16(unsigned char *p,uint16_t v) { p[0]=(unsigned char)(v>>8); p[1]=(unsigned char)v; }
static uint16_t get16(const unsigned char *p) { return (uint16_t)(((uint16_t)p[0]<<8)|p[1]); }
static uint16_t checksum(const unsigned char *p,size_t n) {
    uint32_t sum=0;
    while (n>1) { sum+=((uint32_t)p[0]<<8)|p[1]; p+=2; n-=2; }
    if (n) sum+=(uint32_t)*p<<8;
    while (sum>>16) sum=(sum&0xffff)+(sum>>16);
    return (uint16_t)~sum;
}
static int open_bpf(const char *device) {
    int fd=-1;
    for (int i=0;i<256;i++) {
        char name[32]; snprintf(name,sizeof(name),"/dev/bpf%d",i);
        fd=open(name,O_RDWR|O_CLOEXEC);
        if (fd>=0) break;
        if (errno!=EBUSY) return -1;
    }
    if (fd<0) return -1;
    struct ifreq req; memset(&req,0,sizeof(req));
    if (strlen(device)>=sizeof(req.ifr_name)) { close(fd); return -1; }
    strcpy(req.ifr_name,device);
    unsigned one=1,zero=0;
    if (ioctl(fd,BIOCSETIF,&req) || ioctl(fd,BIOCIMMEDIATE,&one) ||
        ioctl(fd,BIOCSHDRCMPLT,&one) || ioctl(fd,BIOCPROMISC,NULL)) { close(fd); return -1; }
    (void)ioctl(fd,BIOCSSEESENT,&zero);
    return fd;
}
static int send_request(int fd,const unsigned char mac[6],uint32_t xid,int message,
                        const struct in_addr *requested,const struct in_addr *server) {
    unsigned char p[14+20+8+320]={0};
    memset(p,0xff,6); memcpy(p+6,mac,6); put16(p+12,0x0800);
    unsigned char *ip=p+14,*udp=ip+20,*dhcp=udp+8;
    ip[0]=0x45; ip[8]=64; ip[9]=17; memset(ip+16,0xff,4);
    put16(udp,68); put16(udp+2,67);
    dhcp[0]=1; dhcp[1]=1; dhcp[2]=6; memcpy(dhcp+4,&xid,4); put16(dhcp+10,0x8000);
    memcpy(dhcp+28,mac,6); memcpy(dhcp+236,"\x63\x82\x53\x63",4);
    size_t pos=240; dhcp[pos++]=53; dhcp[pos++]=1; dhcp[pos++]=(unsigned char)message;
    dhcp[pos++]=61; dhcp[pos++]=7; dhcp[pos++]=1; memcpy(dhcp+pos,mac,6); pos+=6;
    if (requested) { dhcp[pos++]=50; dhcp[pos++]=4; memcpy(dhcp+pos,requested,4); pos+=4; }
    if (server) { dhcp[pos++]=54; dhcp[pos++]=4; memcpy(dhcp+pos,server,4); pos+=4; }
    dhcp[pos++]=55; dhcp[pos++]=4; dhcp[pos++]=1; dhcp[pos++]=3; dhcp[pos++]=6; dhcp[pos++]=51;
    dhcp[pos++]=255;
    if (pos<300) pos=300;
    size_t ip_len=20+8+pos,frame_len=14+ip_len;
    put16(ip+2,(uint16_t)ip_len); put16(ip+10,checksum(ip,20)); put16(udp+4,(uint16_t)(8+pos));
    return write(fd,p,frame_len)==(ssize_t)frame_len;
}
static int parse_replies(const unsigned char *buf,size_t total,const unsigned char mac[6],
                         uint32_t xid,int wanted,struct in_addr *address,struct in_addr *server) {
    /* bh_hdrlen can be 18 for Ethernet even though sizeof(struct bpf_hdr) is 20. */
    const size_t min_header=offsetof(struct bpf_hdr,bh_hdrlen)+sizeof(((struct bpf_hdr *)0)->bh_hdrlen);
    for (size_t off=0;off<=total && total-off>=min_header;) {
        struct bpf_hdr h={0};
        memcpy(&h,buf+off,min_header);
        if (h.bh_hdrlen<min_header || h.bh_hdrlen>total-off ||
            h.bh_caplen>total-off-h.bh_hdrlen) break;
        const unsigned char *frame=buf+off+h.bh_hdrlen; size_t len=h.bh_caplen;
        size_t next=BPF_WORDALIGN((size_t)h.bh_hdrlen+len);
        off=next>total-off ? total : off+next;
        if (len<14+20+8+240 || get16(frame+12)!=0x0800) continue;
        const unsigned char *ip=frame+14; size_t ihl=(ip[0]&15)*4;
        if (ihl<20 || len<14+ihl+8+240 || ip[9]!=17) continue;
        const unsigned char *udp=ip+ihl; if (get16(udp)!=67 || get16(udp+2)!=68) continue;
        const unsigned char *dhcp=udp+8; size_t avail=len-(size_t)(dhcp-frame);
        if (dhcp[0]!=2 || memcmp(dhcp+4,&xid,4) || memcmp(dhcp+28,mac,6) || memcmp(dhcp+236,"\x63\x82\x53\x63",4)) continue;
        int kind=0,has_server=0; struct in_addr offered,server_id={0}; memcpy(&offered,dhcp+16,4);
        for (size_t i=240;i<avail;) {
            unsigned code=dhcp[i++]; if (code==0) continue; if (code==255) break;
            if (i>=avail) break; size_t n=dhcp[i++]; if (i+n>avail) break;
            if (code==53 && n==1) kind=dhcp[i];
            if (code==54 && n==4) { memcpy(&server_id,dhcp+i,4); has_server=1; }
            i+=n;
        }
        if (kind==6) return 2;
        if (kind==wanted && offered.s_addr && (wanted!=2 || has_server)) {
            if (address) *address=offered; if (server && has_server) *server=server_id;
            return 1;
        }
    }
    return 0;
}
static int await_reply(int fd,const unsigned char mac[6],uint32_t xid,int wanted,
                       struct in_addr *address,struct in_addr *server) {
    unsigned bufsize=0; if (ioctl(fd,BIOCGBLEN,&bufsize) || bufsize<sizeof(struct bpf_hdr)) return -1;
    unsigned char *buf=malloc(bufsize); if (!buf) return -1;
    struct timespec start,now; clock_gettime(CLOCK_MONOTONIC,&start);
    int result=0;
    for (;;) {
        clock_gettime(CLOCK_MONOTONIC,&now);
        int remaining=4000-(int)((now.tv_sec-start.tv_sec)*1000+(now.tv_nsec-start.tv_nsec)/1000000);
        if (remaining<=0) break;
        struct pollfd pfd={.fd=fd,.events=POLLIN};
        int ready=poll(&pfd,1,remaining); if (ready<0 && errno==EINTR) continue; if (ready<=0) break;
        ssize_t total=read(fd,buf,bufsize); if (total<=0) break;
        result=parse_replies(buf,(size_t)total,mac,xid,wanted,address,server);
        if (result) break;
    }
    free(buf); return result;
}
int main(int argc,char **argv) {
    if (argc!=3 && argc!=4) { fputs("usage: feth_dhcp_probe interface client-id [previous-ip]\n",stderr); return 1; }
    char *end=NULL; unsigned long id=strtoul(argv[2],&end,10);
    if (*end || id>0xffffff) return 1;
    unsigned char mac[6]={0x02,0x4e,0x53,(unsigned char)(id>>16),(unsigned char)(id>>8),(unsigned char)id};
    uint32_t xid=arc4random(); int fd=open_bpf(argv[1]); if (fd<0) { perror("bpf"); return 1; }
    struct in_addr address={0},server={0}; int result;
    if (argc==4) {
        if (inet_pton(AF_INET,argv[3],&address)!=1 || !send_request(fd,mac,xid,3,&address,NULL)) { close(fd); return 1; }
        result=await_reply(fd,mac,xid,5,&address,NULL);
    } else {
        if (!send_request(fd,mac,xid,1,NULL,NULL)) { close(fd); return 1; }
        result=await_reply(fd,mac,xid,2,&address,&server);
        if (result==1 && send_request(fd,mac,xid,3,&address,&server)) result=await_reply(fd,mac,xid,5,&address,NULL);
    }
    close(fd);
    if (result!=1) { fprintf(stderr,"dhcp_%s\n",result==2?"nak":"timeout"); return result==2?2:3; }
    char text[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET,&address,text,sizeof(text))) return 1;
    puts(text); return 0;
}
