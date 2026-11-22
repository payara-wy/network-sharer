#define main feth_probe_entry
#include "feth_dhcp_probe.c"
#undef main
#include <assert.h>

static size_t record(unsigned char *out,size_t header_len,const unsigned char mac[6],
                     uint32_t xid,int message) {
    const size_t packet_len=14+20+8+250;
    struct bpf_hdr header={0};
    header.bh_hdrlen=(u_short)header_len;
    header.bh_caplen=(bpf_u_int32)packet_len;
    header.bh_datalen=(bpf_u_int32)packet_len;
    size_t total=BPF_WORDALIGN(header_len+packet_len);
    memset(out,0,total);
    memcpy(out,&header,offsetof(struct bpf_hdr,bh_hdrlen)+sizeof(header.bh_hdrlen));
    unsigned char *frame=out+header_len,*ip=frame+14,*udp=ip+20,*dhcp=udp+8;
    put16(frame+12,0x0800); ip[0]=0x45; ip[9]=17; put16(udp,67); put16(udp+2,68);
    dhcp[0]=2; memcpy(dhcp+4,&xid,4); memcpy(dhcp+28,mac,6);
    assert(inet_pton(AF_INET,"172.30.79.10",dhcp+16)==1);
    memcpy(dhcp+236,"\x63\x82\x53\x63",4);
    dhcp[240]=53; dhcp[241]=1; dhcp[242]=(unsigned char)message;
    dhcp[243]=54; dhcp[244]=4;
    assert(inet_pton(AF_INET,"172.30.79.1",dhcp+245)==1);
    dhcp[249]=255;
    return total;
}
int main(void) {
    unsigned char data[1024],mac[6]={2,0x4e,0x53,0,3,0xe7};
    uint32_t xid=0x12345678; struct in_addr address={0},server={0};
    const size_t raw=offsetof(struct bpf_hdr,bh_hdrlen)+sizeof(((struct bpf_hdr *)0)->bh_hdrlen);
    size_t len=record(data,raw,mac,xid,2);
    assert(raw==18 && sizeof(struct bpf_hdr)>raw);
    assert(parse_replies(data,len,mac,xid,2,&address,&server)==1);
    assert(address.s_addr==inet_addr("172.30.79.10") && server.s_addr==inet_addr("172.30.79.1"));
    assert(parse_replies(data,len,mac,xid+1,2,&address,&server)==0);
    assert(parse_replies(data,raw+10,mac,xid,2,&address,&server)==0);
    len=record(data,sizeof(struct bpf_hdr),mac,xid,6);
    assert(parse_replies(data,len,mac,xid,2,&address,&server)==2);
    len=record(data,raw,mac,xid+1,2);
    len+=record(data+len,raw,mac,xid,5);
    assert(parse_replies(data,len,mac,xid,5,&address,&server)==1);
    puts("DHCP probe: padded and unpadded BPF headers, bounds, XID, ACK and NAK passed");
    return 0;
}
