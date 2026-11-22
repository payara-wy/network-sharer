/* One SOCKS5 UDP association per authenticated LAN control connection.
 * Dedicated client-facing sockets keep clients on the same IP independent. */
#ifndef LANSHARER_LAN_UDP_H
#define LANSHARER_LAN_UDP_H
#define LAN_DESTINATIONS 128
#include "lan_dns.h"

typedef struct {
    int active,fd;
    uint32_t address;
    uint16_t port;
    time_t last;
} lan_destination;

static void lan_forward_datagram(lan_destination *destinations,proxy_udp *upstream,
                                 uint32_t address,uint16_t port,const uint8_t *payload,size_t size) {
    time_t now=time(NULL);
    int slot=-1,free_slot=-1;
    for (int i=0;i<LAN_DESTINATIONS;i++) {
        if (destinations[i].active && now-destinations[i].last>120) {
            if (direct_mode) close(destinations[i].fd);
            destinations[i].active=0;
        }
        if (destinations[i].active && destinations[i].address==address && destinations[i].port==port) { slot=i; break; }
        if (!destinations[i].active && free_slot<0) free_slot=i;
    }
    if (slot<0) {
        // At capacity, drop a new flow instead of tearing down an existing
        // QUIC/media flow and changing its source port mid-session.
        if (free_slot<0) return;
        slot=free_slot;
        destinations[slot]=(lan_destination){.fd=-1,.address=address,.port=port,.last=now};
        if (direct_mode) {
            destinations[slot].fd=direct_socket(SOCK_DGRAM,address,port,2,NULL);
            if (destinations[slot].fd<0) return;
            int flags=fcntl(destinations[slot].fd,F_GETFL,0);
            if (flags<0 || fcntl(destinations[slot].fd,F_SETFL,flags|O_NONBLOCK)) { close(destinations[slot].fd); return; }
        }
        destinations[slot].active=1;
    }
    ssize_t sent=direct_mode ? send(destinations[slot].fd,payload,size,0)
                            : proxy_udp_send(upstream,address,port,payload,size);
    if (sent>=0) destinations[slot].last=now;
}

static void serve_lan_association(int client,uint32_t requested_address,uint16_t requested_port) {
    /* Strict sandbox: in upstream mode replies to LAN clients are not permitted,
     * so fail explicitly instead of letting the client time out. */
    if (!direct_mode && getenv("NAPTD_LAN_UDP_DISABLED")) {
        (void)lan_reply(client,7,NULL,0); return;
    }
    struct sockaddr_in peer={0},local={0}; socklen_t length=sizeof(peer);
    if (getpeername(client,(struct sockaddr *)&peer,&length) || peer.sin_family!=AF_INET ||
        (requested_address && requested_address!=peer.sin_addr.s_addr)) {
        (void)lan_reply(client,2,NULL,0); return;
    }
    length=sizeof(local);
    if (getsockname(client,(struct sockaddr *)&local,&length)) return;
    local.sin_port=0;
    int udp=socket(AF_INET,SOCK_DGRAM,0);
    if (udp<0) { (void)lan_reply(client,1,NULL,0); return; }
    proxy_udp upstream=proxy_udp_empty;
    lan_destination destinations[LAN_DESTINATIONS]={0};
    lan_dns_queue *dns=NULL;
    if (bind(udp,(struct sockaddr *)&local,sizeof(local)) || getsockname(udp,(struct sockaddr *)&local,&length)) goto failed;
    if (!direct_mode && !proxy_udp_open(&upstream)) {
        (void)lan_reply(client,7,NULL,0); goto cleanup;
    }
    if (!lan_reply(client,0,(uint8_t *)&local.sin_addr.s_addr,ntohs(local.sin_port))) goto cleanup;
    struct sockaddr_in endpoint=peer; endpoint.sin_port=requested_port;
    int source_locked=0;
    unsigned long generation=0;
    if (direct_mode && !upstream_snapshot(NULL,NULL,&generation,0)) goto cleanup;
    for (;;) {
        struct pollfd fds[5+LAN_DESTINATIONS]={{.fd=client,.events=POLLIN},{.fd=udp,.events=POLLIN},
                                                {.fd=dns ? dns->notify[0] : -1,.events=POLLIN}};
        int slots[5+LAN_DESTINATIONS], count=3;
        if (!direct_mode) {
            fds[count++]=(struct pollfd){.fd=upstream.control,.events=POLLIN};
            fds[count++]=(struct pollfd){.fd=upstream.fd,.events=POLLIN};
        } else {
            for (int i=0;i<LAN_DESTINATIONS;i++) if (destinations[i].active) {
                slots[count]=i;
                fds[count++]=(struct pollfd){.fd=destinations[i].fd,.events=POLLIN};
            }
        }
        int result=poll(fds,(nfds_t)count,1000);
        if (result<0) { if (errno==EINTR) continue; break; }
        if (fds[0].revents || (!direct_mode && (fds[3].revents || (fds[4].revents&(POLLERR|POLLHUP|POLLNVAL))))) break;
        if (fds[1].revents&(POLLERR|POLLHUP|POLLNVAL)) break;
        struct in_addr wifi;
        if (!lan_wifi_address(&wifi) || wifi.s_addr!=local.sin_addr.s_addr) break;
        time_t now=time(NULL);
        /* Association lifetime follows its TCP control connection. Reclaim
         * idle destination flows below, not the authenticated association. */
        if (direct_mode) {
            unsigned long current;
            if (!upstream_snapshot(NULL,NULL,&current,0) || current!=generation) break;
        }
        if (!direct_mode && (fds[4].revents&POLLIN)) {
            uint8_t response[10+UDP_PAYLOAD_MAX]={0,0,0,1}; uint32_t address=0; uint16_t port=0;
            ssize_t n=proxy_udp_receive(&upstream,&address,&port,response+10,UDP_PAYLOAD_MAX);
            int known=0;
            for (int i=0;i<LAN_DESTINATIONS;i++)
                if (destinations[i].active && destinations[i].address==address && destinations[i].port==port && now-destinations[i].last<=120) known=1;
            if (n>=0 && known && endpoint.sin_port) {
                memcpy(response+4,&address,4); memcpy(response+8,&port,2);
                sendto(udp,response,(size_t)n+10,0,(struct sockaddr *)&endpoint,sizeof(endpoint));

            }
        } else if (direct_mode) {
            for (int j=3;j<count;j++) {
                lan_destination *d=&destinations[slots[j]];
                if (fds[j].revents&POLLIN) {
                    uint8_t response[10+UDP_PAYLOAD_MAX]={0,0,0,1};
                    struct iovec iov={.iov_base=response+10,.iov_len=UDP_PAYLOAD_MAX};
                    struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1};
                    ssize_t n=recvmsg(d->fd,&msg,0);
                    if (n>=0 && (msg.msg_flags&MSG_TRUNC)) n=-1;
                    if (n>=0 && endpoint.sin_port) {
                        memcpy(response+4,&d->address,4); memcpy(response+8,&d->port,2);
                        sendto(udp,response,(size_t)n+10,0,(struct sockaddr *)&endpoint,sizeof(endpoint));
                        d->last=now;
                    }
                }
                if (fds[j].revents&(POLLERR|POLLNVAL) || now-d->last>120) { close(d->fd); d->active=0; }
            }
        }
        if (dns) {
            uint8_t signals[LAN_DNS_PENDING];
            while (read(dns->notify[0],signals,sizeof(signals))>0) {}
            lan_dns_job *job;
            while ((job=lan_dns_take(dns))) {
                if (job->resolved && lan_target_allowed(job->address))
                    lan_forward_datagram(destinations,&upstream,job->address,job->port,job->data,job->size);
                free(job);
            }
        }
        if (!(fds[1].revents&POLLIN)) continue;
        uint8_t packet[262+UDP_PAYLOAD_MAX]; struct sockaddr_in from={0};
        struct iovec iov={.iov_base=packet,.iov_len=sizeof(packet)};
        struct msghdr msg={.msg_name=&from,.msg_namelen=sizeof(from),.msg_iov=&iov,.msg_iovlen=1};
        ssize_t n=recvmsg(udp,&msg,0);
        if (n<10 || (msg.msg_flags&MSG_TRUNC) || from.sin_addr.s_addr!=peer.sin_addr.s_addr ||
            packet[0] || packet[1] || packet[2]) continue;
        uint32_t address=0; uint16_t port=0; size_t offset=4; char name[256]={0};
        if (packet[3]==1) { memcpy(&address,packet+4,4); offset=8; }
        else if (packet[3]==3) {
            size_t size=packet[4];
            if (!size || (size_t)n<7+size) continue;
            memcpy(name,packet+5,size); name[size]=0;
            if (strlen(name)!=size) continue;
            for (size_t i=0;i<size;i++) if ((unsigned char)name[i]<=32 || (unsigned char)name[i]>=127) name[0]=0;
            if (!name[0]) continue;
            offset=5+size;
        } else continue;
        if ((size_t)n<offset+2 || (!name[0] && !lan_target_allowed(address))) continue;
        memcpy(&port,packet+offset,2); offset+=2;
        if (!port || (size_t)n-offset>UDP_PAYLOAD_MAX) continue;
        /* Only a complete, valid frame may claim the client's UDP endpoint. */
        if (!source_locked) { endpoint.sin_port=from.sin_port; source_locked=1; }
        else if (endpoint.sin_port!=from.sin_port) continue;
        if (name[0]) {
            if (!dns) dns=lan_dns_create();
            if (dns) (void)lan_dns_submit(dns,name,port,packet+offset,(size_t)n-offset);
            continue;
        }
        lan_forward_datagram(destinations,&upstream,address,port,packet+offset,(size_t)n-offset);
    }
    goto cleanup;
failed:
    (void)lan_reply(client,1,NULL,0);
cleanup:
    for (int i=0;i<LAN_DESTINATIONS;i++) if (direct_mode && destinations[i].active) close(destinations[i].fd);
    proxy_udp_close(&upstream);
    close(udp);
    lan_dns_destroy(dns);
}
#endif
