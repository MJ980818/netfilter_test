#pragma once
#include <pcap.h>

struct iph{
    u_int8_t vhl;            // version
    u_int8_t tos;           // type of service
    u_int8_t len[2];       // total length
    u_int8_t id[2];
    u_int8_t off[2];
    u_int8_t ttl;
    u_int8_t p;            // protocol  tcp(6)  udp(17)
    u_int8_t sum[2];
    u_int8_t shost[4];
    u_int8_t dhost[4];
    #define IP_HL(ip)		(((ip)->vhl) & 0x0f)
    #define IP_V(ip)		(((ip)->vhl) >> 4)
};


struct tcph{
    u_int8_t sport[2];
    u_int8_t dport[2];
    u_int th_seq;          // sequence number
    u_int th_ack;         // acknowledge number
    u_int8_t th_offx2;   // data offset, reserved
    #define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
    u_int8_t th_flags;
    u_int8_t th_win[2];
    u_int8_t th_sum[2];
    u_int8_t th_urp[2];

};


const struct iph *ip;
const struct tcph *tcp;


void usage(){
    printf("netfilter_test <host>\n");
    printf("ex: netfilter_test test.gilgil.net\n");
}
