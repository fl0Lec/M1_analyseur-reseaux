#ifndef __affiche__
#define __affiche__

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <net/if_arp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
//for IP
#define UDP 0x11
#define TCP 0x06



struct arp_adr
{
    char* add;
};


void afficheAddr(struct arp_adr*, int);

void afficheIPaddr(uint32_t);

void affiche_ETH(const struct ether_header *, int );

void affiche_IP(const struct iphdr *, int );
void affiche_ARP(const struct arphdr *, int);

void affiche_UDP(const struct udphdr *, int);
void affiche_TCP(const struct tcphdr *, int);



#endif