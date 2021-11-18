#ifndef __affiche__
#define __affiche__

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <net/if_arp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include "bootp.h"

//for IP
#define UDP 0x11
#define TCP 0x06



struct arp_adr
{
    char* add;
};


void afficheAddr(struct arp_adr*, int);

void afficheIPaddr(uint32_t);

void affiche_ETH(const struct ether_header *, int , char *tab);

void affiche_IP(const struct iphdr *, int , char *tab);
void affiche_ARP(const struct arphdr *, int, char *tab);

void affiche_UDP(const struct udphdr *, int, char *tab);
void affiche_TCP(const struct tcphdr *, int, char *tab);

void affiche_Bootp(const struct bootp*, int, const u_char*, char *tab);


#endif