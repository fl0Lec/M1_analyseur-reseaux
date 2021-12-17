#ifndef __affiche__
#define __affiche__

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <net/if_arp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include "bootp.h"
#include "dns.h"

//for IP
#define UDP 0x11
#define TCP 0x06

#define PRINTLINE() printf("__________________________________________\n");
#define REVUINT(a) (a>>8)+((a&0xff)<<8)

struct arp_adr
{
    uchar* add;
};


void afficheAddr(const uchar*, int);

void afficheIPaddr(uint32_t);

void affiche_ETH(const struct ether_header *, int , char *tab);

void affiche_IP(const struct iphdr *, int , char *tab);
void affiche_ARP(const struct arphdr *, int, char *tab);

void affiche_UDP(const struct udphdr *, int, char *tab);
void affiche_TCP(const struct tcphdr *, int, char *tab);

void affiche_Bootp(const struct bootp*, int, const u_char*, char *tab);
void affiche_DNS(const struct dns_header* header, const u_char *packet,int v, char* tab);

void affiche_SMTP(const uchar* data, size_t size,int ser, int v, char* tab);


#endif