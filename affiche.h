#ifndef __affiche__
#define __affiche__

#include <net/ethernet.h>
#include <netinet/ip.h>

//for IP
#define UDP 0x11
#define TCP 0x06

//for ARP
#define IPv4 0x8
#define ARP_REQUEST 0x100
#define ARP_REPLY   0x200
struct arp {
  unsigned int type:16;
  unsigned int protocol:16;
  unsigned int L_phy:8;
  unsigned int L_pro:8;
  unsigned int operation:16;
};

struct adresse
{
    char* add;
};

struct arp_adr
{
    char* add;
};


void afficheAddr(struct arp_adr*, int);

void afficheIPaddr(uint32_t);

void affiche_ETH(const struct ether_header *, int );
void affiche_IP(const struct iphdr *, int );
void affiche_ARPR(const struct arp *);



#endif