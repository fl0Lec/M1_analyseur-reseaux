#ifndef __affiche__
#define __affiche__

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <net/if_arp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include "bootp.h"
#include "dns.h"
#include "const.h"


struct arp_adr
{
    uchar* add;
};

enum applicatif {SMTP, POP, IMAP, HTTP, FTP_CMD, FTP_DATA, TFTP, TELNET};
static char * const app_names[] = {
	[SMTP] =	"SMTP",
	[POP] =		"POP3",
	[IMAP] = 	"IMAP",
	[HTTP] = 	"HTTP",
    [FTP_CMD] = "FTP connexion de commande",
	[FTP_DATA] ="FTP connexion de donnée",
	[TFTP] = 	"Trivial FTP",
    [TELNET] = 	"TELNET"
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

void affiche_applicatif(enum applicatif app,const uchar* data, size_t size,int serv, int v, char* tab);

void affiche_SMTP(const uchar* data, size_t size,int ser, int v, char* tab);
void affiche_HTML(const uchar* data, size_t size, int serv, int v, char* tab);

void affiche_TFTP(const uchar* data, int size, int serv, int v, char* tab);

void affiche_TELNET(const uchar* data, size_t size, int serv, int v, char* tab);

#endif