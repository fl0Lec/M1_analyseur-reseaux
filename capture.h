#ifndef __capture__
#define __capture__

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <pcap.h>
#include "affiche.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif