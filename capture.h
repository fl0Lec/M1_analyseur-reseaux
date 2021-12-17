#ifndef __capture__
#define __capture__

#include <pcap.h>

#define DNS_port 0x3500

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif