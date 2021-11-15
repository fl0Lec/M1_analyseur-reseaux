#include <net/ethernet.h>
#include <netinet/ip.h>
#include<netinet/udp.h>
#include<netinet/tcp.h>
#include <stdlib.h>
#include <stdint.h>

#include "capture.h"
#include "affiche.h"

int cpt = 0;
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  int v=(int)*args;
  printf("\nPacket : %d\n",cpt++);
  uint size=0;
  const struct ether_header *ethernet;
  ethernet = (struct ether_header*)(packet);
  size+=sizeof(struct ether_header);
  affiche_ETH(ethernet, v);
  //traite ip
  switch (ntohs(ethernet->ether_type))
    {
      
    case ETHERTYPE_IP : ;
      const struct iphdr *ip;
      ip = (struct iphdr*)(packet +size);
      size+=sizeof(struct iphdr);
      
      affiche_IP(ip,v);
      //check version + option ?
      //traite UDP
      if (ip->protocol==UDP){
	      const struct udphdr *udp;
        udp = (struct udphdr*)(packet+size);
        size+=sizeof(struct udphdr);
        affiche_UDP(udp, v);

      }
      //traite TCP
      if (ip->protocol==TCP){
        const struct tcphdr *tcp;
        tcp = (struct tcphdr*) (packet+size);
        size+=sizeof(struct tcphdr);
	      affiche_TCP(tcp, v);
      }
      break;
      
    case ETHERTYPE_ARP: ;
      const struct arphdr *arp;
      arp= (struct arphdr*)(packet+size);
      size+=sizeof(struct arphdr);	   
      //si est ARP 
      affiche_ARP(arp, v);
      if (v==3){
        struct arp_adr phy, proto;
          
        for (int i=0;i<2;i++){
          phy.add=(char*)(packet+size);
          size+=arp->ar_hln;
          proto.add=(char*)(packet+size);
          size+=arp->ar_pln; 
          printf("%s hardware addresse : ",(i==0?"sender":"receiver"));    
          afficheAddr(&phy, arp->ar_hln);
          printf("%s protocol addresse : ",(i==0?"sender":"receiver")); 
          afficheAddr(&proto, arp->ar_pln);
      }
      }
      break;

    case ETHERTYPE_REVARP:
      printf("RARP\n");
      break;
    }
}