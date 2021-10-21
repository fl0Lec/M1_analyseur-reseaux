#include "capture.h"
#include <stdlib.h>
int cpt = 0;
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  int v=2;
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
	printf("UDP\n");
      }
      //traite TCP
      if (ip->protocol==TCP){
	printf("TCP\n");
      }
      break;
      
    case ETHERTYPE_ARP: ;
      const struct arp *arp;
      arp= (struct arp*)(packet+size);
      size+=sizeof(struct arp);	    

      affiche_ARPR(arp);
      struct arp_adr phy, proto;
      
      for (int i=0;i<2;i++){
        phy.add=(char*)(packet+size);
        size+=arp->L_phy;
        proto.add=(char*)(packet+size);
        size+=arp->L_pro;        
        afficheAddr(&phy, arp->L_phy);
        afficheAddr(&proto, arp->L_pro);
      }
      
      //10.3.-115.1.

      
      break;

    case ETHERTYPE_REVARP:
      printf("RARP\n");
      break;
    }
}