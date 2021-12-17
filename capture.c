#include <net/ethernet.h>
#include <netinet/ip.h>
#include<netinet/udp.h>
#include<netinet/tcp.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "capture.h"
#include "affiche.h"
#include "const.h"
#include "dns.h"

int cpt = 0;
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  int v=(int)*args;
  char tab[10];
  printf("\n\nPacket : %d\n",cpt++);
  uint size=0;
  const struct ether_header *ethernet;
  ethernet = (struct ether_header*)(packet);
  size+=sizeof(struct ether_header);
  affiche_ETH(ethernet, v, tab);
  tab[0]='\t';
  tab[1]='\0';
  //traite ip
  switch (ntohs(ethernet->ether_type))
    {
      
    case ETHERTYPE_IP : ;
      const struct iphdr *ip;
      ip = (struct iphdr*)(packet +size);
      size+=ip->ihl*4;//;sizeof(struct iphdr);
      //printf("size ip %ld\n", sizeof(struct iphdr));
      affiche_IP(ip,v, tab);
      strcat(tab, "\t");
      //check version + option ?
      //traite UDP
      if (ip->protocol==UDP){
	      const struct udphdr *udp;
        udp = (struct udphdr*)(packet+size);
        size+=sizeof(struct udphdr);
        affiche_UDP(udp, v, tab);
        strcat(tab, "\t");
        switch (udp->uh_dport)
        {
        case BOOTP_PORT_CLIENT :
        case BOOTP_PORT_SERVER : 
          ;
          const struct bootp *bootp;
          bootp = (struct bootp*)(packet+size);
          size+=sizeof(struct bootp);
          
          affiche_Bootp(bootp, v, packet+size, tab);
          break;
        case DNS_port :
          ;
          const struct dns_header *dns;
          dns = (struct dns_header*) (packet+size);
          size+=sizeof(struct dns_header);
          affiche_DNS(dns, packet+size, v, tab);
          //printf("DNS\n");
        
        default:
          switch (udp->uh_sport)
          {
          case DNS_port :
            ;
          const struct dns_header *dns;
          dns = (struct dns_header*) (packet+size);
          size+=sizeof(struct dns_header);
          affiche_DNS(dns, packet+size, v, tab);
          //printf("DNS\n");
            break;
          
          default:
            break;
          }
          break;
        }

      }
      //traite TCP
      else if (ip->protocol==TCP){
        const struct tcphdr *tcp;
        tcp = (struct tcphdr*) (packet+size);
        size+=sizeof(struct tcphdr);
	      affiche_TCP(tcp, v, tab);
        strcat(tab, "\t");
        size_t payload = REVUINT(ip->tot_len)-tcp->doff*4-ip->ihl*4;
        if (tcp->source==0x1900 || tcp->dest==0x1900){
          
          affiche_SMTP(packet+size, payload, (tcp->source==0x1900), v, tab);
        }
      }
      else {
        printf("protocol inconnu ou non implémenter\n");
      }


      break;
    //pas IP mais ARP
    case ETHERTYPE_ARP: ;
      const struct arphdr *arp;
      arp= (struct arphdr*)(packet+size);
      size+=sizeof(struct arphdr);	   
      //si est ARP 
      affiche_ARP(arp, v, tab);
      if (v==3){
        struct arp_adr phy, proto;
          
        for (int i=0;i<2;i++){
          phy.add=(uchar*)(packet+size);
          size+=arp->ar_hln;
          proto.add=(uchar*)(packet+size);
          size+=arp->ar_pln; 
          printf("%s hardware addresse : ",(i==0?"sender":"receiver"));    
          afficheAddr(phy.add, arp->ar_hln);
          printf("%s protocol addresse : ",(i==0?"sender":"receiver")); 
          afficheAddr(proto.add, arp->ar_pln);
      }
      }
      break;

    case ETHERTYPE_REVARP:
      printf("RARP\n");
      break;
    }
    return;
}