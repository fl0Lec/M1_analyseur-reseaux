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
int tftp=-1;
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  int v=(int)*args;
  char tab[10];
  printf("\nPacket : %d %c",++cpt, (v==1?'|':'\n'));
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
          break;
        case TFTP_port : ;
          tftp=udp->uh_sport;
          affiche_TFTP(packet+size, REVUINT(udp->len)-sizeof(struct udphdr), udp->uh_sport==tftp, v, tab);
          break;
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
            if (udp->uh_sport == tftp || udp->uh_dport == tftp){
              affiche_TFTP(packet+size, REVUINT(udp->len)-sizeof(struct udphdr), udp->uh_sport==tftp, v, tab);
              break;
            }
            printf(" | port application non implementer ou reconnu");
            break;
          }
          break;
        }

      }
      //traite TCP
      else if (ip->protocol==TCP){
        const struct tcphdr *tcp;
        tcp = (struct tcphdr*) (packet+size);
        size+=(tcp->doff*4);
	      affiche_TCP(tcp, v, tab);
        strcat(tab, "\t");
        size_t payload = REVUINT(ip->tot_len)-tcp->doff*4-ip->ihl*4;
        //printf("ip : %d | ip ihl : %d | tcp->doff : %d | %d", REVUINT(ip->tot_len), ip->ihl*4, tcp->doff, payload);
        if (tcp->source==SMTP_port || tcp->dest==SMTP_port)
          affiche_applicatif(SMTP, packet+size, payload, tcp->source==SMTP_port, v, tab);
        else if (tcp->source==IMAP_port || tcp->dest==IMAP_port)
          affiche_applicatif(IMAP, packet+size, payload, tcp->source==IMAP_port, v, tab);
        else if (tcp->source==POP_port || tcp->dest==POP_port)
          affiche_applicatif(POP, packet+size, payload, tcp->source==POP_port, v, tab);
        else if (tcp->source==HTTP_port || tcp->dest==HTTP_port)
          affiche_applicatif(HTTP, packet+size, payload, tcp->source==HTTP_port, v, tab);
        else if (tcp->source==FTP_port_CMD || tcp->dest==FTP_port_CMD)
          affiche_applicatif(FTP_CMD, packet+size, payload, tcp->source==FTP_port_CMD, v, tab);
        else if (tcp->source==FTP_port_DATA || tcp->dest==FTP_port_DATA)
          affiche_applicatif(FTP_CMD, packet+size, payload, tcp->source==FTP_port_DATA, v, tab);
        else if (tcp->source==TELNET_port || tcp->dest==TELNET_port)
          affiche_TELNET(packet+size, payload, tcp->source==TELNET_port, v, tab);
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
  if (v!=1)
    printf("\n\n");
  return;
}