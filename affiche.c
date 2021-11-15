#include "affiche.h"
#include "const.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PRINTLINE() printf("______________________________________\n");

#define ABSA(a) (a<0?-a+2:a)
void 
afficheAddr(struct arp_adr* a, int size)
{
  switch (size)
  {
  case 4:
    for (int i=0;i<4;i++)
      printf("%d.",ABSA(a->add[i]));
    
    break;
  case 6 :
    for (int i=0;i<6;i++)
      printf("%x:",ABSA(a->add[i])); //use ABSA car addresse sont sur unsigned
    
  break;
  default: 
    for (int i=0;i<size;i++)
      printf("%x|",ABSA(a->add[i]));
    break;
  }
  printf("\n");
}

void 
afficheIPaddr(uint32_t addr)
{
  printf("%d.%d.%d.%d", addr & 255, addr>>8 & 255,
	 addr>>16 & 255,
	 addr>>24 & 255);
}

void
affiche_ETH(const struct ether_header *ethernet, int v)
{
  if (v==2 || v==3){
    printf("ETHERNET : src=");
    for (int i=0; i<ETH_ALEN-1;i++)
      printf("%x:",ethernet->ether_shost[i]);
    printf("%x >> dst=",ethernet->ether_shost[ETH_ALEN-1]);
     for (int i=0; i<ETH_ALEN-1;i++)
      printf("%x:",ethernet->ether_dhost[i]);
     printf("%x", ethernet->ether_dhost[ETH_ALEN-1]);	   
  }
  if (v==2)
    printf("\n");
  if (v==3)
    printf(" | type=%x\n", ntohs(ethernet->ether_type));
}

void
affiche_IP(const struct iphdr *ip, int v)

{
  //affiche IP src IP dst et protocol utiliser
  switch (v)
  {
  case 1:
    printf("IP | ");
    break;
  
  case 2 :
    printf("IP:src=");
    afficheIPaddr(ip->saddr);
    printf(" >> dst=");
    afficheIPaddr(ip->daddr);
    printf("\n");
    break;
  case 3 :
    PRINTLINE();
    printf("\t\tIP\n");
    printf("|version=%d|taille header=%d|TOS=%d|taille total=%d|\n",
	   ip->version, ip->ihl, ip->tos, ip->tot_len);
    //cas ou pas de gragmentation
    printf("|identification=%d|flags=%x|fragmentation offset=%d|\n",
	   ip->id, ip->frag_off>>14,ip->frag_off & ~(2<<14));
    printf("|TTL=%d|protocol=%d|header checksum=%x|\n",
	   ip->ttl, ip->protocol, ip->check);
    printf("|source addresse = ");
    afficheIPaddr(ip->saddr);
    printf("|\n|destination addresse = ");
    afficheIPaddr(ip->daddr);
    printf("|\n");  
    break;
  }
   
}
void 
affiche_ARP(const struct arphdr *arp, int v)
{
  switch (v)
  {
  case 1 :
    printf("%s operation %s | ",
  (arp->ar_op>>8<ARPOP_RREQUEST?"ARP":"RARP"),
  ((arp->ar_op>>8==ARPOP_REQUEST || arp->ar_op>>8==ARPOP_RREQUEST)?"request":(arp->ar_op>>8==ARPOP_REPLY || arp->ar_op>>8==ARPOP_RREPLY)?"reply":"autre")
    );
    break;
  case 2 :
  case 3 :
    printf("%s : type : %s | protocol : %s | operation : %s %x\n",
    (arp->ar_op>>8<ARPOP_RREQUEST?"ARP":"RARP"),
    (arp->ar_hln==ETH_ALEN?"ethernet":"autre"), 
    (arp->ar_pln==4?"IPv4":"autres"),
    ((arp->ar_op>>8==ARPOP_REQUEST || arp->ar_op>>8==ARPOP_RREQUEST)?"request":(arp->ar_op>>8==ARPOP_REPLY || arp->ar_op>>8==ARPOP_RREPLY)?"reply":"autre"),
    arp->ar_op>>8);
    break;
  }
}

void affiche_UDP(const struct udphdr * udp, int v){
  switch (v)
  {
  case 1 : 
    printf("UDP | ");
    break;
  case 2 :
    printf("UDP : port source : %x | port destination : %x\n",
    udp->source, udp->dest);
    break;
  case 3 :
    PRINTLINE();
    printf("UDP\nport source : %x | port destination : %u\nlength udp %d | checksum : %d\n",
    udp->source, udp->dest, udp->len, udp->check);
    break;
  }
}

void affiche_TCP(const struct tcphdr* tcp, int v){
  switch (v)
  {
  case 1 :
    printf("TCP | ");
    break;
  case 2 :
    printf("TCP : source port %d | destination port %d\n", 
      tcp->source, tcp->dest);
    break;
  case 3 :
    printf("TCP : source port %d | destination port %d \n flags : ",
      tcp->source, tcp->dest);
    uint8_t tcp_flag=tcp->th_flags;
    if (tcp_flag & TH_FIN)
      printf("FIN ");
    if (tcp_flag & TH_SYN)
      printf("SYN");
    if (tcp_flag & TH_RST)
      printf("RST "); 
    if (tcp_flag & TH_PUSH)
      printf("PUSH ");
    if (tcp_flag & TH_ACK)
      printf("ACK ");
    if (tcp_flag & TH_URG)
      printf("URGENT ");
    printf("|\n");   

    break;
  }
}

void affiche_Bootp(const struct bootp* bootp, int v, const u_char* vend){
  switch (v)
  {
  case 1 :
    printf("BOOTP");
    break;
  case 2 :
    printf("BOOTP : info\n");
  break;
  case 3 :
    PRINTLINE();
    printf("BOOTP \n");
    
    if (vend[0]==0x63 && vend[1]==0x82 && vend[2]==0x53 && vend[3]==0x63)
      printf("MAGIC COOKIE\n");
    else {
      printf("MAGIC COOKIE INVALID\n");
      return;
    }
    int i=4, len;
    while (vend[i]!=0xff && i<64){
    switch (vend[i])
    {
    case 53:
      len=vend[++i];
      printf("MSG TYPE : %x \n", vend[++i]);
      i+=len;
      break;
    
    default:
      printf("TYPE : %x ",vend[i++]);
      len=vend[i++];
      printf("LEN : %d MSG :",len);
      for (int k=0;k<len;k++){
        printf("%x ",vend[i+k]);
      }
      printf("\n");
      i+=len;
      break;
    }
    }
    //printf("%x",vend[4]);
    
  }
}