#include "affiche.h"
#include "const.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "afficheDHCP.c"
#define PRINTLINE() printf("__________________________________________\n");

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
affiche_ETH(const struct ether_header *ethernet, int v, char *tab)
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
affiche_IP(const struct iphdr *ip, int v, char *tab)

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
    printf("%s|version=%d|taille header=%d|TOS=%d|taille total=%d|\n",tab,
      ip->version, ip->ihl, ip->tos, ip->tot_len);
    //cas ou pas de fragmentation
    if (ip->frag_off>>14)
      printf("%s|identification=%d|flags=%x|fragmentation offset=%d|\n", tab,
	   ip->id, ip->frag_off>>14,ip->frag_off & ~(2<<14));
    else 
      printf("%s|pas de gragmentation|\n",tab);
    printf("%s|TTL=%s|protocol=%d|header checksum=%x|\n", tab,
	   (ip->ttl>0?"OK":"0"), ip->protocol, ip->check);
    printf("%s|source addresse = ", tab);
    afficheIPaddr(ip->saddr);
    printf("|\n%s|destination addresse = ", tab);
    afficheIPaddr(ip->daddr);
    printf("|\n");  
    break;
  }
   
}
void 
affiche_ARP(const struct arphdr *arp, int v, char *tab)
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
    printf("%s%s : type : %s | protocol : %s | operation : %s %x\n",
    tab,
    (arp->ar_op>>8<ARPOP_RREQUEST?"ARP":"RARP"),
    (arp->ar_hln==ETH_ALEN?"ethernet":"autre"), 
    (arp->ar_pln==4?"IPv4":"autres"),
    ((arp->ar_op>>8==ARPOP_REQUEST || arp->ar_op>>8==ARPOP_RREQUEST)?"request":(arp->ar_op>>8==ARPOP_REPLY || arp->ar_op>>8==ARPOP_RREPLY)?"reply":"autre"),
    arp->ar_op>>8);
    break;
  }
}

void affiche_UDP(const struct udphdr * udp, int v, char *tab){
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
    printf("%s\tUDP\n%s|port source : %x | port destination : %x\n%s|length udp %d | checksum : %d\n",
    tab, tab, udp->source, udp->dest, 
    tab, udp->len, udp->check);
    break;
  }
}

void affiche_TCP(const struct tcphdr* tcp, int v, char *tab){
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
    printf("%sTCP : source port %d | destination port %d \n flags : ",
      tab, tcp->source, tcp->dest);
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
/*------------------------------------------------------*/
/*
void afficheAddBootp(const u_char* vend, int len){
  int i=1;//type=vend[0];
  for (;i<len;i++){
    printf("%d.",vend[i]);
  }
}

void afficheIPBootp(const u_char* vend, int len){
  if (len!=4)
    printf("longueur address non valde : %d attendu 4",len);
  else {
    for (int i=0;i<len;i++){
      printf("%d.",vend[i]);
    }
  }
}
void affiche_Bootp(const struct bootp* bootp, int v, const u_char* vend, char *tab){
  switch (v)
  {
  case 1 :
    printf("BOOTP");
    break;
  case 2 :
    printf("BOOTP : info\n");
  break;
  case 3 :
    //PRINTLINE();
    printf("%s\tBOOTP \n", tab);
    
    if (vend[0]==0x63 && vend[1]==0x82 && vend[2]==0x53 && vend[3]==0x63)
      printf("%s|MAGIC COOKIE\n", tab);
    else {
      printf("%s|MAGIC COOKIE INVALID\n", tab);
      return;
    }
    int i=4, len;
    while (vend[i]!=0xff && i<64){
      printf("%s|",tab);
      switch (vend[i])
      {
      case 1:
        printf("Subnet Mask :");
        i++;
        len=vend[i++];
        afficheIPBootp(vend+i, len);
        break;
      //-------------------------------------------------
      //Requested IP Address
      case 50:
        printf("Request IP Address : ");
        i++;
        len=vend[i++];
        afficheIPBootp(vend+i, len);
      break;
      //-------------------------------------------------
      case 51:
        printf("IP Address Lease Time : ");
        i++;
        len=vend[i++];
         if (len==4){
           //const uint32_t *time; time=vend+i;
           //il ya des problemes ici
           uint32_t time=0;
           for (int k=0;k<len;k++){
             //printf("\n %x %x %x ",vend[i+k], expo, time);
             time=(time<<8)+vend[i+k];
           }
           if (time!=0xffffff)
             printf("%d",time);
           else 
            printf("infini");
         } else {
          printf("longeur invalide %d",len);
        }
        break;
      //-------------------------------------------------
      case 52 :
      printf("Option Overload : ");
      i++;
      len=vend[i++];
      if (len==1){
        switch (vend[i])
        {
        case 1:
          printf("fichier utiliser");
          break;
        case 2:
          printf("sname utiliser");
          break;
        break;
        case 3:
          printf("fichier et sname utiliser");
          break;
        default:
          printf("non reconnu");
          break;
        }
      }
      else 
        printf("longueur non attentdu");
      break;
      //-------------------------------------------------
      
      //DCHP Message Type
      case 53:
        printf("DHCP Message Type : ");
        i++;
        len=vend[i++];
        switch (vend[i])
        {
        case  1:
          printf("discovery");
          break;
        case 2:
          printf("offer");
          break;
        case 3:
          printf("request");
          break;
        case 4:
          printf("decline");
          break;
        case 5: 
          printf("ack");
          break;
        case 6:
          printf("nack");
          break;
        case 7:
          printf("realse");
          break;
        case 8:
          printf("informe");
          break;
        default:
          printf("non reconnu %x", vend[i++]);
          break;
        }
        break;
      //-------------------------------------------------
      case 54 :
        i++;
        len=vend[i++];
        printf("Server Identifier :");
        if (len==4){
          for (int k=0;k<4;k++){
            printf("%d.",vend[i+k]);
          }
        } else {
          printf("longueur non valide : %d",len);
        }
        break;
      //-------------------------------------------------
      case 55 :
        i++;
        len=vend[i++];
        printf("Parameter Request List :");
        for (int k=0;k<len;k++){
          switch (vend[i+k])
          {
          case 1:
            printf("subnet mask, ");
            break;
          case 3:
            printf("router ");
            break;
          case 6:
            printf("DNS ");
            break;
          case 15:
            printf("domain name ");
            break;
          case 28 :
            printf("broadcast address ");
            break;
          default:
            printf("%d ",vend[i+k]);
            break;
          }
        }
        break;
      //-------------------------------------------------
      case 61:
        i++;
        len=vend[i++];
        printf("Client Id :");
        afficheAddBootp(vend+i, len);
        break;
      //-------------------------------------------------
      default:
        printf("TYPE : %d ", vend[i++]);
        len=vend[i++];
        printf("LEN : %d MSG :",len);
        for (int k=0;k<len;k++){
          printf("%x ",vend[i+k]);
        }
        break;
      }
      printf("\n");
      i+=len;
    }
    //printf("%x",vend[4]);
    
  }
}
//*/