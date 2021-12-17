#include "affiche.h"
#include "const.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "afficheDHCP.c"

#define ABSA(a) (a<0?-a+2:a)

void 
afficheAddr(const uchar* a, int size) //pas necessairement arp_adr mais une struct qui contient char* avec les adresses
{
  switch (size)
  {
  case 4:
    for (int i=0;i<4;i++)
      printf("%d.",ABSA(a[i]));
    
    break;
  case 6 :
    for (int i=0;i<6;i++)
      printf("%x:",ABSA(a[i])); //use ABSA car addresse sont sur unsigned
    
  break;
  default: 
    for (int i=0;i<size;i++)
      printf("%x|",ABSA(a[i]));
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
      printf("%s|pas de fragmentation|\n",tab);
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

void 
affiche_UDP(const struct udphdr * udp, int v, char *tab)
{
  switch (v)
  {
  case 1 : 
    printf("UDP | ");
    break;
  case 2 :
    printf("UDP : port source : %d | port destination : %d\n",
    REVUINT(udp->source), REVUINT(udp->dest));
    break;
  case 3 :
    printf("%s\tUDP\n%s|port source : %d | port destination : %d\n%s|length udp %d | checksum : %d\n",
    tab, tab, REVUINT(udp->source), REVUINT(udp->dest), 
    tab, udp->len, udp->check);
    break;
  }
}

void 
affiche_DNS(const struct dns_header* header, const u_char *packet, int v, char* tab)
{
  int k=0;
  switch (v)
  {
  case 1:
    printf("| DNS : %s ", (header->flags&0x80?"reponse": "demande"));
    break;
  case 2: 
    printf("DNS : %s : demande sur ", (header->flags&0x80?"reponse": "demande"));

    for (int i=0; i<(header->QDcount>>8)+((header->QDcount&0xff)<<8); i++){
      //taille prochain champs
      while (packet[k]!=0){
        //parcours champs
        for (int j=1; j<=packet[k];j++)
          printf("%c", packet[k+j]);

        k+=packet[k]+1;
        printf(".");
      }
      printf(" / ");
      //pour extra champs 
      k+=5;
    }
    printf("\n");
    break;
  default://3
    printf("%s\tDNS\n%sid : %x| type : %s | number of question : %x | number of answer : %x\n", tab, tab,
    (header->id>>8)+((header->id&0xff)<<8), 
    (header->flags&0x80?"reponse": "demande"), 
    (header->QDcount>>8)+((header->QDcount&0xff)<<8), 
    (header->ANcount>>8)+((header->ANcount&0xff)<<8));
    char nom[100];
    //pour chaque question
    for (int i=0; i<(header->QDcount>>8)+((header->QDcount&0xff)<<8); i++){
      printf("%sDemande %d : ",tab, i+1);
      //taille prochain champs
      while (packet[k]!=0){
        //parcours champs
        for (int j=1; j<=packet[k];j++){
          printf("%c", packet[k+j]);
          if (i==1) nom[k+j]=packet[k+j];
        }
        k+=packet[k]+1;
        printf(".");
        if (i==1) nom[k]='.';
      }
      nom[k]='\0';
      printf("\n");
      //pour extra champs 
      k+=5;
    }
    
    for (int i=0; i<(header->ANcount>>8)+((header->ANcount&0xff)<<8); i++){
      printf("%sReponse %d : ", tab, i+1);
      struct dns_response r;
      //construction namuel par pointeur ne fonctionne pas pour raison inconnu
      r.name = packet[k]*16+packet[k+1];
      r.type = packet[k+2]*16+packet[k+3];
      r.class = packet[k+4]*16+packet[k+5];
      r.TTL = (packet[k+6]<<24)+(packet[k+7]<<16)+(packet[k+8]<<8)+packet[k+9]; 
      r.len = packet[k+10]*16+packet[k+11];

      printf("nom : %s | type : %s | class : %s | ttl : %d | ",
        nom+(r.name&0xff)-12, 
        (r.type==1?"host address":r.type==2?"NS":r.type==5?"CNAME":"inconnu"),
        (r.class==1?"IN":"inconnu"), 
        r.TTL);
      switch (r.len)
      {
      case 2:
        printf("reference to : %s\n",nom+packet[k+13]-12);
        break;
      case 4:
        printf("addresse :");
        afficheAddr(packet+k+12, 4);
      default:
        break;
      }
      k+=12+r.len;
    }
      break;
  }
} 