#include "affiche.h"
#include "const.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "afficheDHCP.c"

#define ABSA(a) (a<0?-a+2:a)
#define ASCII(c) (c<=126)?c:'-'

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
  if (v==1)
    printf(" ETHERNET ");
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
    printf("| IP ");
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
  case 3 :
    printf("%s", tab);
  case 2 :
    printf("%s : type : %s | protocol : %s | operation : %s %x\n",
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
    printf("| UDP ");
    break;
  case 2 :
    printf("UDP : port source : %x | port destination : %x\n",
    REVUINT(udp->source), REVUINT(udp->dest));
    break;
  case 3 :
    printf("%s\tUDP\n%s|port source : %d | port destination : %d\n%s|length udp %d | checksum : %d\n",
    tab, tab, REVUINT(udp->source), REVUINT(udp->dest), 
    tab, udp->len, udp->check);
    break;
  }
}

size_t 
readDNS_name(const uchar* s, const uchar *start)
{
  size_t i=0;
  while (s[i]!=0){
    if (s[i]==0xc0)
      return readDNS_name(start+s[i+1]-sizeof(struct dns_header), start);
    else {
      for (int j=1; j<=s[i];j++)
            printf("%c", s[i+j]);
          i+=s[i]+1;
          printf(".");
    }
  }
  return i+1;
} 

void 
affiche_DNS(const struct dns_header* header, const u_char *packet, int v, char* tab)
{
  int k=0;
  switch (v)
  {
  case 1:
    printf("| DNS : %s \n", (header->flags&0x80?"reponse": "demande"));
    break;
  case 2: 
    printf("DNS : %s : demande sur ", (header->flags&0x80?"reponse": "demande"));

    for (int i=0; i<(header->QDcount>>8)+((header->QDcount&0xff)<<8); i++){
      //taille prochain champs
      k = readDNS_name(packet+k, packet);
      printf(" / ");
      //pour extra champs 
      k+=5;
    }
    printf("\n");
    break;
  default://3
    printf("%s\tDNS\n%sid : %x| type : %s\n%snombre de question : %x | nnombre de reponse : %x\n%snombre serveur authoritaire %d | record aditionnel : %d\n", tab, tab,
    REVUINT(header->id), 
    (header->flags&0x80?"reponse": "demande"), 
    tab,
    REVUINT(header->QDcount), 
    REVUINT(header->ANcount),
    tab,
    REVUINT(header->NSCount),
    REVUINT(header->ARCount)
    );
    //pour chaque question
    for (int i=0; i<REVUINT(header->QDcount); i++){
      printf("%sDemande %d : ",tab, i+1);
      //taille prochain champs
      k+=readDNS_name(packet+k, packet);
      printf("\n");
      //pour extra champs 
      k+=4;
    }
    
    //pour chaque reponse
    for (int i=0; i<REVUINT(header->ANcount)+REVUINT(header->NSCount)+REVUINT(header->ARCount); i++){
      printf("%s%s %d : ", tab, 
      (i<REVUINT(header->ANcount)?"Reponse":REVUINT(header->ANcount)+REVUINT(header->NSCount)?"Autoritatif":"Autre"), 
      (i<REVUINT(header->ANcount)?i+1:REVUINT(header->ANcount)+REVUINT(header->NSCount)?i+1-REVUINT(header->ANcount):i+1-REVUINT(header->ANcount)+REVUINT(header->NSCount)));
      struct dns_response r;
      //construction namuel par pointeur ne fonctionne pas pour raison inconnu
      r.name = packet[k]*16+packet[k+1];
      printf("nom : ");
      if ((r.name&0xff00)==0xc00)
        readDNS_name(packet+(r.name&0xff)-sizeof(struct dns_header), packet);
      else 
        k+=readDNS_name(packet+k, packet);

      r.type = packet[k+2]*16+packet[k+3];
      r.class = packet[k+4]*16+packet[k+5];
      r.TTL = (packet[k+6]<<24)+(packet[k+7]<<16)+(packet[k+8]<<8)+packet[k+9]; 
      r.len = packet[k+10]*16+packet[k+11];

      printf(" | type : %s | class : %s | ttl : %d | ",
        (r.type==1?"host address":r.type==2?"NS":r.type==5?"CNAME":"inconnu"),
        (r.class==1?"IN":"inconnu"), 
        r.TTL);

      switch (r.len)
      {
      case 4:
        printf("addresse : ");
        afficheAddr(packet+k+12, 4);
        break;
      default:
        printf("reference to : ");
        readDNS_name(packet+k+12, packet);
        printf("\n");
        break;
      }
      k+=12+r.len;
    }
      break;
  }
} 

void 
affiche_TFTP(const uchar* data, int size,  int serv, int v, char* tab)
{
  char* nom = app_names[TFTP];
  uint32_t op, block;
  op = data[0]*16+data[1];
  block = data[2]*16+data[3];
  switch (v)
  {
  case 1:
  case 2:
    printf("%s : %s : ",nom, (serv?"serveur->client":"client->serveur "));
    switch (op)
    {
    case 1:
      printf("Read Request : %s", data+2);
      break;
    case 2 :
      printf("Write Request : %s", data+2);
      break;
    case 3:
      printf("Data : block %d, %d octet", block, size-4);
      break;
    case 4 :
      printf("Ack : block %d", block);
      break;
    case 5 :
      printf("Erreur %s", data+2);
      break;
    default :
      printf("Operation code non reconnu");
      break;
    }
    break;
  default:
    printf("%s\t%s\n%s%s\n", tab, nom, tab,(serv?"serveur->client":"client->serveur"));
    switch (op)
    {
    case 1:
      printf("%sRead Request : %s\n%smode : %s\n",tab, data+2, tab, data+3+strlen((char*)data+2));
      break;
    case 2 :
      printf("%sWrite Request : %s\n%smode : %s\n",tab, data+2,tab, data+3+strlen((char*)data+2));
      break;
    case 3:
      printf("%sData : block %d\n",tab, block);
      PRINTLINE()
      printf("contenu :\n\x1b[36m");
      for (int i=4; i<size;i++){
        printf("%c",ASCII(data[i]));
      }
      printf("\n\x1b[0m");
      break;
    case 4 :
      printf("%sAck : block %d",tab, block);
      break;
    case 5 :
      printf("%sErreur %s",tab, data+2);
      break;
    default :
      printf("Operation code non reconnu");
      break;
    }
    
    break;
  }
}
