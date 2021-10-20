#include <pcap.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

//print err
#define printErr(err) printf("erreur : %s\n",err);
//pour open_live
#define LENGTH_PKT_MAX 100
#define PROMISC 0
#define TO_MS 100
//pour loop
#define NP_PKT_CAPTURE 20
//mdp info tplri

//for IP
#define UDP 0x11
#define TCP 0x06

//ARP
struct arp {
  unsigned int type:16;
  unsigned int protocol:16;
  unsigned int L_phy:8;
  unsigned int L_pro:8;
  unsigned int operation:16;
};

#include "affiche.c"
int cpt=0;

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
      printf("ARP\n");
      affiche_ARPR(arp);
      break;

    case ETHERTYPE_REVARP:
      printf("RARP\n");
      break;
    }
}

int
main(int argc, char**argv, char** env)
{
  char *dev, errbuf[PCAP_ERRBUF_SIZE];
  bpf_u_int32 netaddr, netmask;
  pcap_if_t *alldev;
  pcap_t *pcap;

  //addresse sous reseau
  //pcap_lookupnet(dev, netaddr, netmask);
  if (pcap_findalldevs(&alldev, errbuf)==-1){
    printf("%s",errbuf);
    return 1;
  }
  if (alldev==NULL){
    printf("no device found\n");
    return 10;
  }
  else{
    dev = alldev->name;
  }
  
  if (pcap_lookupnet(dev, &netaddr, &netmask, errbuf)==-1){
    printf("%s\n",errbuf);
    netaddr=0;
    netmask=0;
  }
  //printf("%s %d %d\n",dev, netaddr, netmask);
  if (!(pcap=pcap_open_live(dev, LENGTH_PKT_MAX, PROMISC, TO_MS, errbuf))){
    printErr(errbuf);
    return 2;
  }

  struct bpf_program filter;
  char* filter_exp = "tcp"; 
  if (pcap_compile(pcap, &filter, filter_exp, 0, netmask)==-1){
    printf("%s\n",errbuf);
    return 3;
  }
  if(pcap_setfilter(pcap, &filter)==-1){
    printf("%s\n",errbuf);
    return 4;
  }
  int res=pcap_loop(pcap, NP_PKT_CAPTURE, got_packet, NULL);
  printf("nombre packet capturer : %d\n",cpt);
  
  return 0;
}
