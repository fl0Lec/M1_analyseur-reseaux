#include <pcap.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

#include "affiche.c"
//print err
#define printErr(err) printf("erreur : %s\n",err);
//pour open_live
#define LENGTH_PKT_MAX 100
#define PROMISC 0
#define TO_MS 100
//pour loop
#define NP_PKT_CAPTURE 10
//mdp info tplri

//for IP
#define UDP 0x11
#define TCP 0x06
 
int cpt=0;

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  int v=3;
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
      
    case ETHERTYPE_ARP:
      printf("ARP\n");
      break;

    case ETHERTYPE_REVARP:
      printf("RARP\n");
      break;
    }
  /*
  printf("packet %d dst=",cpt++);
  for (int i=0;i<ETH_ALEN;i++){
    printf("%x:",ethernet->ether_dhost[i]);
  }
  printf("\tsrc=");
  for (int i=0;i<ETH_ALEN;i++){
    printf("%x:",ethernet->ether_shost[i]);
  }
  printf("\t type=%x\n", ntohs(ethernet->ether_type));
  //*/
}

int
main(int argc, char**argv, char** env)
{
  char *dev, errbuf[PCAP_ERRBUF_SIZE];
  /*
  if (!(dev = pcap_lookupdev(errbuf))){
    printErr(errbuf);
    return 2;
  }
  */
  dev = "enp2s0";
  printf("%s\n",dev);
  /*
  bpf_u_int32 *netaddr, *netmask;
  if (pcap_lookupnet(dev, netaddr, netmask, errbuf)==-1){
    printErr(errbuf);
    return 3;
  }
  */
  pcap_t *pcap;
  if (!(pcap=pcap_open_live(dev, LENGTH_PKT_MAX, PROMISC, TO_MS, errbuf))){
    printErr(errbuf);
    return 2;
  }
  int res=pcap_loop(pcap, NP_PKT_CAPTURE, got_packet, NULL);
  printf("nombre packet capturer : %d\n",cpt);
  
  return 0;
}
