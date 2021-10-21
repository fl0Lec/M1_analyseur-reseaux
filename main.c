#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include "affiche.h"
//print err
#define printErr(err) printf("erreur : %s\n",err);
//pour open_live
#define LENGTH_PKT_MAX 100
#define PROMISC 0
#define TO_MS 100
//pour loop
#define NP_PKT_CAPTURE 5
//mdp info tplri



#include "affiche.h"
#include "capture.h"


int
main(int argc, char**argv, char** env)
{
  char *dev, errbuf[PCAP_ERRBUF_SIZE], *ofile_path, *filter_exp;
  bpf_u_int32 netaddr, netmask;
  pcap_if_t *alldev;
  pcap_t *pcap;
  int verbose=-1;
  if ((argc-1)%2){
    printf("erreur attend nom et paramètre -h");
    return 2;
  }

  for (int i=1; i<argc-1;i++){
    if (strcmp(argv[i], "-i")==0){
      dev = argv[i+1];
    }
    else if (strcmp(argv[i],"-o")==0){
      ofile_path = argv[i+1];
    }
    else if (strcmp(argv[i], "-f")==0){
      filter_exp = argv[i+1];
    }
    else if (strcmp(argv[i], "-v")==0){
      if (verbose!=-1){
        printf("erreur vous avez deja defini verbose\n");
        return 6;
      }
      else if ((verbose=atoi(argv[i+1]))>3 || verbose<1){
        printf("erreur verbose compris entre 1 et 3\n");
        return 7;
      }
    }
  }

  //si dev pas déclarer prend le premier que l'on trouve
  if (!dev){
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
  }

  //trouve l'addresse et le masque de l'interface
  if (pcap_lookupnet(dev, &netaddr, &netmask, errbuf)==-1){
    printf("%s\n",errbuf);
    netaddr=0;
    netmask=0;
  }
  
  //ouvre pcap en live ou dans file
  if (ofile_path){
    if (!(pcap_open_offline(ofile_path, errbuf))){
      printErr(errbuf);
      return 3;
    }
  }
  else {
    if (!(pcap=pcap_open_live(dev, LENGTH_PKT_MAX, PROMISC, TO_MS, errbuf))){
      printErr(errbuf);
      return 3;
    }
  }

  //applique filter si existe 
  if (filter_exp){
    struct bpf_program filter; 
    if (pcap_compile(pcap, &filter, filter_exp, 0, netmask)==-1){
      printf("%s\n",errbuf);
      return 3;
    }
    if(pcap_setfilter(pcap, &filter)==-1){
      printf("%s\n",errbuf);
      return 4;
    }
  }

  //verifie verbose 
  verbose = (verbose==-1?1:verbose);
  printf("commence capture sur %s  avec verbose de %d et filtrer %s\n",dev, verbose, filter_exp);
  pcap_loop(pcap, NP_PKT_CAPTURE, got_packet, NULL);
  //printf("nombre packet capturer : %d\n",cpt);
  
  return 0;
}
