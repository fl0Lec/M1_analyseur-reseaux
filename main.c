#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include "affiche.h"

//pour open_live
#define LENGTH_PKT_MAX 100
#define PROMISC 0
#define TO_MS 100
//pour loop
#define NP_PKT_CAPTURE 0
//mdp info tplri



#include "affiche.h"
#include "capture.h"

#define USAGE printf("./mydump [parametre]\n\"-v\"niveau de verbosite\n\"-o fichier\" fichier a ouvrir en mode oflline\n\"-i interface\" interface a ouvrir, mode online\n\"-f filtre\" filtre appilquer (penzez a mettre des guillement)\n\"-h\" affiche cette aide\n");
int
main(int argc, char**argv, char** env)
{  
  char *dev=0, errbuf[PCAP_ERRBUF_SIZE], *ofile_path=0, *filter_exp=0;
  bpf_u_int32 netaddr, netmask;
  pcap_if_t *alldev=0;
  pcap_t *pcap=0;
  u_char verbose=-1;
   
  for (int i=1; i<argc;i++){
    if (strcmp(argv[i], "-i")==0){
      dev = argv[++i];
    }
    else if (strcmp(argv[i],"-o")==0){
      ofile_path = argv[++i];

    }
    else if (strcmp(argv[i], "-f")==0){
      filter_exp = argv[++i];
    }
    else if (strcmp(argv[i], "-v")==0){
      if (verbose!=(u_char)-1){
        printf("erreur vous avez deja defini verbose\n");
        return -1;
      }
      else if ((verbose=atoi(argv[i+1]))>3 || verbose<1){
        printf("erreur verbose compris entre 1 et 3\n");
        return -1;
      }
      i++;
    }
    else if (strcmp(argv[i], "-h")==0){
      USAGE
      return 0;
    }
    else {
      printf("erreur argument %d -h pour aide\n", i);
      return -1;
    }
  }

  //si dev pas déclarer prend le premier que l'on trouve
  if (!dev){
    if (pcap_findalldevs(&alldev, errbuf)==-1){
    printf("%s",errbuf);
    return -1;
    }
    if (alldev==NULL){
      printf("no device found\n");
      return -1;
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
    if (!(pcap=pcap_open_offline(ofile_path, errbuf))){
      fprintf(stderr, "erreur open offline :\n%s\n", errbuf);
      return -1;
    }
  }
  else {
    if (!(pcap=pcap_open_live(dev, LENGTH_PKT_MAX, PROMISC, TO_MS, errbuf))){
      fprintf(stderr, "erreur open live :\n%s\n", errbuf);
      return -1;
    }
  }

  //applique filter si existe 
  if (filter_exp){
    struct bpf_program filter; 
    if (pcap_compile(pcap, &filter, filter_exp, 0, netmask)==-1){
      printf("erreur comile : \n%s\n",errbuf);
      return -1;
    }
    if(pcap_setfilter(pcap, &filter)==-1){
      printf("erreur filtre : \n%s\n",errbuf);
      return -1;
    }
  }

  //verifie verbose 
  verbose = (verbose==255?2:verbose);
  printf("commence capture sur %s  avec verbose de %d et filtrer %s\n",dev, verbose, filter_exp);
  pcap_loop(pcap, NP_PKT_CAPTURE, got_packet, &verbose);
  printf("\x1b[0m\n");
  
  return 0;
}
