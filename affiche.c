#define PRINTLINE() printf("______________________________________\n");
void afficheIPaddr(uint32_t addr)
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
affiche_IP(const struct iphdr *ip, int v){
  //affiche IP src IP dst et protocol utiliser
  if (v==2){
    printf("IP:src=");
    afficheIPaddr(ip->saddr);
    printf(" >> dst=");
    afficheIPaddr(ip->daddr);
    printf("\n");
  }
  if (v==3){
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
    
      

  }
}
