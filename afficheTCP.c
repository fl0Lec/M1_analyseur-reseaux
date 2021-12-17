#include <stdio.h>
#include "affiche.h"

#define ASCII(c) ((c>=' ' && c<=126)?c:'.')

void 
affiche_TCP(const struct tcphdr* tcp, int v, char *tab){
  switch (v)
  {
  case 1 :
    printf("TCP | ");
    break;
  case 2 :
    printf("TCP : source port %d | destination port %d\n", 
      REVUINT(tcp->source), REVUINT(tcp->dest));
    break;
  case 3 :
    printf("%s\tTCP\n%ssource port %d | destination port %d \n%sflags : ",
      tab, tab, REVUINT(tcp->source), REVUINT(tcp->dest), tab);
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
    printf("\n");   

    break;
  }
}

void 
affiche_SMTP(const uchar* data, size_t size, int serv, int v, char* tab)
{
    switch (v)
    {
    case 1:
        printf("| SMTP ");
        break;
    case 2:
        printf("SMTP :  %s\n", (serv?"serveur->client":"client->serveur"));
        break;
    default:

        printf("%s\tSMTP\n", tab);
        printf("%s%s\n", tab, (serv?"serveur->client":"client->serveur"));
        PRINTLINE();
        for (int i=0; i<size; i++){
            if (data[i]==13 && data[i+1]==10){
                printf("\n");
                i+=1;
            }
            else 
                printf("%c",ASCII(data[i]));
        }
        printf("\n");
    break;
    }

}