#include <stdio.h>
#include "affiche.h"

#define ASCII(c) (c<=126)?c:'-'
#define MIN(a, b) (a<b?a:b)
void 
affiche_TCP(const struct tcphdr* tcp, int v, char *tab){
  switch (v)
  {
  case 1 :
    printf("| TCP ");
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
      printf("SYN ");
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
affiche_applicatif(enum applicatif app, const uchar* data, size_t size,int serv, int v, char* tab)
{
  char* nom = app_names[app];
  switch (v)
  {
  case 1:
  case 2:
    printf("%s : %s : ",nom, (serv?"serveur->client":"client->serveur"));
    if (size==0){
      printf(" pas de contenue applicatif dans ce paquet\n");
      return;
    }
    else {
      printf("\x1b[36m");
      for (int i=0; i<MIN(20, size) && data[i]!=0x0d; i++){          
        printf("%c",ASCII(data[i]));
      }
      printf("\x1b[0m\n");
    }
    break;
  default:
    printf("%s\t%s\n%s%s\n", tab, nom, tab,(serv?"serveur->client":"client->serveur"));
    if (size==0){
      printf("%spas de contenue applicatif dans ce paquet\n", tab);
      return;
    }
    PRINTLINE();
    printf("contenu :\n\x1b[36m");
    for (int i=0; i<size; i++){
      printf("%c",ASCII(data[i]));
      }
    printf("\x1b[0m\n");
    
    break;
  }
}

void 
affiche_TELNET(const uchar* data, size_t size, int serv, int v, char* tab)
{
  switch (v)
  {
  case 1:
  case 2:
    printf("%s : %s : ",app_names[TELNET], (serv?"serveur->client":"client->serveur"));
    if (size==0){
      printf(" pas de contenue applicatif dans ce paquet\n");
      return;
    }
    else {
      printf("\x1b[36m");
      for (int i=0; i<MIN(20, size) && data[i]!=0x0d; i++){          
        ;
      }
      printf("\x1b[0m\n");
    }
    break;
    break;
  
  default:
    printf("%s\t%s\n%s%s\n", tab, app_names[TELNET], tab,(serv?"serveur->client":"client->serveur"));
    if (size==0){
      printf("%spas de contenue applicatif dans ce paquet\n", tab);
      return;
    }
    //PRINTLINE();
    //printf("contenu :\n\x1b[36m");
    size_t i=0;
    while (data[i]==0xff){
      i++;
      printf("%sOption : ", tab);
      switch (data[i])
      {
      case 241:
        printf("no operation");
        break;
      case 242:
        printf("data mark (vide tampon)");
        break;
      case 244:
        printf("Interrupt process");
        break;
      case 245:
        printf("Abort output");
        break;
      case 246:
        printf("Are you there");
        break;
      case 247:
        printf("Erase Charactere");
        break;
      case 248:
        printf("Erase line");
        break;
      case 249:
        printf("go head");
        break;
      case 250:
        printf("suboption : ");
        switch (data[i+1])
        {
        case 1 :
          printf("echo");
          break;
        case 5:
          printf("status");
          break;
        case 3:
          printf("suppres go head");
          break;
        case 24:
          printf("terminal type");
          break;
        case 31:
          printf("window size");
          break; 
        case 32 :
          printf("termina speed");
          break;
        case 33:
          printf("flow control");
        case 34:
          printf("line mode");
          break;
        case 35:
          printf("X Display Location");
          break;
        case 36:
          printf("envrionement varibale");
          break;
        case 37:
          printf("Autentification option");
          break;
        case 38:
          printf("Encryption  option");
          break;
        case 39:
          printf("new environement variable");
          break;
        default:
          printf("option non reconnu %d", data[i]);
          break;
        }
        printf("\n%saffichage au format hexa : \x1b[36m",tab);
        i+=2;
        while (data[i]!=0xff && data[i+1]!=0xf0){
          printf("%x ", data[i++]);
        }
        printf("\x1b[0m\n%ssuboption : end", tab);
        i+=1;
        goto done;
      case 251:
        printf("WILL ");
        break;
      case 252:
        printf("WON'T ");
        break;
      case 253:
        printf("DO ");
        break;
      case 254:
        printf("DON'T ");
        break;
      default:
        printf("non reconnu  ");
        break;
      }
      i++;
      switch (data[i])
      {
      case 1 :
        printf("echo");
        break;
      case 5:
        printf("status");
        break;
      case 3:
        printf("suppres go head");
        break;
      case 24:
        printf("terminal type");
        break;
      case 31:
        printf("window size");
        break; 
      case 32 :
        printf("termina speed");
        break;
      case 33:
        printf("flow control");
      case 34:
        printf("line mode");
        break;
      case 35:
        printf("X Display Location");
        break;
      case 36:
        printf("envrionement varibale");
        break;
      case 37:
        printf("Autentification option");
        break;
      case 38:
        printf("Encryption  option");
        break;
      case 39:
        printf("new environement variable");
        break;
      default:
        printf("option non reconnu %d", data[i]);
        break;
      }
      done:
      i++;
      printf("\n");
    }
    if (i<size){
      printf("Contenu\n\x1b[36m");
      for (; i<size; i++){
        printf("%c",ASCII(data[i]));
      }
      printf("\n\x1b[0m");
    }
    break;
  }
}