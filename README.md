# Analyseur Reseau

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

