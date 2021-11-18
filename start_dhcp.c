void afficheAddBootp(const u_char* vend, int len){
  int i=1;//type=vend[0];
  for (;i<len;i++){
    printf("%x:",vend[i]);
  }
  printf("\b ");
}

void afficheIPBootp(const u_char* vend, int len){
  if (len!=4)
    printf("longueur address non valde : %d attendu 4",len);
  else {
    for (int i=0;i<len;i++){
      printf("%d.",vend[i]);
    }
    printf("\b ");
  }
}

void afficheTimeBootp(const u_char* vend, int len){
  if (len!=4){
    printf("longeur invalide %d",len);
  }
  else {
    uint32_t time=0;
    for (int k=0;k<len;k++){
      time=(time<<8)+vend[k];
      }
      if (time!=0xffffff)
        printf("%d",time);
      else 
        printf("infini");
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
