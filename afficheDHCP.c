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
case 0 :
	i++;
	len=vend[i++];
	printf("Pad : ");
	i--;
	len=0;	break;

case 1 :
	i++;
	len=vend[i++];
	printf("Subnet Mask : ");
	afficheIPBootp(vend+i, len);	break;

case 2 :
	i++;
	len=vend[i++];
	printf("Time Offset : ");
	afficheTimeBootp(vend+i, len);
	break;

case 3 :
	i++;
	len=vend[i++];
	printf("Router : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 4 :
	i++;
	len=vend[i++];
	printf("Time Server : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 5 :
	i++;
	len=vend[i++];
	printf("Name Server : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 6 :
	i++;
	len=vend[i++];
	printf("Domain Server : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 7 :
	i++;
	len=vend[i++];
	printf("Log Server : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 8 :
	i++;
	len=vend[i++];
	printf("Quotes Server : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 9 :
	i++;
	len=vend[i++];
	printf("LPR Server : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 10 :
	i++;
	len=vend[i++];
	printf("Impress Server : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 11 :
	i++;
	len=vend[i++];
	printf("RLP Server : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 12 :
	i++;
	len=vend[i++];
	printf("Hostname : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 13 :
	i++;
	len=vend[i++];
	printf("Boot File Size : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 14 :
	i++;
	len=vend[i++];
	printf("Merit Dump File : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 15 :
	i++;
	len=vend[i++];
	printf("Domain Name : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 16 :
	i++;
	len=vend[i++];
	printf("Swap Server : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 17 :
	i++;
	len=vend[i++];
	printf("Root Path : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 18 :
	i++;
	len=vend[i++];
	printf("Extension File : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 19 :
	i++;
	len=vend[i++];
	printf("Forward On/Off : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 20 :
	i++;
	len=vend[i++];
	printf("SrcRte On/Off : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 21 :
	i++;
	len=vend[i++];
	printf("Policy Filter : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 22 :
	i++;
	len=vend[i++];
	printf("Max DG Assembly : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 23 :
	i++;
	len=vend[i++];
	printf("Default IP TTL : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 24 :
	i++;
	len=vend[i++];
	printf("MTU Timeout : ");
	afficheTimeBootp(vend+i, len);
	break;

case 25 :
	i++;
	len=vend[i++];
	printf("MTU Plateau : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 26 :
	i++;
	len=vend[i++];
	printf("MTU Interface : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 27 :
	i++;
	len=vend[i++];
	printf("MTU Subnet : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 28 :
	i++;
	len=vend[i++];
	printf("Broadcast Address : ");
	afficheIPBootp(vend+i, len);	break;

case 29 :
	i++;
	len=vend[i++];
	printf("Mask Discovery : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 30 :
	i++;
	len=vend[i++];
	printf("Mask Supplier : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 31 :
	i++;
	len=vend[i++];
	printf("Router Discovery : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 32 :
	i++;
	len=vend[i++];
	printf("Router Request : ");
	afficheIPBootp(vend+i, len);	break;

case 33 :
	i++;
	len=vend[i++];
	printf("Static Route : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 34 :
	i++;
	len=vend[i++];
	printf("Trailers : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 35 :
	i++;
	len=vend[i++];
	printf("ARP Timeout : ");
	afficheTimeBootp(vend+i, len);
	break;

case 36 :
	i++;
	len=vend[i++];
	printf("Ethernet : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 37 :
	i++;
	len=vend[i++];
	printf("Default TCP TTL : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 38 :
	i++;
	len=vend[i++];
	printf("Keepalive Time : ");
	afficheTimeBootp(vend+i, len);
	break;

case 39 :
	i++;
	len=vend[i++];
	printf("Keepalive Data : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 40 :
	i++;
	len=vend[i++];
	printf("NIS Domain : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 41 :
	i++;
	len=vend[i++];
	printf("NIS Servers : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 42 :
	i++;
	len=vend[i++];
	printf("NTP Servers : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 43 :
	i++;
	len=vend[i++];
	printf("Vendor Specific : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 44 :
	i++;
	len=vend[i++];
	printf("NETBIOS Name Srv : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 45 :
	i++;
	len=vend[i++];
	printf("NETBIOS Dist Srv : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 46 :
	i++;
	len=vend[i++];
	printf("NETBIOS Node Type : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 47 :
	i++;
	len=vend[i++];
	printf("NETBIOS Scope : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 48 :
	i++;
	len=vend[i++];
	printf("X Window Font : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 49 :
	i++;
	len=vend[i++];
	printf("X Window Manager : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 50 :
	i++;
	len=vend[i++];
	printf("Address Request : ");
	afficheIPBootp(vend+i, len);	break;

case 51 :
	i++;
	len=vend[i++];
	printf("Address Time : ");
	afficheTimeBootp(vend+i, len);
	break;

case 52 :
	i++;
	len=vend[i++];
	printf("Overload : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 53 :
	i++;
	len=vend[i++];
	printf("DHCP Msg Type : ");
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

case 54 :
	i++;
	len=vend[i++];
	printf("DHCP Server Id : ");
	afficheIPBootp(vend+i, len);	break;

case 55 :
	i++;
	len=vend[i++];
	printf("Parameter List : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 56 :
	i++;
	len=vend[i++];
	printf("DHCP Message : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 57 :
	i++;
	len=vend[i++];
	printf("DHCP Max Msg Size : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 58 :
	i++;
	len=vend[i++];
	printf("Renewal Time : ");
	afficheTimeBootp(vend+i, len);
	break;

case 59 :
	i++;
	len=vend[i++];
	printf("Rebinding Time : ");
	afficheTimeBootp(vend+i, len);
	break;

case 60 :
	i++;
	len=vend[i++];
	printf("Class Id : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 61 :
	i++;
	len=vend[i++];
	printf("Client Id : ");
	afficheAddBootp(vend+i, len);	break;

case 62 :
	i++;
	len=vend[i++];
	printf("NetWare/IP Domain : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 63 :
	i++;
	len=vend[i++];
	printf("NetWare/IP Option : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 64 :
	i++;
	len=vend[i++];
	printf("NIS-Domain-Name : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 65 :
	i++;
	len=vend[i++];
	printf("NIS-Server-Addr : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 66 :
	i++;
	len=vend[i++];
	printf("Server-Name : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 67 :
	i++;
	len=vend[i++];
	printf("Bootfile-Name : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 68 :
	i++;
	len=vend[i++];
	printf("Home-Agent-Addrs : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 69 :
	i++;
	len=vend[i++];
	printf("SMTP-Server : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 70 :
	i++;
	len=vend[i++];
	printf("POP3-Server : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 71 :
	i++;
	len=vend[i++];
	printf("NNTP-Server : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 72 :
	i++;
	len=vend[i++];
	printf("WWW-Server : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 73 :
	i++;
	len=vend[i++];
	printf("Finger-Server : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 74 :
	i++;
	len=vend[i++];
	printf("IRC-Server : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 75 :
	i++;
	len=vend[i++];
	printf("StreetTalk-Server : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 76 :
	i++;
	len=vend[i++];
	printf("STDA-Server : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 77 :
	i++;
	len=vend[i++];
	printf("User-Class : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 78 :
	i++;
	len=vend[i++];
	printf("Directory Agent : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 79 :
	i++;
	len=vend[i++];
	printf("Service Scope : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

case 255 :
	i++;
	len=vend[i++];
	printf("End : ");
	for (int k=0;k<len;k++){
		printf("%x ",vend[i+k]);
	}
	break;

default :
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
  }
}