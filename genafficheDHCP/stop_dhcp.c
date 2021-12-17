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