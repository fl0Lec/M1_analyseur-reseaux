import pandas as pd
import numpy as np

values = [i for i in range(80)]
values.append(255)

addrIP = [1, 28, 32, 50, 54]
notime = [54, 118, 159, 208]
df = pd.read_csv("dhcp_option.csv", sep=',')
f = open("afficheDHCP.c", "w")
fr = open("start_dhcp.c")
for line in fr :
    f.write(line)
fr.close()
for index, row in df.iterrows():
    if row["Tag"].find("-")==-1 and int(row["Tag"]) in values:
        #affichage initilal
        f.write("case %s :\n\ti++;\n\tlen=vend[i++];\n" % row["Tag"])
        f.write("\tprintf(\"%s : \");\n" % row["Name"])
        #verifie la taille
        if (int(row["Tag"]))==53: 
            f.write("""switch (vend[i])
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
                    """)
        elif int(row["Tag"])==0:
            f.write("\ti--;\n\tlen=0;")
        elif int(row["Tag"])in addrIP :
            f.write("\tafficheIPBootp(vend+i, len);")
        elif int(row["Tag"])==61:
            f.write("\tafficheAddBootp(vend+i, len);")
        elif (row["length"]!="N") and pd.isnull(row["length"]):
            f.write("\tif (len!=%s){\n" % row["length"])
            len = row["length"]
            f.write(f"\t\tprintf(\"longueur non valide :%d attendu {len}\",len);\n")
            f.write("\t} else {\n")
            f.write("\t\tfor (int k=0;k<len;k++){\n")
            f.write("\t\t\tprintf(\"%x \",vend[i+k]);\n\t\t}\n")
            f.write("\t}\n")
        elif (row["length"]!="N") and int(row["length"])==4 and int(row["Tag"]) not in notime:
            f.write("\tafficheTimeBootp(vend+i, len);\n") 
        else :
            f.write("\tfor (int k=0;k<len;k++){\n")
            f.write("\t\tprintf(\"%x \",vend[i+k]);\n\t}\n")
        f.write("\tbreak;\n\n")
fr = open("stop_dhcp.c")
for line in fr :
    f.write(line)
fr.close()
f.close()