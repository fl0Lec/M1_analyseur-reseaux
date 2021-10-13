mydump : main.c affiche.c
	gcc main.c -lpcap -o mydump -g
