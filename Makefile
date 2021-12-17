CC=gcc
CFLAGS=-Wall -g
LDFLAGS=-lpcap
EXEC=mydump
all : $(EXEC)

mydump : main.o afficheUDP.o afficheTCP.o capture.o
	$(CC) $^  -o $@ $(LDFLAGS)
	sudo setcap cap_net_raw,cap_net_admin=eip $(EXEC)


%.o : %.c 
	$(CC) $(CFLAGS) -o $@ -c $<	

clean : 
	rm *.o $(EXEC)