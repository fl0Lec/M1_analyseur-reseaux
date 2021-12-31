#define BOOTP_PORT_CLIENT 0x4400
#define BOOTP_PORT_SERVER 0x4300
#define BOOTP_MAGIC_COOKIE 0x63 82 53 63

#define PRINTLINE() printf("__________________________________________\n");
#define REVUINT(a) (a>>8)+((a&0xff)<<8)

//for IP
#define UDP 0x11
#define TCP 0x06

//for TCP
#define SMTP_port 0x1900
#define HTTP_port 0x5000
#define FTP_port_CMD 0x1500
#define FTP_port_DATA 0x1400
#define TFTP_port 0x4500
#define TELNET_port 0x1700
#define IMAP_port 0x8f00
#define POP_port 0x6e00
