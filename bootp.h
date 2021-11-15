#ifndef __bootp__
#define __bootp__

#include <stdint.h>
#define uint    unsigned int
#define uchar   unsigned char

#define OP_REQUEST 1
#define OP_REPLY 2

#define HTYPE_ETHERNET 1

#define MAGIC_COOKIE 0x63825363
#
struct bootp
{
    uint op:8;
    uint htype:8;
    uint hlen:8;
    uint hops:8;

    uint xid:32;

    uint secs:16;
    uint flags:16;

    uint ciaddr:32;
    uint yiaddr:32;
    uint siaddr:32;
    uint giaddr:32;
    char chaddr[16];
    char sname[64];
    char file[128];
    //u_char vend[64];
};

#endif