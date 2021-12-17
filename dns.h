#ifndef __DNSFORMAT__
#define __DNSFORMAT__
#include <stdint.h>

struct dns_header
{
    uint16_t id; //identifier of queries 
    uint16_t flags;
    uint16_t QDcount; //nomber of question
    uint16_t ANcount; //nomber of answer
    uint16_t NSCount; //autoritaive server count
    uint16_t ARCount; //additionnal recode count
};

struct dns_response
{
    uint16_t name; //reference to question
    uint16_t type; 
    uint16_t class;
    uint32_t TTL;
    uint16_t len;
};
#endif