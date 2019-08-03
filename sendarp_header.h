#ifndef SENDARP_HEADER_H
#define SENDARP_HEADER_H

#include <stdint.h>
#include <sys/types.h>
#include <string.h>

typedef struct{
    const uint8_t Dmac[6];
    const uint8_t Smac[6];
    const uint16_t type;
}Ethernet;

typedef struct{
    const uint16_t hwtype;
    const uint16_t protocol;
	const uint8_t hwsize;
	const uint8_t ptsize;
	const uint16_t opcode;
	const uint8_t sender_mac[6];
	const uint8_t sender_ip[4];
	const uint8_t target_mac[6];
	const uint8_t target_ip[4];
}ARP;

typedef struct{
    const uint8_t IHL;
    const uint8_t service;
    const uint16_t total_length;
    const uint8_t dummy2[5];
    const uint8_t protocol;
    const uint8_t dummy3[2];
    const uint8_t source_address[4];
    const uint8_t destination_address[4];
}IP;

typedef struct{
    const uint16_t source_port;
    const uint16_t destination_port;
    const uint8_t dummy[8];
    const uint8_t Hlen;
    const uint8_t dummy2[7];
}TCP;


#endif // SENDARP_HEADER_H
