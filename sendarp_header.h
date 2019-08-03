#ifndef SENDARP_HEADER_H
#define SENDARP_HEADER_H

#include <stdint.h>
#include <sys/types.h>
#include <string.h>

typedef struct{
    const u_int8_t Dmac[6];
    const u_int8_t Smac[6];
    const u_int16_t type;
}_Ethernet;

typedef struct{
    const u_int16_t type;
    const u_int16_t protocol;
}

typedef struct{
    const u_int8_t IHL;
    const u_int8_t service;
    const u_int16_t total_length;
    const u_int8_t dummy2[5];
    const u_int8_t protocol;
    const u_int8_t dummy3[2];
    const u_int8_t source_address[4];
    const u_int8_t destination_address[4];
}_IP;

typedef struct{
    const u_int16_t source_port;
    const u_int16_t destination_port;
    const u_int8_t dummy[8];
    const u_int8_t Hlen;
    const u_int8_t dummy2[7];
}_TCP;


#endif // SENDARP_HEADER_H
