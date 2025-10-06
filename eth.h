#ifndef ETH_H
#define ETH_H

#include <stdint.h>
#include <stdio.h>
#include "pcap_type.h"

typedef struct __attribute__((packed)) {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t type;
} eth_hdr_t;

uint16_t ethernet(const uint8_t *packet);

char *eth_type_to_str(uint16_t type);

#endif