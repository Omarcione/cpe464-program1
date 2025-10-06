#ifndef ICMP_H
#define ICMP_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "pcap_type.h"

typedef struct __attribute__((packed)) {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	uint32_t ext_hdr;
} icmp_hdr_t;

void icmp(const uint8_t *packet);

char *icmp_type_to_str(uint16_t opcode);

#endif