#ifndef ARP_H
#define ARP_H

#include <stdint.h>
#include <stdio.h>
#include "pcap_type.h"

typedef struct __attribute__((packed)) {
    uint16_t htype;
	uint16_t ptype;
	uint8_t hlen;
	uint8_t plen;
	uint16_t opcode;
	uint8_t sender_mac[6];
	uint32_t sender_ip;
	uint8_t target_mac[6];
	uint32_t target_ip;
} arp_hdr_t;

void arp(const uint8_t *packet);

char *arp_opcode_to_str(uint16_t opcode);

#endif