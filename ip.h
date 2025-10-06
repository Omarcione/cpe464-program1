#ifndef IP_H
#define IP_H

#include <stdint.h>
#include <stdio.h>
#include "pcap_type.h"
#include <stdbool.h>
#include <string.h>
#include "checksum.h"

typedef struct __attribute__((packed)) {
    uint8_t version_ihl;
	uint8_t tos;
	uint16_t total_len;
	uint16_t id;
	uint16_t flags_frag;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	uint32_t src_addr;
	uint32_t dst_addr;
} ip_hdr_t;

// typedef struct {
// 	uint8_t protocol;
// 	uint16_t total_len;
// 	uint16_t hdr_len;
// } ip_return_t;

ip_hdr_t* ip(const uint8_t *packet);

char *ip_proto_to_str(uint8_t protocol);

#endif