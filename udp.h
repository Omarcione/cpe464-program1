#ifndef UDP_H
#define UDP_H

#include <stdint.h>
#include <stdio.h>
#include "pcap_type.h"
#include "ip.h"

typedef struct __attribute__((packed)) {
    uint16_t src_port;
	uint16_t dst_port;
	uint32_t len;
	uint16_t checksum;
} udp_hdr_t;

void udp(const uint8_t *packet);

const char *udp_port_to_service(uint16_t port);

#endif