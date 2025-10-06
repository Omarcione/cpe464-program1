#ifndef TCP_H
#define TCP_H

#include <stdint.h>
#include <stdio.h>
#include "pcap_type.h"
#include "ip.h"
#include "udp.h"

typedef struct __attribute__((packed)) {
    uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq_num;
	uint32_t ack_num;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint8_t reserved:4;
    uint8_t data_offset:4;
#else
    uint8_t data_offset:4;
    uint8_t reserved:4;
#endif
	uint8_t flags;
	uint16_t window;
	uint16_t checksum;
	uint16_t urgent_pointer;
} tcp_hdr_t;

typedef struct __attribute__((packed)) {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint8_t reserved;
	uint8_t protocol;
	uint16_t tcp_length;
	
} pseudo_hdr_t;


void tcp(const uint8_t *packet, ip_hdr_t *ip_hdr);

uint16_t tcp_checksum(const uint8_t *packet, ip_hdr_t *ip_hdr);

const char *tcp_port_to_service(uint16_t port);

#endif