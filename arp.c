#include "arp.h"

void arp(const uint8_t *packet) {
	arp_hdr_t *arp_hdr = (arp_hdr_t *)packet;

	printf("\tARP header\n");
	printf("\t\tOpcode: %s\n", arp_opcode_to_str(ntohs(arp_hdr->opcode)));
	printf("\t\tSender MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		arp_hdr->sender_mac[0], arp_hdr->sender_mac[1], arp_hdr->sender_mac[2],
		arp_hdr->sender_mac[3], arp_hdr->sender_mac[4], arp_hdr->sender_mac[5]);

	// convert to byte array for printing
	uint8_t *sender_ip_ptr = (uint8_t *)&arp_hdr->sender_ip;
	printf("\t\tSender IP: %u.%u.%u.%u\n",
		sender_ip_ptr[0], sender_ip_ptr[1], sender_ip_ptr[2], sender_ip_ptr[3]);

	printf("\t\tTarget MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		arp_hdr->target_mac[0], arp_hdr->target_mac[1], arp_hdr->target_mac[2],
		arp_hdr->target_mac[3], arp_hdr->target_mac[4], arp_hdr->target_mac[5]);

	// convert to byte array for printing
	uint8_t *target_ip_ptr = (uint8_t *)&arp_hdr->target_ip;
	printf("\t\tTarget IP: %u.%u.%u.%u\n\n",
		target_ip_ptr[0], target_ip_ptr[1], target_ip_ptr[2], target_ip_ptr[3]);
}

char *arp_opcode_to_str(uint16_t opcode) {
	switch (opcode) {
		case 1: return "Request";
		case 2: return "Reply";
		default: return "Unknown";
	}
}