#include "eth.h"

uint16_t ethernet(const uint8_t *packet) {
	eth_hdr_t *eth_hdr = (eth_hdr_t *)packet;	
	uint16_t ethertype = ntohs(eth_hdr->type);
	
	printf("\tEthernet Header\n");
	printf("\t\tDest MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		eth_hdr->dst[0], eth_hdr->dst[1], eth_hdr->dst[2],
		eth_hdr->dst[3], eth_hdr->dst[4], eth_hdr->dst[5]);
	printf("\t\tSource MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		eth_hdr->src[0], eth_hdr->src[1], eth_hdr->src[2],
		eth_hdr->src[3], eth_hdr->src[4], eth_hdr->src[5]);
	printf("\t\tType: %s\n\n", eth_type_to_str(ethertype));
	return ethertype;
}

char *eth_type_to_str(uint16_t ethertype) {
	switch (ethertype) {
		case 0x0800:
		case 0x86DD: return "IP";
		case 0x0806: return "ARP";
		default: return "Unknown";
	}
}
