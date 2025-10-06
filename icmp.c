#include "icmp.h"

void icmp(const uint8_t *packet) {
	icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)packet;

	printf("\tICMP Header\n");
	char *type = icmp_type_to_str(icmp_hdr->type);
	if (type) {
		printf("\t\tType: %s\n\n", type);
	} else {
		printf("\t\tType: %u\n\n", icmp_hdr->type);
	}
}

char *icmp_type_to_str(uint16_t type) {
	switch (type) {
		case 0: return "Reply";
		case 8: return "Request";
		default: return NULL;
	}
}