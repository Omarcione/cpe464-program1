#include "ip.h"

ip_hdr_t* ip(const uint8_t *packet) {
	ip_hdr_t *ip_hdr = (ip_hdr_t *)packet;
	uint8_t hdr_len = (ip_hdr->version_ihl & 0x0F) * 4;


	printf("\tIP Header\n");
	printf("\t\tIP PDU Len: %u\n", ntohs(ip_hdr->total_len));
	printf("\t\tHeader Len (bytes): %u\n", hdr_len);
	printf("\t\tTTL: %u\n", ip_hdr->ttl);
	printf("\t\tProtocol: %s\n", ip_proto_to_str(ip_hdr->protocol));

	// Make a copy
	uint8_t buf[hdr_len];
	memcpy(buf, packet, hdr_len);
	// Cast to ip_hdr and zero out checksum field in copy
	((ip_hdr_t *)buf)->checksum = 0;
	// Check if checksums are equal
	uint16_t checksum = (uint16_t)in_cksum((unsigned short *)buf, hdr_len);
	printf("\t\tChecksum: %s (0x%04x)\n", checksum == ip_hdr->checksum ? "Correct" : "Incorrect", ntohs(ip_hdr->checksum));
	
	// convert to byte array for printing
	uint8_t *src_ptr = (uint8_t *)&ip_hdr->src_addr;
	printf("\t\tSender IP: %u.%u.%u.%u\n",
		src_ptr[0], src_ptr[1], src_ptr[2], src_ptr[3]);

	uint8_t *dst_ptr = (uint8_t *)&ip_hdr->dst_addr;
	printf("\t\tDest IP: %u.%u.%u.%u\n\n",
		dst_ptr[0], dst_ptr[1], dst_ptr[2], dst_ptr[3]);

	return ip_hdr;
}

char *ip_proto_to_str(uint8_t protocol) {
	switch (protocol) {
		case 1: return "ICMP";
		case 6: return "TCP";
		case 17: return "UDP";
		default: return "Unknown";
	}
}
