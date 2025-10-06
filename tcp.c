#include "tcp.h"
#include "ip.h"

void tcp(const uint8_t *packet, ip_hdr_t *ip_hdr) {
	
	tcp_hdr_t *tcp_hdr = (tcp_hdr_t *)packet;
	uint8_t ip_hdr_len = (ip_hdr->version_ihl & 0x0F) * 4;

	//tcp segment length = total length - ip header length
	uint16_t segment_len = ntohs(ip_hdr->total_len) - ip_hdr_len;
	//mask lower nibble and shift to get data offset in bytes
	uint8_t data_offset = (tcp_hdr->data_offset) * 4;

	//get service name if possible
	const char *src_port = tcp_port_to_service(ntohs(tcp_hdr->src_port));
	const char *dst_port = tcp_port_to_service(ntohs(tcp_hdr->dst_port));

	printf("\tTCP Header\n");
	printf("\t\tSegment Length: %u\n", segment_len);

	if (src_port)
		printf("\t\tSource Port: %s\n", src_port);
	else
		printf("\t\tSource Port: %u\n", ntohs(tcp_hdr->src_port));

	if (dst_port)
		printf("\t\tDest Port: %s\n", dst_port);
	else
		printf("\t\tDest Port: %u\n", ntohs(tcp_hdr->dst_port));

	printf("\t\tSequence Number: %u\n", ntohl(tcp_hdr->seq_num));
	printf("\t\tACK Number: %u\n", ntohl(tcp_hdr->ack_num));
	printf("\t\tData Offset (bytes): %u\n", data_offset);
	printf("\t\tSYN Flag: %s\n", (tcp_hdr->flags & 0x02) ? "Yes" : "No");
	printf("\t\tRST Flag: %s\n", (tcp_hdr->flags & 0x04) ? "Yes" : "No");
	printf("\t\tFIN Flag: %s\n", (tcp_hdr->flags & 0x01) ? "Yes" : "No");
	printf("\t\tACK Flag: %s\n", (tcp_hdr->flags & 0x10) ? "Yes" : "No");
	printf("\t\tWindow Size: %u\n", ntohs(tcp_hdr->window));

	uint16_t checksum = tcp_checksum(packet, ip_hdr);
	printf("\t\tChecksum: %s (0x%04x)\n\n", checksum == tcp_hdr->checksum ? "Correct" : "Incorrect", ntohs(tcp_hdr->checksum));
}

uint16_t tcp_checksum(const uint8_t *packet, ip_hdr_t *ip_hdr) {
	//create tcp pseudo header
	pseudo_hdr_t pseudo_hdr;
	pseudo_hdr.src_ip = ip_hdr->src_addr;
	pseudo_hdr.dst_ip = ip_hdr->dst_addr;
	pseudo_hdr.reserved = 0;
	pseudo_hdr.protocol = ip_hdr->protocol;
	// total length - ip header length and put back in network order
	pseudo_hdr.tcp_length = htons(ntohs(ip_hdr->total_len) - ((ip_hdr->version_ihl & 0x0F) * 4));

	//create buf size of psudo header + tcp 
	size_t buf_len = sizeof(pseudo_hdr) + ntohs(pseudo_hdr.tcp_length);
	uint8_t buf[buf_len];

	memcpy(buf, &pseudo_hdr, sizeof(pseudo_hdr));
	// add tcp packet after pseudo header
	memcpy(buf + sizeof(pseudo_hdr), packet, ntohs(pseudo_hdr.tcp_length));

	//zero out checksum field
	((tcp_hdr_t *)(buf + sizeof(pseudo_hdr)))->checksum = 0;

	return (uint16_t)in_cksum((unsigned short *)buf, buf_len);
}

const char *tcp_port_to_service(uint16_t port) {
    switch (port) {
        case 21:  return "FTP";
        case 23:  return "Telnet";
        case 25:  return "SMTP";
        case 53:  return "DNS";
        case 80:  return "HTTP";
        case 110: return "POP3";
        default:  return NULL; 
    }
}