#include "udp.h"

void udp(const uint8_t *packet) {
	
	udp_hdr_t *udp_hdr = (udp_hdr_t *)packet;

	const char *src_port = udp_port_to_service(ntohs(udp_hdr->src_port));
	const char *dst_port = udp_port_to_service(ntohs(udp_hdr->dst_port));

	printf("\tUDP Header\n");
		
	if (src_port)
		printf("\t\tSource Port: %s\n", src_port);
	else
		printf("\t\tSource Port: %u\n", ntohs(udp_hdr->src_port));

	if (dst_port)
		printf("\t\tDest Port: %s\n\n", dst_port);
	else
		printf("\t\tDest Port: %u\n\n", ntohs(udp_hdr->dst_port));

}

const char *udp_port_to_service(uint16_t port) {
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