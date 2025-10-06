#include "trace.h"
#include "checksum.h"

int main(int argc, char *argv[]) {
	int packet_count = 0;

	struct pcap_pkthdr *packet_header;
	pcap_t *pcap_handle;
	char error_buffer[PCAP_ERRBUF_SIZE];
	const u_char *packet;
	uint16_t ethertype;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
		return 1;
	}

	// open the pcap file
	pcap_handle = pcap_open_offline(argv[1], error_buffer);

	printf("\n");
	// read packets from the pcap file until there are no more packets
	while (pcap_next_ex(pcap_handle, &packet_header, &packet) >= 0) {
		packet_count++;
		printf("Packet number: %d  Packet Len: %d\n\n", packet_count, packet_header->len);
		ethertype = ethernet(packet);
		switch (ethertype) {
			case 0x0800:
			case 0x86DD: {
				// IP processing function
				ip_hdr_t *ip_hdr = ip(packet + sizeof(eth_hdr_t)); // skip Ethernet header
				uint8_t ip_hdr_len = (ip_hdr->version_ihl & 0x0F) * 4;
				switch (ip_hdr->protocol) {
					case 1:
						// ICMP processing function
						// Use the actual IP header length in case of IP options
						icmp(packet + sizeof(eth_hdr_t) + ip_hdr_len);
						break;
					case 6:
						// TCP processing function
						tcp(packet + sizeof(eth_hdr_t) + ip_hdr_len, ip_hdr);
						break;
					case 17:
						// UDP processing function
						udp(packet + sizeof(eth_hdr_t) + ip_hdr_len);
						break;
					default:
						// Unknown IP protocol, skip the packet
						continue;
				}
				break;
			}
				
			case 0x0806:
				// ARP processing function
				arp(packet + sizeof(eth_hdr_t));
				break;
			default:
				// Unknown ethertype, skip the packet
				continue;
		}
	}
	return 0;
}