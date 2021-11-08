#include "analysis.h"

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>

void analyse(struct pcap_pkthdr *header, const unsigned char *packet, int verbose) {
	// Define static variables
	static int syn_packets = 0;
	static in_addr_t ip_addresses[50];

	// Process Ethernet header
	struct ether_header *eth_header = (struct ether_header *) packet;

	// Process IP header
	struct ip *ip_header = (struct ip *) packet + ETH_HLEN;
	unsigned int ip_length = (ip_header->ip_hl) * 4;
	u_int8_t ip_protocol = ip_header->ip_p;
	struct in_addr ip_src = ip_header->ip_src;
	struct in_addr ip_dst = ip_header->ip_dst;

	if (ip_protocol == 5){
		//Process TCP header
		struct tcphdr *tcp_header = (struct tcphdr *) ip_header + ip_length;
		u_int16_t tcp_src = tcp_header->th_sport;
		u_int16_t tcp_dst = tcp_header->th_dport;
		unsigned int tcp_length = (tcp_header->th_off) * 4;
		if (tcp_header->th_flags == TH_SYN){
			// Is SYN packet
			if (syn_packets < 50){
				ip_addresses[syn_packets] = ip_src.s_addr;
			}
			syn_packets++;
		}
	}
}
