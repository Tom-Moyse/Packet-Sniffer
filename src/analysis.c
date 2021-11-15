#include "analysis.h"
#include "dispatch.h"
#include "sniff.h"

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

typedef struct dyn_arr_ip{
	in_addr_t *arr;
	size_t used;
	size_t max;
} dyn_arr_ip;

static int syn_packets = 0;
static int arp_packets = 0;
static int urlv_packets = 0;
static dyn_arr_ip ip_addresses;
static int is_initialised = 0;

void init_arr_ip(dyn_arr_ip *arr, size_t size){
	arr->arr = malloc(size * sizeof(in_addr_t));
	arr->used = 0;
	arr->max = size;
}

void append_arr_ip(dyn_arr_ip *arr, in_addr_t ip){
	if (arr->used == arr->max){
		arr->max = arr->max * 2;
		arr->arr = realloc(arr->arr, arr->max * sizeof(in_addr_t));
	}
	arr->arr[arr->used] = ip;
	arr->used = arr->used + 1;
}

void free_arr_ip(dyn_arr_ip *arr){
	free(arr->arr);
	arr->arr = NULL;
	arr->used = 0;
	arr->max = 0;
}

void exit_callback(int signum){
	// To find number of unique IP's first make sorted array
	in_addr_t uniques[ip_addresses.used];
	int length = 0;
	int found;
	in_addr_t address;

	for (int i = 0; i < ip_addresses.used; i++){
		found = 0;
		address = ip_addresses.arr[i];
		for (int j = 0; j < length; j++){
			if (uniques[j] == address){
				found = 1;
				break;
			}
		}
		if (!found){
			uniques[length] = address;
			length++;
		}
	}

	printf("\n%d SYN packets detected from %d different IPs (syn attack)\n", syn_packets, length);
	printf("%d ARP responses\n", arp_packets);
	printf("%d URL Blacklist violations\n", urlv_packets);

	close_threads();
	exit(signum);
}



void analyse(struct pcap_pkthdr *header, unsigned char *packet, int verbose) {
	printf("WE ANALYSING");
	int packet_length = header->len;

	if (!is_initialised){
		init_arr_ip(&ip_addresses, 5);
		is_initialised = 1;
	}
	// Process Ethernet header
	struct ether_header *eth_header = (struct ether_header *) packet;
	// Detect if ARP packet
	if (ntohs(eth_header->ether_type) == ETH_P_ARP){
		arp_packets++;
	}

	// Process IP header
	struct ip *ip_header = (struct ip *) (packet + ETH_HLEN);
	unsigned int ip_length = (ip_header->ip_hl) * 4;
	u_int8_t ip_protocol = ip_header->ip_p;
	struct in_addr ip_src = ip_header->ip_src;
	struct in_addr ip_dst = ip_header->ip_dst;

	//char mystring[50];
	//printf("IP source: %s\n", inet_ntop(AF_INET, &(ip_src.s_addr), &mystring, 50));
	//printf("IP Protocol: %d\n", ip_protocol);
	if (ip_protocol == IPPROTO_TCP){
		
		//Process TCP header

		// This works
		struct tcphdr *tcp_header = (struct tcphdr *) (packet + ETH_HLEN + ip_length);

		// This doesn't work
		// struct tcphdr *tcp_header = (struct tcphdr *) (ip_header + ip_length);

		// These are identical
		//printf("%p %p",ip_header, packet + ETH_HLEN );

		// These are different
		// printf(" %d %p %p",ip_length, ip_header + ip_length, packet + ETH_HLEN + ip_length);

		//u_int16_t tcp_src = tcp_header->th_sport;
		u_int16_t tcp_dst = tcp_header->th_dport;
		unsigned int tcp_length = (tcp_header->th_off) * 4;

		if (ntohs(tcp_dst) == 80){
			int num_bytes = packet_length - (ETH_HLEN + ip_length + tcp_length);
    		unsigned char *payload = (unsigned char *)packet + ETH_HLEN + ip_length + tcp_length;
			
			// Copy http payload to string
			char http_string[num_bytes + 1];
			http_string[num_bytes] = '\0';
			for (int i = 0; i < num_bytes; i++){
				http_string[i] = *(payload + i);
			}

			printf("\nPacket length:%d, Ip len:%d, Tcp len:%d, Content:%s\n",packet_length,ip_length,tcp_length,http_string);

			char *host_pos = strstr(http_string, "Host: ");

			if (host_pos != NULL){
				char *domain_pos = host_pos+6;
				if (strstr(domain_pos, "www.google.co.uk") != NULL || strstr(domain_pos, "www.bbc.com") != NULL){
					urlv_packets++;
					char mystring[50];
					printf("==============================\n");
					printf("Blacklisted URL violation detection\n");
					printf("Source IP address: %s\n", inet_ntop(AF_INET, &(ip_src.s_addr), mystring, 50));
					printf("Destination IP address: %s\n", inet_ntop(AF_INET, &(ip_dst.s_addr), mystring, 50));
					printf("==============================\n");
				}
			}
		}

		// Use equals opposed to & as want to check exclusively syn bit set
		if (tcp_header->th_flags == TH_SYN){
			// Is SYN packet
			if (syn_packets < 50){
				append_arr_ip(&ip_addresses, ip_src.s_addr);
			}
			syn_packets++;
		}
	}
}
