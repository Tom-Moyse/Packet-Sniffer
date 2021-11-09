#include "analysis.h"

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <signal.h>
#include <stdlib.h>

typedef struct dyn_arr_ip{
	in_addr_t *arr;
	size_t used;
	size_t max;
} dyn_arr_ip;

static int syn_packets = 0;
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

in_addr_t get_arr_ip(dyn_arr_ip *arr, int index){
	if (arr->used >= index){ return NULL; }
	return arr->arr[index];
}

void exit_callback(int signum){
    printf("%d SYN packets detected\n", syn_packets);
	// To find number of unique IP's first make sorted array
	in_addr_t uniques[(&ip_addresses)->used];
	int length = 0;
	int found;
	in_addr_t address;

	for (int i = 0; i < (&ip_addresses)->used; i++){
		found = 0;
		address = get_arr_ip(&ip_addresses, i);
		printf("%d",address);
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

	printf("%d Unique IP source addresses\n, %d", length, uniques[0]);

	exit(signum);
}

void analyse(struct pcap_pkthdr *header, const unsigned char *packet, int verbose) {
	if (!is_initialised){
		init_arr_ip(&ip_addresses, 5);
		is_initialised = 1;
	}
	// Process Ethernet header
	struct ether_header *eth_header = (struct ether_header *) packet;

	// Process IP header
	struct ip *ip_header = (struct ip *) (packet + ETH_HLEN);
	unsigned int ip_length = (ip_header->ip_hl) * 4;
	u_int8_t ip_protocol = ip_header->ip_p;
	struct in_addr ip_src = ip_header->ip_src;
	struct in_addr ip_dst = ip_header->ip_dst;

	char mystring[50];
	printf("IP source: %s\n", inet_ntop(AF_INET, &(ip_src.s_addr), &mystring, 50));

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

		u_int16_t tcp_src = tcp_header->th_sport;
		u_int16_t tcp_dst = tcp_header->th_dport;
		unsigned int tcp_length = (tcp_header->th_off) * 4;

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
