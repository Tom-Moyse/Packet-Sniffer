#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

// Dynamic array for storing IP addresses of SYN packets
typedef struct dyn_arr_ip{
	in_addr_t *arr;
	size_t used;
	size_t max;
} dyn_arr_ip;

// Initialise static global variables to store data for analysis report
static int syn_packets = 0;
static int arp_packets = 0;
static int urlv_packets = 0;
static dyn_arr_ip ip_addresses;
static int is_initialised = 0;

pthread_mutex_t arrip_mutex = PTHREAD_MUTEX_INITIALIZER;

// Initialise dynamic packet address array
void init_arr_ip(dyn_arr_ip *arr, size_t size){
	arr->arr = malloc(size * sizeof(in_addr_t));
	arr->used = 0;
	arr->max = size;
}

// Store address in the array
void append_arr_ip(dyn_arr_ip *arr, in_addr_t ip){
	// Check if array full and thus should be resized
	if (arr->used == arr->max){
		arr->max = arr->max * 2;
		arr->arr = realloc(arr->arr, arr->max * sizeof(in_addr_t));
	}
	// Store address
	arr->arr[arr->used] = ip;
	arr->used = arr->used + 1;
}

// Helper function to appropriately free resources associated with IP array
void free_arr_ip(dyn_arr_ip *arr){
	free(arr->arr);
	arr->arr = NULL;
	arr->used = 0;
	arr->max = 0;
}

// Procedure to print report
void display_report(){
	// Find number of unique IP addresses
	in_addr_t uniques[ip_addresses.used];
	int length = 0;
	int found;
	in_addr_t address;

	// O(n^2) procedure for identifying unique addresses
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

	// Free the ip address array now that number of uniques identified
	free_arr_ip(&ip_addresses);

	// Print report information
	printf("\nIntrusion Detection Report:\n");
	printf("%d SYN packets detected from %d different IPs (syn attack)\n", syn_packets, length);
	printf("%d ARP responses\n", arp_packets);
	printf("%d URL Blacklist violations\n", urlv_packets);
}


// Function to handle analysis of malicious packet according to specification
void analyse(struct pcap_pkthdr *header, unsigned char *packet, int verbose) {
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


	if (ip_protocol == IPPROTO_TCP){
		//Process TCP header
		struct tcphdr *tcp_header = (struct tcphdr *) (packet + ETH_HLEN + ip_length);

		u_int16_t tcp_dst = tcp_header->th_dport;
		unsigned int tcp_length = (tcp_header->th_off) * 4;

		// Check if HTTP packet
		if (ntohs(tcp_dst) == 80){
			int num_bytes = packet_length - (ETH_HLEN + ip_length + tcp_length);
    		unsigned char *payload = (unsigned char *)packet + ETH_HLEN + ip_length + tcp_length;
			
			// Copy http payload to string
			char http_string[num_bytes + 1];
			http_string[num_bytes] = '\0';
			for (int i = 0; i < num_bytes; i++){
				http_string[i] = *(payload + i);
			}

			// Get pointer to the host address
			char *host_pos = strstr(http_string, "Host: ");

			// Check for blacklisted host at given position
			if (host_pos != NULL){
				char *domain_pos = host_pos+6;
				if (strstr(domain_pos, "www.google.co.uk") != NULL || strstr(domain_pos, "www.bbc.com") != NULL){
					urlv_packets++;
					char mystring[50];
					// Print report of blacklisted URL identified
					printf("==============================\n");
					printf("Blacklisted URL violation detection\n");
					printf("Source IP address: %s\n", inet_ntop(AF_INET, &(ip_src.s_addr), mystring, 50));
					printf("Destination IP address: %s\n", inet_ntop(AF_INET, &(ip_dst.s_addr), mystring, 50));
					printf("==============================\n");
				}
			}
		}

		// Check if packet is a SYN packet
		if (tcp_header->th_flags & TH_SYN){
			// Store IP src in array using mutex
			pthread_mutex_lock(&arrip_mutex);
			append_arr_ip(&ip_addresses, ip_src.s_addr);
			pthread_mutex_unlock(&arrip_mutex);
			syn_packets++;
		}
	}
}
