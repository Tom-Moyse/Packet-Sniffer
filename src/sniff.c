#include "sniff.h"

#include <netinet/if_ether.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "dispatch.h"
#include "analysis.h"

pcap_t *pcap_handle;

void terminate_sniff(int sigint){
    pcap_breakloop(pcap_handle);
}

// Callback function for pcap_loop() that determines if packet should be dumped based upon verbose flag
void callback(unsigned char *verbose_chr, const struct pcap_pkthdr *header, const unsigned char *packet) {
    int verbose = (int) *verbose_chr;
    
    if (verbose) {
        dump(packet, header->len);
    }
    // Dispatch packet for processing
    dispatch(header, packet, verbose);
}

// Utility/Debugging method for dumping raw packet data
void dump(const unsigned char *data, int length) {
    unsigned int i;
    static unsigned long pcount = 0;
    // Decode Packet Header
    struct ether_header *eth_header = (struct ether_header *)data;
    printf("\n\n === PACKET %ld HEADER ===", pcount);
    printf("\nSource MAC: ");
    for (i = 0; i < 6; ++i) {
        printf("%02x", eth_header->ether_shost[i]);
        if (i < 5) {
            printf(":");
        }
    }
    printf("\nDestination MAC: ");
    for (i = 0; i < 6; ++i) {
        printf("%02x", eth_header->ether_dhost[i]);
        if (i < 5) {
            printf(":");
        }
    }
    printf("\nType: %hu\n", eth_header->ether_type);
    printf(" === PACKET %ld DATA == \n", pcount);
    // Decode Packet Data (Skipping over the header)
    int data_bytes = length - ETH_HLEN;
    const unsigned char *payload = data + ETH_HLEN;
    const static int output_sz = 20;  // Output this many bytes at a time
    while (data_bytes > 0) {
        int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
        // Print data in raw hexadecimal form
        for (i = 0; i < output_sz; ++i) {
            if (i < output_bytes) {
                printf("%02x ", payload[i]);
            } else {
                printf("   ");  // Maintain padding for partial lines
            }
        }
        printf("| ");
        // Print data in ascii form
        for (i = 0; i < output_bytes; ++i) {
            char byte = payload[i];
            if (byte > 31 && byte < 127) {
                // Byte is in printable ascii range
                printf("%c", byte);
            } else {
                printf(".");
            }
        }
        printf("\n");
        payload += output_bytes;
        data_bytes -= output_bytes;
    }
    pcount++;
}

// Application main sniffing loop
void sniff(char *interface, int verbose) {
    init_threads();
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the specified network interface for packet capture. pcap_open_live() returns the handle to be used for the packet
    // capturing session. check the man page of pcap_open_live()
    pcap_handle = pcap_open_live(interface, 4096, 1, 1000, errbuf);
    if (pcap_handle == NULL) {
        fprintf(stderr, "Unable to open interface %s\n", errbuf);
        exit(EXIT_FAILURE);
    } else {
        printf("SUCCESS! Opened %s for capture\n", interface);
    }

    // Create unsigned char for verbose such that it can be passed to callback function
    unsigned char verbose_chr = (unsigned char) verbose;

    // Add signal handler for CtrlC detection
    signal(SIGINT, terminate_sniff);

    // Captures packets using pcap_loop() and for each packet calls the callback function
    pcap_loop(pcap_handle, -1, callback, &verbose_chr);

    //Will be reached upon CtrlC
    pcap_close(pcap_handle);
    close_threads();
    display_report();

    exit(SIGINT);
}
