#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H

#include <pcap.h>

void analyse(struct pcap_pkthdr *header,
             unsigned char *packet,
             int verbose);

void exit_callback(int signum);

#endif
