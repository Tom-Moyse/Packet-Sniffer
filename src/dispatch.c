#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "analysis.h"

// Required structs for packet queue storage
typedef struct packet_q_node {
    struct pcap_pkthdr header;
    unsigned char *data_start;
    unsigned int data_length;
    struct packet_q_node *next;
} packet_q_node;

typedef struct stored_packet_queue {
    packet_q_node *start;
    packet_q_node *end;
} stored_packet_queue;

typedef struct packet_node {
    struct pcap_pkthdr header;
    unsigned char *data_start;
    unsigned int data_length;
} packet_node;

int is_empty(stored_packet_queue *q) {
    return (!q->start);
}

void store_packet(stored_packet_queue *q, const struct pcap_pkthdr *header, const unsigned char *packet) {
    // Allocates resources and creates copy of packet
    unsigned int packet_size = header->len;
    packet_q_node *new_packet = malloc(sizeof(packet_q_node));
    unsigned char *packet_data = malloc(sizeof(unsigned char) * packet_size);
    memcpy(packet_data, packet, packet_size);
    new_packet->header = *header;
    new_packet->data_length = packet_size;
    new_packet->data_start = packet_data;

    // Assign packet node to queue
    if (is_empty(q)) {
        q->start = new_packet;
        q->end = new_packet;
    }
    else {
        q->end->next = new_packet;
        q->end = q->end->next;
    }
}

int remove_packet(stored_packet_queue *q) {
    // Check if packet exists in queue
    if (is_empty(q)) {
        return EXIT_FAILURE;
    }
    // If only one packet return queue to empty state
    if (q->start == q->end) {
        free(q->start->data_start);
        free(q->start);
        q->start = NULL;
        q->end = NULL;
        return EXIT_SUCCESS;
    }

    // If more than one, free last packet and adjust queue accordingly
    packet_q_node *current_start = q->start;

    q->start = q->start->next;
    free(current_start->data_start);
    free(current_start);
    current_start = NULL;
    return EXIT_SUCCESS;
}

// Function returns first available packet dest. or -1 if no such dest. exists
int get_analysis_index(int *new_packets, int size) {
    for (int i = 0; i < size; i++) {
        if (new_packets[i] == 0) {
            return i;
        }
    }
    return -1;
}

// Define all required global variables/structs
#define NUMTHREADS 8

stored_packet_queue packet_queue;
packet_node *to_analyse;
int new_packets[NUMTHREADS] = {0};
int analysis_index = 0;

/* mutex lock required for the shared queue*/
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;

pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;
pthread_cond_t arrp_cond = PTHREAD_COND_INITIALIZER;

pthread_t tid[NUMTHREADS + 1];

int threadnums[NUMTHREADS];

static int end_analysis = 0;

// Function to intialise required data structures for packet dispatch
void init_structures() {
    packet_queue.start = NULL;
    packet_queue.end = NULL;
    to_analyse = calloc(NUMTHREADS, sizeof(packet_node));
}

// Function to be executed by each analysis thread
void *handle_analyse(void *arg) {
    // Placeholder mutex to allow for condition broadcast thus avoiding excess waste processing
    pthread_mutex_t placeholder_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&placeholder_mutex);
    int tid = *((int *)arg);
    // Check if new packet to analyse
    while (1) {
        if (end_analysis){
            return NULL;
        }
        // Wait for packet to arrive on condition broadcast
        while(new_packets[tid] == 0){
            pthread_cond_wait(&arrp_cond, &placeholder_mutex);
            if (end_analysis){
                pthread_mutex_unlock(&placeholder_mutex);
                return NULL;
            }
        }
        // Analyse and subsequently free new packet
        if (new_packets[tid] == 1) {
            analyse(&to_analyse[tid].header, to_analyse[tid].data_start, 0);
            free(to_analyse[tid].data_start);
            to_analyse[tid].data_start = NULL;
            new_packets[tid] = 0;
        }
    }
    return NULL;
}

/*Function to be executed by allocation thread*/
void *handle_allocate(void *arg) {
    int p_index;

    while (1) {
        if (end_analysis) {
            return NULL;
        }
        // Check if any available analysis threads
        p_index = get_analysis_index(new_packets, NUMTHREADS);
        if (p_index == -1) {
            continue;
        }
        // Wait on new packet being added to queue/broadcast
        pthread_mutex_lock(&queue_mutex);
        while (is_empty(&packet_queue)) {
            pthread_cond_wait(&queue_cond, &queue_mutex);
            if (end_analysis) {
                pthread_mutex_unlock(&queue_mutex);
                return NULL;
            }
        }
        // Transfer packet from queue to packet struct in to_analyse at given index
        to_analyse[p_index].header = packet_queue.start->header;
        to_analyse[p_index].data_length = packet_queue.start->data_length;
        to_analyse[p_index].data_start = malloc(packet_queue.start->data_length);
        memcpy(to_analyse[p_index].data_start, packet_queue.start->data_start, packet_queue.start->data_length);

        // Indicate to thread that there's a new packet to analyse
        new_packets[p_index] = 1;
        pthread_cond_broadcast(&arrp_cond);

        // Remove packet from queue
        remove_packet(&packet_queue);

        pthread_mutex_unlock(&queue_mutex);
    }
    return NULL;
}

void init_threads() {
    //create work queue
    init_structures();

    //create the allocater thread
    pthread_create(&tid[0], NULL, handle_allocate, NULL);

    //create the analysis threads
    for (int i = 0; i < NUMTHREADS; i++) {
        threadnums[i] = i;
        pthread_create(&tid[i + 1], NULL, handle_analyse, &threadnums[i]);
    }
}

void close_threads() {
    // Set termination flag
    end_analysis = 1;

    // Condition broadcast to stop thread being blocked and thus not terminating
    pthread_cond_broadcast(&queue_cond);
    pthread_join(tid[0], NULL);

    pthread_cond_broadcast(&arrp_cond);
    // Free relevant packet structures
    for (int i = 0; i < NUMTHREADS; i++){
        pthread_join(tid[i+1], NULL);
        if (to_analyse[i].data_start){
            free(to_analyse[i].data_start);
        }
    }
    free(to_analyse);
}

// Simple dispatch interface function which adds packet to the processing queue
void dispatch(const struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose) {
    // Lock queue mutexes, store packet and broadcast packet added
    pthread_mutex_lock(&queue_mutex);
    store_packet(&packet_queue, header, packet);
    pthread_cond_broadcast(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);
}