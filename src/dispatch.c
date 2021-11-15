#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "analysis.h"

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
    // Allocate resources and create packet
    unsigned int packet_size = header->len;
    packet_q_node *new_packet = malloc(sizeof(packet_q_node));
    unsigned char *packet_data = malloc(sizeof(unsigned char) * packet_size);
    memcpy(packet_data, packet, packet_size);
    new_packet->header = *header;
    new_packet->data_length = packet_size;
    new_packet->data_start = packet_data;

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
    //printf("REMOVING PACKET\n");
    if (is_empty(q)) {
        //printf("The queue is empty - operation failed\n");
        return EXIT_FAILURE;
    }
    if (q->start == q->end) {
        //printf("ONLY ONE NODE\n");
        free(q->start->data_start);
        free(q->start);
        q->start = NULL;
        q->end = NULL;
        return EXIT_SUCCESS;
    }
    //printf("MANY NODES\n");
    packet_q_node *current_start = q->start;

    q->start = q->start->next;
    free(current_start->data_start);
    free(current_start);
    current_start = NULL;
    //printf("New Head After: %p\n", q->start);
    return EXIT_SUCCESS;
}

int get_analysis_index(int *new_packets, int size) {
    printf("New Packets: [%d, %d]\n",new_packets[0], new_packets[1]);
    for (int i = 0; i < size; i++) {
        if (new_packets[i] == 0) {
            return i;
        }
    }
    return -1;
}

#define NUMTHREADS 2

stored_packet_queue packet_queue;
packet_node *to_analyse;
int new_packets[NUMTHREADS] = {0};
int analysis_index = 0;

void init_structures() {
    packet_queue.start = NULL;
    packet_queue.end = NULL;
    to_analyse = malloc(NUMTHREADS * sizeof(packet_node));
}

/* mutex lock required for the shared queue*/
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;

pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

pthread_t tid[NUMTHREADS + 1];
int threadnums[NUMTHREADS];

static int end_analysis = 0;

/*Function to be executed by each analysis thread*/
void *handle_analyse(void *arg) {
    int tid = *((int *)arg);
    // Check if new packet to analyse
    while (1) {
        if (new_packets[tid] == 1) {
            printf("We about to analyse!\n");
            analyse(&to_analyse[tid].header, to_analyse[tid].data_start, 0);
            free(to_analyse[tid].data_start);
            new_packets[tid] = 0;
        }
    }
    return NULL;
}

/*Function to be executed by allocation thread*/
void *handle_allocate(void *arg) {
    int p_index;
    while (1) {
        pthread_mutex_lock(&queue_mutex);
        while (is_empty(&packet_queue)) {
            pthread_cond_wait(&queue_cond, &queue_mutex);
        }
        p_index = get_analysis_index(new_packets, NUMTHREADS);
        if (p_index == -1) {
            continue;
        }
        // Transfer packet from queue to packet struct in to_analyse at given index
        to_analyse[p_index].header = packet_queue.start->header;
        to_analyse[p_index].data_length = packet_queue.start->data_length;
        to_analyse[p_index].data_start = malloc(packet_queue.start->data_length);
        memcpy(to_analyse[p_index].data_start, packet_queue.start->data_start, packet_queue.start->data_length);

        // Indicate to thread that there's a new packet to analyse
        new_packets[p_index] = 1;
        printf("Packet index: %d\n",p_index);
        // Remove packet from queue
        remove_packet(&packet_queue);

        pthread_mutex_unlock(&queue_mutex);

        if (end_analysis) {
            //free(packet);
            return NULL;
        }
    }
    return NULL;
}

void init_threads() {
    //create work queue
    init_structures();

    //create the allocater thread
    pthread_create(&tid[0], NULL, handle_allocate, NULL);
    pthread_detach(tid[0]);

    //create the analysis threads
    for (int i = 0; i < NUMTHREADS; i++) {
        threadnums[i] = i;
        pthread_create(&tid[i + 1], NULL, handle_analyse, &threadnums[i]);
        pthread_detach(tid[i + 1]);
    }
}

void close_threads() {
    while (!remove_packet(&packet_queue)) {
        printf("Packet data freed\n");
    }
    end_analysis = 1;
}

void dispatch(const struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose) {
    pthread_mutex_lock(&queue_mutex);
    store_packet(&packet_queue, header, packet);
    pthread_cond_broadcast(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);
}