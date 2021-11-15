#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "analysis.h"

typedef struct stored_packet_queue{
    packet_node* head;
    packet_node* tail;
} stored_packet_queue;

typedef struct packet_node{
    struct pcap_pkthdr header;
    unsigned char* data_start;
    unsigned int data_length; 
    struct packet_node* next;
} packet_node;

int is_empty(stored_packet_queue *q){
    return (!q->head);
}

int tail_empty(stored_packet_queue *q){
    return (!q->tail);
}

void store_packet(stored_packet_queue *q, const struct pcap_pkthdr *header, const unsigned char *packet){
    // Allocate resources and create packet
    unsigned int packet_size = header->len;
    packet_node* new_packet = malloc(sizeof(packet_node));
    unsigned char* packet_data = malloc(sizeof(unsigned char) * packet_size);
    memcpy(packet_data, packet, packet_size);
    new_packet->header = *header;
    new_packet->data_length = packet_size;
    new_packet->data_start = packet_data;

    if (is_empty(q)){
        if(tail_empty(q)){
            q->head = new_packet;
        }
        else{
            q->tail = new_packet;
        }
    }
    else{
        q->tail->next = new_packet;
        q->tail = q->tail->next;
    }
}

int remove_packet(stored_packet_queue *q){
    if (is_empty(q)){
        printf("The queue is empty - operation failed\n");
        return EXIT_FAILURE;
    }
    if (tail_empty(q)){
        free(q->head->data_start);
        free(q->head);
        q->head = NULL;
        return EXIT_SUCCESS;
    }
    packet_node *current_head = q->head;
    q->head = q->head->next;
    if (q->head == q->tail){
        q->tail = NULL;
    }
    free(current_head->data_start);
    free(current_head);
    current_head = NULL;
    return EXIT_SUCCESS;
}

#define NUMTHREADS 1

stored_packet_queue packet_queue;
packet_node *to_analyse;

void init_structures(){
    to_analyse = calloc(NUMTHREADS, 1500);
    packet_queue.head = NULL;
    packet_queue.tail = NULL;
}

/* mutex lock required for the shared queue*/
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;

pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

pthread_t tid[NUMTHREADS+1];

static int end_analysis = 0;

/*Function to be executed by each analysis thread*/
void *handle_analyse(void *arg) {
    return NULL;
}

/*Function to be executed by allocation thread*/
void *handle_allocate(void *arg) {
    return NULL;
}

void init_threads(){
    //create work queue
    init_structures();

    //create the allocater thread
    pthread_create(&tid[0], NULL, handle_allocate, NULL);
    pthread_detach(tid[0]);

    //create the analysis threads
    for (int i = 1; i < NUMTHREADS + 1; i++) {
        pthread_create(&tid[i], NULL, handle_analyse, NULL);
        pthread_detach(tid[i]);
    }
}

void close_threads(){
    while (remove_packet(&packet_queue)){
        printf("Packet data freed\n");
    }
    end_analysis = 1;
}

void dispatch(const struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose) {
      
    
}