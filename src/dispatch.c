#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "analysis.h"

typedef struct stored_packet_queue{
    packet_q_node* head;
    packet_q_node* tail;
} stored_packet_queue;

typedef struct packet_q_node{
    struct pcap_pkthdr header;
    unsigned char* data_start;
    unsigned int data_length; 
    struct packet_node* next;
} packet_q_node;

typedef struct packet_node{
    struct pcap_pkthdr header;
    unsigned char* data_start;
    unsigned int data_length; 
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
    packet_q_node* new_packet = malloc(sizeof(packet_q_node));
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
    packet_q_node *current_head = q->head;
    q->head = q->head->next;
    if (q->head == q->tail){
        q->tail = NULL;
    }
    free(current_head->data_start);
    free(current_head);
    current_head = NULL;
    return EXIT_SUCCESS;
}

int get_analysis_index(int* new_packets, int size){
    for (int i = 0; i < size; i++){
        if (new_packets[i]){ return i; }
    }
    return -1;
}

#define NUMTHREADS 2

stored_packet_queue packet_queue;
packet_node *to_analyse;
int new_packets[NUMTHREADS];
int analysis_index = 0;

void init_structures(){
    packet_queue.head = NULL;
    packet_queue.tail = NULL;
    to_analyse = malloc(NUMTHREADS * sizeof(packet_node));
    memset(new_packets, 1, sizeof(new_packets));
}

/* mutex lock required for the shared queue*/
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;

pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

pthread_t tid[NUMTHREADS+1];

static int end_analysis = 0;

/*Function to be executed by each analysis thread*/
void *handle_analyse(void *arg) {
    printf("Thread id: %d", pthread_self());
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
        if (p_index = get_analysis_index(new_packets, NUMTHREADS) == -1){
            continue;
        }
        // Transfer packet from queue to packet struct in to_analyse at given index
        to_analyse[p_index].header = packet_queue.head->header;
        to_analyse[p_index].data_length = packet_queue.head->data_length;
        to_analyse[p_index].data_start = malloc(packet_queue.head->data_length);
        memcpy(to_analyse[p_index].data_start, packet_queue.head->data_start, packet_queue.head->data_length);

        // Indicate to thread that there's a new packet to analyse
        new_packets[p_index] = 1;

        // Remove packet from queue
        remove_packet(&packet_queue);

        pthread_mutex_unlock(&queue_mutex);

        if (end_analysis){
            //free(packet);
            return NULL;
        }
    }
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
      
    pthread_mutex_lock(&queue_mutex);
    store_packet(&packet_queue, header, packet);
    pthread_cond_broadcast(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);
}