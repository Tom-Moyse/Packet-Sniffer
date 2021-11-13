#include "dispatch.h"
#include "sniff.h"

#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#include "analysis.h"

struct node {  // data structure for each node
    struct pcap_pkthdr header;
    unsigned char packet;
    int verbose;
    struct node *next;
};

struct queue {  // data structure for queue
    struct node *head;
    struct node *tail;
};

struct queue *create_queue(void) {  //creates a queue and returns its pointer
    struct queue *q = (struct queue *)malloc(sizeof(struct queue));
    q->head = NULL;
    q->tail = NULL;
    return (q);
}

int isempty(struct queue *q) {  // checks if queue is empty
    return (q->head == NULL);
}

void dequeue(struct queue *q) {  //dequeues a the head node
    struct node *head_node;
    if (isempty(q)) {
        printf("Error: attempt to dequeue from an empty queue");
    } else {
        head_node = q->head;
        q->head = q->head->next;
        if (q->head == NULL)
            q->tail = NULL;
        free(head_node);
    }
}

void destroy_queue(struct queue *q) {  //destroys the queue and frees the memory
    while (!isempty(q)) {
        dequeue(q);
    }
    free(q);
}

void enqueue(struct queue *q, const struct pcap_pkthdr *header, const unsigned char *packet, int verbose) {  //enqueues a node with an item
    struct node *new_node = (struct node *)malloc(sizeof(struct node));
    new_node->header = *header;
    new_node->packet = *packet;
    new_node->verbose = verbose;
    new_node->next = NULL;
    //printf("Size 0: %d, Size 1: %d\n",new_node->nheader->len,new_node->headsize);
    if (isempty(q)) {
        q->head = new_node;
        q->tail = new_node;
    } else {
        q->tail->next = new_node;
        q->tail = new_node;
    }
}

#define NUMTHREADS 1
/* Queue where the main server thread adds work and from where the 
worker threads pull work*/
struct queue *work_queue;

/* mutex lock required for the shared queue*/
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;

pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

pthread_t tid[NUMTHREADS];

static int end_analysis = 0;

/*Function to be executed by each worker thread*/
void *handle_thread(void *arg) {
    const struct pcap_pkthdr *header;
    const unsigned char *packet;
    int verbose;
    /* In a loop continue checking if any more work is left to be done*/
    while (1) {
        // acquire lock, get connection socket descriptor from work queue, release lock
        // wait if work queue is empty
        pthread_mutex_lock(&queue_mutex);
        while (isempty(work_queue)) {
            pthread_cond_wait(&queue_cond, &queue_mutex);
        }
        header = &(work_queue->head->header);
        packet = &(work_queue->head->packet);
        verbose = work_queue->head->verbose;
        dequeue(work_queue);
        pthread_mutex_unlock(&queue_mutex);

        printf("\n\n\nPacket Inside\n");
        dump(packet, header->len);

        //analyse(header, packet, verbose);

        if (end_analysis){
            return NULL;
        }
    }
    return NULL;
}

void init_threads(){
    //create work queue
    work_queue = create_queue();

    //create the worker threads
    for (int i = 0; i < NUMTHREADS; i++) {
        pthread_create(&tid[i], NULL, handle_thread, NULL);
        pthread_detach(tid[i]);
    }
}

void close_threads(){
    destroy_queue(work_queue);
    end_analysis = 1;
}

void dispatch(const struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose) {
                  
    // acquire lock, add connection socket to the work queue,
    // signal the waiting threads, and release lock
    pthread_mutex_lock(&queue_mutex);
    printf("\n\n\nPacket Outside\n");
    dump(packet, header->len);
    enqueue(work_queue, header, packet, verbose);
    //printf("Packet size: %d, True Packet size: %d\n", work_queue->head->header.len, header->len);
    pthread_cond_broadcast(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);
    //analyse(header, packet, verbose);
}