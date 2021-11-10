#include "dispatch.h"

#include <pcap.h>

#include "analysis.h"

void dispatch(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose) {
    // TODO: Your part 2 code here
    // This method should handle dispatching of work to threads. At present
    // it is a simple passthrough as this skeleton is single-threaded.
    analyse(header, packet, verbose);
}

struct node {  // data structure for each node
    int item;
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

void destroy_queue(struct queue *q) {  //destroys the queue and frees the memory
    while (!isempty(q)) {
        dequeue(q);
    }
    free(q);
}

int isempty(struct queue *q) {  // checks if queue is empty
    return (q->head == NULL);
}

void enqueue(struct queue *q, int item) {  //enqueues a node with an item
    struct node *new_node = (struct node *)malloc(sizeof(struct node));
    new_node->item = item;
    new_node->next = NULL;
    if (isempty(q)) {
        q->head = new_node;
        q->tail = new_node;
    } else {
        q->tail->next = new_node;
        q->tail = new_node;
    }
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

void printqueue(struct queue *q) {
    if (isempty(q)) {
        printf("The queue is empty\n");
    } else {
        struct node *read_head;
        read_head = q->head;
        printf("The queue elements from head to tail are:\n");
        printf("%d", read_head->item);
        while (read_head->next != NULL) {
            read_head = read_head->next;
            printf("--> %d", read_head->item);
        }
        printf("\n");
    }
}

#include <arpa/inet.h>
#include <ctype.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUFSIZE 2048
#define BACKLOG 500
#define NUMTHREADS 10
#define PORTNO 8888

/* Queue where the main server thread adds work and from where the 
worker threads pull work*/
struct queue *work_queue;

/* mutex lock required for the shared queue*/
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;

pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

/*Function to be executed by each worker thread*/
void *handle_conn(void *arg) {
    int recvlen;
    int conn_sock;
    char buf[BUFSIZE];
    long long limit;
    long long sum = 0, i;

    /* In a loop continue checking if any more work is left to be done*/
    while (1) {
        // acquire lock, get connection socket descriptor from work queue, release lock
        // wait if work queue is empty
        pthread_mutex_lock(&queue_mutex);
        while (isempty(work_queue)) {
            pthread_cond_wait(&queue_cond, &queue_mutex);
        }
        conn_sock = work_queue->head->item;
        dequeue(work_queue);
        pthread_mutex_unlock(&queue_mutex);

        // read from connetion socket into buffer
        recvlen = read(conn_sock, &limit, sizeof(limit));

        // print received message
        if (recvlen > 0) {
            printf("Received number by thread %d: %lld\n", (int)pthread_self(), limit);
        } else {
            printf("uh oh - something went wrong!\n");
        }

        sum = 0;
        for (i = 1; i <= limit; i++) {  //compute the sum
            sum += i;
        }
        // send back to the sender by writing to the conneection socket
        write(conn_sock, &sum, sizeof(sum));
    }
    return NULL;
}

int main(int argc, char **argv) {
    struct sockaddr_in myaddr;           /* our address */
    struct sockaddr_in remaddr;          /* remote address */
    int conn_sock;                       /* connection specific socket */
    socklen_t addrlen = sizeof(remaddr); /* length of addresses */
    int recvlen;                         /* # bytes received */
    int servSocket;                      /* our socket */
    int msgcnt = 0;                      /* count # of messages we received */
    char buf[BUFSIZE];                   /* receive buffer */
    int *sock_ptr;
    int i;
    pthread_t tid[NUMTHREADS];  // array to store thread id's
    unsigned short port_num = PORTNO;

    //create work queue
    work_queue = create_queue();

    //create the worker threads
    for (i = 0; i < NUMTHREADS; i++) {
        pthread_create(&tid[i], NULL, handle_conn, NULL);
    }

    /* create a TCP socket */

    if ((servSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("Error: cannot create socket\n");
        exit(1);
    }

    /* bind the socket to any valid IP address and a specific port */

    memset((char *)&myaddr, 0, sizeof(myaddr));
    myaddr.sin_family = AF_INET;
    myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    myaddr.sin_port = htons(port_num);

    if (bind(servSocket, (struct sockaddr *)&myaddr, sizeof(myaddr)) < 0) {
        printf("Error: bind failed\n");
        exit(1);
    }

    // start listening on the created port for incoming connections
    // the second parameter "BACKLOG" specifies the max number of connections that can
    // wait in a queue to get accepted
    listen(servSocket, BACKLOG);
    printf("waiting on port %d\n", port_num);

    /* now loop, accepting incoming connections and adding them to the work queue */
    while (1) {
        // accept incoming connection request and create connection specific socket

        conn_sock = accept(servSocket, (struct sockaddr *)&remaddr, &addrlen);

        // acquire lock, add connection socket to the work queue,
        // signal the waiting threads, and release lock
        pthread_mutex_lock(&queue_mutex);
        enqueue(work_queue, conn_sock);
        pthread_cond_broadcast(&queue_cond);
        pthread_mutex_unlock(&queue_mutex);
    }
    destroy_queue(work_queue);
    printf("Server program ended normally\n");
    return 0;
}