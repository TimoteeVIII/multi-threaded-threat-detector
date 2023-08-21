#include "dispatch.h"
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <pcap.h>
#include "analysis.h"
#include <signal.h>


#define NUM_THREADS 1

// structure to contain the arguments used by the thread function required by the analyse function 
struct thread_args{
 // const struct pcap_pkthdr *header;
  const unsigned char *packet;
 // int verbose;
};

struct node{ // data structure for each node
  struct thread_args *item;
  struct node *next;
};

struct queue{ // data structure for queue
  struct node *head;
  struct node *tail;
};

// declare all functions 
struct queue *create_queue(void);
int isempty(struct queue *q);
void enqueue(struct queue *q, struct thread_args *item);
void dequeue(struct queue *q);
void destroy_queue(struct queue *q);
void *threadCode(void *arg);
void initialiseThreads();

struct queue *create_queue(void){ //creates a queue and returns its pointer
  struct queue *q=(struct queue *)malloc(sizeof(struct queue));
  q->head=NULL;
  q->tail=NULL;
  return(q);
}

void destroy_queue(struct queue *q){  //destroys the queue and frees the memory
  while(!isempty(q)){
    dequeue(q);
  }
  free(q);
}

int isempty(struct queue *q){ // checks if queue is empty
  return(q->head==NULL);
}

void enqueue(struct queue *q, struct thread_args *item){ //enqueues a node with an item
  struct node *new_node=(struct node *)malloc(sizeof(struct node));
  new_node->item=item;
  new_node->next=NULL;
  if(isempty(q)){
    q->head=new_node;
    q->tail=new_node;
  }
  else{
    q->tail->next=new_node;
    q->tail=new_node;
  }
}

void dequeue(struct queue *q){ //dequeues a the head node
  struct node *head_node;
  if(isempty(q)){
    printf("Error: attempt to dequeue from an empty queue");
  }
  else{
    head_node=q->head;
    q->head=q->head->next;
    if(q->head==NULL)
      q->tail=NULL;
    free(head_node);
  }
}

//initialise the work queue, the array of worker threads, and the mutexes
struct queue *work_queue;
pthread_t tid[NUM_THREADS];
int packetCount = 0;
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

// code to be run by each worker thread
void *threadCode(void *arg){
  struct thread_args *args = malloc(sizeof(struct thread_args *));
  while(1){ // wait until queue isn't empty, and the queue mutex is free, then dequeue the packet and send that to be analysed
    pthread_mutex_lock(&queue_mutex);
		while(isempty(work_queue)){  
			pthread_cond_wait(&queue_cond,&queue_mutex);
		}
		args = work_queue->head->item;
		dequeue(work_queue);
		pthread_mutex_unlock(&queue_mutex);
    analyse(args->packet);
    free(args);
  }
  return NULL;
}

// code that creates the work queue and creates each worker thread when the first packet is encountered
void initialiseThreads(){
    work_queue=create_queue();
    int i;
    for(i=0;i<NUM_THREADS;i++){
	  	pthread_create(&tid[i],NULL,threadCode,NULL);
	  }
}



void dispatch(const struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose) {
  // This method should handle dispatching of work to threads. At present
  // it is a simple passthrough as this skeleton is single-threaded.
  //analyse(header, packet, verbose);
  packetCount = packetCount + 1;
  if(packetCount == 1){ // create threads and work queue when first packet encountered
    initialiseThreads();
  } 
  // create a thread_arg pointer so the packet's details can be enqueued and subsequently anaylsed by threadCode
  struct thread_args *a = malloc(sizeof(struct thread_args *));
 // a->header = header;
  a->packet = packet;
 // a->verbose = verbose;
  pthread_mutex_lock(&queue_mutex);
  enqueue(work_queue, a);
  pthread_cond_broadcast(&queue_cond);
  pthread_mutex_unlock(&queue_mutex);
}