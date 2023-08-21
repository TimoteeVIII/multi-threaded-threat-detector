#include "analysis.h"
#include <string.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

// declare all functions
void INThandler(int sig);
void stripHeaders(const unsigned char *data);
int blacklistURL(const unsigned char *data);
int isBlacklisted(char *website);
void arpPoison(const unsigned char *data);
void populateIPArray(unsigned int source);
void countDuplicates();

int synSniffed=0; // keeps count of number of SYN packets sniffed
int numOfDuplicateSourceIPs=0; // keeps count of the number of duplicate IPs in array of IPs
int itemsInArray = 50; // initial amount of IPs stored
unsigned int *arrayOfIPs; // store IPs as array of string

int arpReplyCount=0; // counts number of ARP packets

char *blacklistedSites [] = {"www.bbc.com", "www.google.co.uk"}; // array of blacklisted sites
int numOfBlacklistedSitesAttempted = 0; // count of number of blacklisted sites attempted to be accessed

#define IP_PROTOCOL_NUMBER 2048
#define ARP_PROTOCOL_NUMBER 2054
#define TCP_PROTOCOL_NUMBER 6
#define HTTP_PORT_NUMBER 80

// strips the different headers of the packet
void stripHeaders(const unsigned char *data){
  // extract necessary data from ether header structure
  struct ether_header *ethHeader = (struct ether_header *) data;
  unsigned short protocol = 0;
  protocol = ntohs(ethHeader->ether_type);
  
  // declare variables that will be stripped from IP header
  unsigned int ipProtocol = 0;
  unsigned short ipHeaderLen = 0;
  struct sockaddr_in source, dest;
  unsigned int sourceAsInt = 0;
  // if the ethernet layer specifies IPv4 is being used, strip its header
  if(protocol == IP_PROTOCOL_NUMBER){
  struct iphdr *ipHeader = (struct iphdr *) (data + ETH_HLEN);
  ipHeaderLen = (ipHeader->ihl) * 4;
  ipProtocol = ipHeader->protocol;
  memset(&source, 0, sizeof(source));
  memset(&dest, 0, sizeof(dest));
	source.sin_addr.s_addr = ipHeader->saddr;
  dest.sin_addr.s_addr = ipHeader->daddr;
  sourceAsInt = ipHeader->saddr;
  }
  // declare variables that will be stripped from TCP header
  unsigned short destPort = 0;
  unsigned short synActive = 0, urgActive = 0, ackActive = 0, pshActive = 0, rstActive = 0, finActive = 0;
  int tcpHeaderLen = 0;
  // if IP layer specifies TCP is being used, strip TCP header
  if(ipProtocol == TCP_PROTOCOL_NUMBER){
  struct tcphdr *tcpHeader = (struct tcphdr *)(data + ETH_HLEN + ipHeaderLen);
  // unsigned short sourcePort = ntohs(tcpHeader->source);
  destPort = ntohs(tcpHeader->dest);
  tcpHeaderLen = tcpHeader->doff*4;
  synActive = tcpHeader->syn;
  urgActive = tcpHeader->urg;
  ackActive = tcpHeader->ack;
  pshActive = tcpHeader->psh;
  rstActive = tcpHeader->rst;
  finActive = tcpHeader->fin;
  }
  // if IPv4 and TCP being used, and only SYN flag active, check for SYN attack 
  if(ipProtocol == TCP_PROTOCOL_NUMBER && synActive && !urgActive && !ackActive && !pshActive && !rstActive && !finActive){
    populateIPArray(sourceAsInt);
  }
  // if ARP is being used, check for ARP poison
  if(protocol == ARP_PROTOCOL_NUMBER){
    arpPoison(data);
  }
  // if TCP and HTTP being used, check for blacklisted site
  if(ipProtocol == TCP_PROTOCOL_NUMBER && destPort == HTTP_PORT_NUMBER){
    if(blacklistURL((data + ETH_HLEN + ipHeaderLen + tcpHeaderLen)) == 1){
      printf("==============================\n");
      printf("Blacklisted URL violation detected\n");
      printf("Source IP Address: %s\n", inet_ntoa(source.sin_addr));
      printf("Destination IP Address: %s\n", inet_ntoa(dest.sin_addr));
      printf("==============================\n");
    }
    
  }
}

// function that returns whether URL name of HTTP header is blacklisted
int blacklistURL(const unsigned char *data){
  char *host = NULL;
  char *connection = NULL;
  char *dest = NULL;
  char *url = NULL;
  host = strstr((char *) data, "Host: ");
  connection = strstr((char *) data, "Connection: ");
  int i=0;
  // if host name is in packet, get its name, and pass to isBlacklisted to see if it's blacklisted
  if(host){ 
    dest = malloc(connection-host + 1);
    strncpy(dest, host+6, connection-host);
    while(dest[i] != '\n'){
      i++;
    }
    url = malloc(i+1);
    strncpy(url, dest, i-1);
    url[i] = '\0';
    // if the URL is blacklisted, increment blacklist counter, and free memory
    if(isBlacklisted(url) == 1){
      numOfBlacklistedSitesAttempted++;
      free(dest);
      free(url);
      return 1;
    }
  }
  free(dest);
  free(url);
  return 0;
}

// loops through url provided and checks if it's blacklisted, if so return 1
int isBlacklisted(char *website){
  int len = sizeof(blacklistedSites)/sizeof(blacklistedSites[0]);
  int i = 0;
  for(i=0;i<len;i++){
    if(strcmp(website, blacklistedSites[i]) == 0){
      return 1;
    }
  }
  return 0;
}

// check arp header to see if its operation is REPLY, if so increase the counter
// that keeps the count of the number of arp replies received
void arpPoison(const unsigned char *data){
  struct ether_arp *arpHeader = (struct ether_arp *)(data + ETH_HLEN);
  unsigned short arpOperation = ntohs(arpHeader->arp_op);
  if(arpOperation == ARPOP_REPLY){
    arpReplyCount++;
  }
}

// this function puts the source IP of a packet into an array that is
// suspected of performing a SYN attack
void populateIPArray(unsigned int source){
  synSniffed++;
  // when the first SYN packet is sniffed, initialise the array of IPs
  if(synSniffed == 1){
    arrayOfIPs = malloc(itemsInArray * sizeof(unsigned int));    
    //allocateArrayMemory(0, itemsInArray);
  }
  // if array of IPs too small to hold next IP, increase array size by 50
  if(synSniffed + 1 >= itemsInArray){
    unsigned int *tmp_ptr = realloc(arrayOfIPs, (itemsInArray + 50) * sizeof(unsigned int));
    if (tmp_ptr != NULL){
      arrayOfIPs = tmp_ptr;
     // allocateArrayMemory(itemsInArray, itemsInArray+50);
      itemsInArray += 50;
    }
    else {
      perror("Failed to reallocate memory.");
    }
  }
  // copy IP to array of IPs
  arrayOfIPs[synSniffed-1] = source;
}


// when CTRL+C pressed, this is called to count the number of duplicates
// in the array of IPs, which is subtracted from the syn sniffed to determine
// the number of unique IPs
void countDuplicates(){
  int i = 0, j = 0;
  // goes through each IP, compares it with every IP after it, if unique,
  // increase num of duplicate IPs, and go to next IP
   for(i=0; i < synSniffed; i++){
    for(j=i+1; j < synSniffed; j++){
      if(arrayOfIPs[i] == arrayOfIPs[j]){
        numOfDuplicateSourceIPs++;
        break;
      }
    }
  }
}

// strips packet headers and determines whether they may be malicious
void analyse(const unsigned char *packet) {
  // TODO your part 2 code here
 signal(SIGINT, INThandler);
 stripHeaders(packet);
}

// function for when CTRL+C pressed - first counts duplicate IPs, then 
// outputs the number of unique IPs, ARP responses, and URL blacklist violations
void INThandler(int sig){
  countDuplicates();
  printf("\nIntusion Detection Report:\n");
  printf("%d SYN packets sniffed from %d different IPs (syn attack)\n", synSniffed, synSniffed - numOfDuplicateSourceIPs);
  printf("%d ARP responses (cache poisoning)\n", arpReplyCount);
  printf("%d URL Blacklist violations\n", numOfBlacklistedSitesAttempted);
  free(arrayOfIPs);
  exit(0);
}

 
