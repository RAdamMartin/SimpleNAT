/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{

  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* Ethernet Protocol */
  uint8_t* ether_packet = malloc(len);
  memcpy(ether_packet,packet,len);
  /* fill in the struct with raw data in ether_packet 
  sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*)ether_packet;
  
  uint8_t* dest = (uint8_t*) ethernet_header->ether_dhost;
  uint8_t* source = (uint8_t*) ethernet_header->ether_shost;
  printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
         dest[0] & 0xff, dest[1] & 0xff, dest[2] & 0xff,
         dest[3] & 0xff, dest[4] & 0xff, dest[5] & 0xff);
  printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
         source[0] & 0xff, source[1] & 0xff, source[2] & 0xff,
         source[3] & 0xff, source[4] & 0xff, source[5] & 0xff);
  */
  uint16_t package_type = ethertype(ether_packet);
  printf("Protocol: %0xff \n",package_type);
  enum sr_ethertype arp = ethertype_arp;
  enum sr_ethertype ip = ethertype_ip;
  /*strip off ethernet header*/
  unsigned int newLength = len - 14; 
  ether_packet = ether_packet+14;
  uint8_t* sr_processed_packet;
  if(package_type==arp){
    /* ARP protocol */
    printf("ARP! \\o/! \n");
  }else if(package_type==ip){
    /* IP protocol */
     printf("IP! \\o/! \n");
     sr_processed_packet = sr_handleIPpacket(ether_packet,newLength);
  }else{
    /* drop package */
     printf("bad protocol! BOO! \n");

  }
  free(ether_packet);
}/* end sr_ForwardPacket */

uint8_t* sr_handleIPpacket(uint8_t* packet,unsigned int len){
  assert(packet);
  uint8_t* ip_packet = malloc(len);
  memcpy(ip_packet,packet,len);
  struct sr_ip_hdr * ipHeader = (struct sr_ip_hdr *) ip_packet;  
  uint16_t currentChecksum = cksum(ip_packet,len);
 
  if(currentChecksum==ipHeader->ip_sum && len>19){
    /* drop TCP/UDP packagets */
    if(ipHeader->ip_tos==6 || ipHeader->ip_tos==17){
      /* ICMP port unreachable */
      goto returnNull;
    }else if(ipHeader->ip_tos==1){
        /* ICMP stuff */
        ipHeader->ip_ttl--;
        return (uint8_t*)ipHeader; 
    }else{
      goto returnNull;
    }
  }else{
    goto returnNull;
  }

  returnNull: 
    free(ip_packet);
    free(ipHeader);
    return NULL;
}
