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
  printf("Router Accessed\n");
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);
  struct sr_if * iface = sr_get_interface(sr, interface);
  printf("*** -> Received packet of length %d \n",len);
  
  /* Ethernet Protocol */
  if(len>=34){
    uint8_t* ether_packet = malloc(len+28);
    memcpy(ether_packet,packet,len);

    uint16_t package_type = ethertype(ether_packet);
    enum sr_ethertype arp = ethertype_arp;
    enum sr_ethertype ip = ethertype_ip;

    if(package_type==arp){
      /* ARP protocol */
      sr_handleARPpacket(sr, ether_packet, len, iface);
    }else if(package_type==ip){
      /* IP protocol */
      sr_handleIPpacket(sr, ether_packet,len, iface);
    }else{
      /* drop package */
       printf("bad protocol! BOO! \n");
    }
    free(ether_packet);
  }
}/* end sr_ForwardPacket */

void sr_handleIPpacket(struct sr_instance* sr, uint8_t* packet,unsigned int len, struct sr_if * iface){
  assert(packet);
  struct sr_ethernet_hdr* ethHeader = (struct sr_ethernet_hdr*) packet;
  uint8_t* ip_packet = packet+sizeof(sr_ethernet_hdr_t);
  struct sr_ip_hdr * ipHeader = (struct sr_ip_hdr *) (ip_packet);  
  print_hdrs(packet,len);

  uint16_t incm_cksum = ipHeader->ip_sum;
  ipHeader->ip_sum = 0;
  uint16_t currentChecksum = cksum(ip_packet,20);
  ipHeader->ip_sum = incm_cksum;
  uint8_t* icmp_packet;

  /* if the destination address is not one of my routers interfaces */
  if (currentChecksum==incm_cksum && sr_get_interface_from_ip(sr,ntohl(ipHeader->ip_dst)) == NULL){
    /* check cache for ip->mac mapping for next hop */
    struct sr_arpentry *entry;
    entry = sr_arpcache_lookup(&sr->cache, ipHeader->ip_dst);
    struct sr_rt * rt = (struct sr_rt *)sr_find_routing_entry_int(sr, ipHeader->ip_dst);

    /* found next hop. send packet */
    if (ipHeader->ip_ttl <= 1){   /* IP TTL died. send ICMP type 11, code 0 */
      icmp_packet = createICMP(11, 0, ip_packet,len-14);
      memcpy(ip_packet+20,icmp_packet,sizeof(sr_icmp_t3_hdr_t));
      ipHeader->ip_p = 1;
      ipHeader->ip_len = htons(20+8+(len-34<28?len-34:28));
      free(icmp_packet);      
    } else if (entry && rt) {    /* found next hop. send packet */
      iface = sr_get_interface(sr, rt->interface);
      ipHeader->ip_ttl = ipHeader->ip_ttl - 1;
      ipHeader->ip_sum = 0;
      ipHeader->ip_sum = cksum(ip_packet,20);
      
      memcpy(ethHeader->ether_dhost, entry->mac,6);
      memcpy(ethHeader->ether_shost, iface->addr,6);

      sr_send_packet(sr,packet,len,iface->name);
      free(entry);
      ip_packet = NULL;
    } else if (rt) { /* send an arp request to find out what the next hop should be */
      struct sr_arpreq *req;
      sr_arpcache_insert(&(sr->cache), ethHeader->ether_shost, ipHeader->ip_src);
      req = sr_arpcache_queuereq(&(sr->cache), ipHeader->ip_dst, packet, len, iface->name);
      handle_arpreq(sr, req);
      ip_packet = NULL;
    } else {  /* no route found. send ICMP type 3, code 0 */
      printf("No route found\n");
      icmp_packet = createICMP(3, 0, ip_packet,len-14);
      memcpy(ip_packet+20,icmp_packet,sizeof(sr_icmp_t3_hdr_t));
      ipHeader->ip_p = 1;
      ipHeader->ip_len = htons(20+8+(len-34<28?len-34:28));;
      free(icmp_packet);      
    }
  }
  else if(currentChecksum==incm_cksum){
    if(ipHeader->ip_p==6 || ipHeader->ip_p==17){  /* IP TCP/UDP */
      icmp_packet = createICMP(3,3,ip_packet,len-14);
      memcpy(ip_packet+20,icmp_packet,sizeof(sr_icmp_t3_hdr_t));
      
      ipHeader->ip_p = 1;
      ipHeader->ip_len = htons(20+8+(len-34<28?len-34:28));
      free(icmp_packet);
    }else if(ipHeader->ip_tos==0 && ipHeader->ip_p==1){ /* IP ping */
	    struct sr_icmp_hdr * icmp_header = (struct sr_icmp_hdr *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      incm_cksum = icmp_header->icmp_sum;
      icmp_header->icmp_sum = 0;
	    currentChecksum = cksum(icmp_header,len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
	    
      if(currentChecksum == incm_cksum && icmp_header->icmp_type == 8 && icmp_header->icmp_code == 0) {
	      icmp_header->icmp_type = 0;
        ipHeader->ip_sum = 0;
	      icmp_header->icmp_sum = cksum(icmp_header,len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
	    }
      else{
        printf("ICMP INVALID\n");
        printf("%d != %d OR %d != %d\n",currentChecksum,incm_cksum, icmp_header->icmp_type, 8);
      }
    } else {
      printf("IP Bad\n");
      ip_packet = NULL;
    }
  }
  else{
      printf("IP INVALID\n");
      printf("%d != %d OR %d <= 34\n",currentChecksum,ipHeader->ip_sum, len);
      ip_packet = NULL;
  }
  if(ip_packet){  /* send ICMP packet */
    ipHeader->ip_dst = ipHeader->ip_src;
    ipHeader->ip_src = iface->ip;
    ipHeader->ip_ttl = 64;
    ipHeader->ip_sum = 0;
    ipHeader->ip_sum = cksum(ip_packet,20);

    struct sr_arpentry *entry;
    entry = sr_arpcache_lookup(&sr->cache, ipHeader->ip_dst);
    struct sr_rt * rt = (struct sr_rt *)sr_find_routing_entry_int(sr, ipHeader->ip_dst);

    if (entry && rt) {    /* found next hop. send packet */
      iface = sr_get_interface(sr, rt->interface);
      ipHeader->ip_ttl = ipHeader->ip_ttl - 1;
      ipHeader->ip_sum = 0;
      ipHeader->ip_sum = cksum(ip_packet,20);

      memcpy(ethHeader->ether_dhost, entry->mac,6);
      memcpy(ethHeader->ether_shost, iface->addr,6);

      printf("SENDING\n");
      print_hdrs(packet,len);
      sr_send_packet(sr,packet,len,iface->name);
      free(entry);
      ip_packet = NULL;
    } else if (rt) { /* send an arp request to find out what the next hop should be */
      struct sr_arpreq *req;
      sr_arpcache_insert(&(sr->cache), ethHeader->ether_shost, ipHeader->ip_src);
      req = sr_arpcache_queuereq(&(sr->cache), ipHeader->ip_dst, packet, len, iface->name);
      handle_arpreq(sr, req);
      ip_packet = NULL;
    }
  }
}

void sr_handleARPpacket(struct sr_instance *sr, uint8_t* packet, unsigned int len, struct sr_if * iface) {
    assert(packet);
    struct sr_ethernet_hdr* ethHeader = (struct sr_ethernet_hdr*) packet;
    struct sr_arp_hdr * arpHeader = (struct sr_arp_hdr *) (packet+14);

    enum sr_arp_opcode request = arp_op_request;
    enum sr_arp_opcode reply = arp_op_reply;

    struct sr_if *interface = sr_get_interface_from_ip(sr, htonl(arpHeader->ar_tip));

    /* handle an arp request.*/
    if (ntohs(arpHeader->ar_op) == request) {
        /* found an ip->mac mapping. send a reply to the requester's MAC addr */
        if (interface){
          arpHeader->ar_op = ntohs(reply);
          uint32_t temp = arpHeader->ar_sip;
          arpHeader->ar_sip = arpHeader->ar_tip;
          arpHeader->ar_tip = temp;
          memcpy(arpHeader->ar_tha, arpHeader->ar_sha,6);
          memcpy(arpHeader->ar_sha, iface->addr,6);

          /*swapping outgoing and incoming addr*/
          memcpy(ethHeader->ether_dhost, ethHeader->ether_shost,6);
          memcpy(ethHeader->ether_shost, iface->addr,6);
          sr_send_packet(sr,(uint8_t*)ethHeader,len,iface->name);
        }
    }
    /* handle an arp reply */
    else {
      struct sr_packet *req_packet = NULL;
      struct sr_arpreq *req = NULL;
      pthread_mutex_lock(&(sr->cache.lock));   
      
      for (req = sr->cache.requests; req != NULL; req = req->next){
        if(req->ip == arpHeader->ar_sip){
          /* find the interface the packets should be sent out of */
          struct sr_rt * rt = (struct sr_rt *)sr_find_routing_entry_int(sr, req->ip);
          if (rt) {
            iface = sr_get_interface(sr, rt->interface);
            /* send all packets waiting on the request that was replied to */
            for (req_packet = req->packets; req_packet != NULL; req_packet = req_packet->next) {
              struct sr_ethernet_hdr * outEther = (struct sr_ethernet_hdr *)req_packet->buf;
              memcpy(outEther->ether_shost, iface->addr,6);
              memcpy(outEther->ether_dhost, ethHeader->ether_shost,6);

              struct sr_ip_hdr * outIP = (struct sr_ip_hdr *)(req_packet->buf+14);
              outIP->ip_ttl = outIP->ip_ttl-1;
              outIP->ip_sum = 0;
              outIP->ip_sum = cksum((uint8_t *)outIP,20);
              
              sr_send_packet(sr,req_packet->buf,req_packet->len,iface->name);
            }
            sr_arpreq_destroy(&(sr->cache), req);
          }
          break;
        }
      }
      pthread_mutex_unlock(&(sr->cache.lock));
      sr_arpcache_insert(&(sr->cache),arpHeader->ar_sha,arpHeader->ar_sip);
    }
}