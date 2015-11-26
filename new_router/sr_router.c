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

void handleARPpacket(struct sr_instance *sr,
        uint8_t* packet, 
        unsigned int len, 
        struct sr_if * iface)
{
    sr_ethernet_hdr_t* eth_header = (sr_ethernet_hdr_t*) packet;
    sr_arp_hdr_t * arp_header = (sr_arp_hdr_t *) (packet+SIZE_ETH);
    struct sr_if *interface = sr_get_interface_from_ip(sr, arp_header->ar_tip);
    if (interface == NULL){
        printf("ARP Not for us\n");
    }
    else if(ntohs(arp_header->ar_op) == arp_op_request){
        printf("Replying to ARP request\n");
        arp_header->ar_op = ntohs(arp_op_reply);
        uint32_t temp = arp_header->ar_sip;
        arp_header->ar_sip = arp_header->ar_tip;
        arp_header->ar_tip = temp;
        memcpy(arp_header->ar_tha, arp_header->ar_sha,6);
        memcpy(arp_header->ar_sha, iface->addr,6);
        memcpy(eth_header->ether_dhost, eth_header->ether_shost,6);
        memcpy(eth_header->ether_shost, iface->addr,6);/*ENDIANESS*/
        sr_send_packet(sr
                       ,packet
                       ,SIZE_ETH+SIZE_ARP
                       ,iface->name);
    }
    else if (ntohs(arp_header->ar_op) == arp_op_reply){/*} && strcmp(iface->addr,eth_header->ether_dhost) == 0){*/
        printf("Processing ARP reply\n");
        struct sr_arpreq *req;
        struct sr_packet *pckt;
        req = sr_arpcache_insert(&(sr->cache), arp_header->ar_sha, arp_header->ar_sip);
        if(req){
            /*struct sr_rt * rt = (struct sr_rt *)sr_find_routing_entry_int(sr, req->ip);*/
            for (pckt = req->packets; pckt != NULL; pckt = pckt->next){
                sr_ethernet_hdr_t * outEther = (sr_ethernet_hdr_t *)pckt->buf;
                memcpy(outEther->ether_shost, iface->addr,6);
                memcpy(outEther->ether_dhost, arp_header->ar_sha,6);
                sr_ip_hdr_t * outIP = (sr_ip_hdr_t *)(pckt->buf+14);
                outIP->ip_ttl = outIP->ip_ttl-1;
                outIP->ip_sum = 0;
                outIP->ip_sum = cksum((uint8_t *)outIP,20);
                sr_send_packet(sr,pckt->buf,pckt->len,iface->name);
            }
        }
    }
}

void handleIPPacket(struct sr_instance* sr, 
        uint8_t* packet,
        unsigned int len, 
        struct sr_if * iface)
{
    sr_ethernet_hdr_t* eth_header = (sr_ethernet_hdr_t*) packet;
    sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *)(packet+SIZE_ETH);
    struct sr_if *interface= sr_get_interface_from_ip(sr,ip_header->ip_dst);

    uint16_t incm_cksum = ip_header->ip_sum;
    ip_header->ip_sum = 0;
    uint16_t calc_cksum = cksum((uint8_t*)ip_header,20);
    ip_header->ip_sum = incm_cksum;
    if (calc_cksum != incm_cksum){/* || strcmp(iface->addr,eth_header->ether_dhost) != 0){*/
        printf("Bad cksum/interface mismatch\n");
    } else if (interface != NULL){
        printf("For us\n");
        if(ip_header->ip_p==6){ /*TCP*/
            printf("TCP\n");
            sr_send_icmp(packet, len, 3, 3);
        } else if (ip_header->ip_p==17){ /*UDP*/
            printf("UDP\n");
            sr_send_icmp(packet, len, 3, 3);
        } else if (ip_header->ip_p==1 && ip_header->ip_tos==0){ /*ICMP*/
            printf("ICMP\n");
            sr_icmp_hdr_t* icmp_header = (sr_icmp_hdr_t *)(packet+SIZE_ETH+SIZE_IP);
            incm_cksum = icmp_header->icmp_sum;
            icmp_header->icmp_sum = 0;
            calc_cksum = cksum((uint8_t*)ip_header,20);
            icmp_header->icmp_sum = incm_cksum;
            uint8_t type = icmp_header->icmp_type;
            uint8_t code = icmp_header->icmp_code;
            if (incm_cksum != calc_cksum){
                printf("Bad cksum\n");
            } else if (type == 8 && code == 0) {
                sr_send_icmp(packet, len, 0, 0);
            }
        }
    } else if (ip_header->ip_ttl <= 1){
        printf("Packet died\n");
    } else {
        printf("Not for us\n");
    }
    printf("TODO: Implement IP\n");
}

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
    /* fill in code here */
    printf("*** -> Received packet of length %d \n",len);
    print_hdrs(packet,len);
    struct sr_if * iface = sr_get_interface(sr, interface);
    if(len>=34){
        uint8_t* ether_packet = malloc((size_t)(len+28));
        memcpy(ether_packet,packet,len);
        uint16_t packet_type = ethertype(ether_packet);
        if(packet_type == ethertype_arp){
            handleARPpacket(sr, ether_packet, len, iface);
        }else if(packet_type==ethertype_ip){
            handleIPPacket(sr, ether_packet, len, iface);
        }else{
            printf("Unsupported Protocol!\n");
        }
        free(ether_packet);
    }
}/* end sr_ForwardPacket */

void sr_send_icmp(uint8_t *buf, unsigned int len, unsigned int type, unsigned int code){
	printf("TODO: Send ICMP type %d code %d to\n",type, code);
	print_hdrs(buf,(uint32_t)len);
}