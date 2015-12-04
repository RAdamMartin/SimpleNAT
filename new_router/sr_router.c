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
#include "sr_nat.h"

/*INTERNAL TO sr_router*/
void sendIPPacket(struct sr_instance* sr,
               uint8_t* packet, 
               unsigned int len, 
               struct sr_rt* rt){
    struct sr_if* iface = sr_get_interface(sr, rt->interface);
    struct sr_arpentry* entry;
    pthread_mutex_lock(&(sr->cache.lock));
    entry = sr_arpcache_lookup(&sr->cache, (uint32_t)(rt->gw.s_addr));
    sr_ethernet_hdr_t* eth_header = (sr_ethernet_hdr_t*) packet;
    sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*) (packet+SIZE_ETH);
    
    if (entry) {
        fprintf(stderr,"Found cache hit\n");
        iface = sr_get_interface(sr, rt->interface);
        memcpy(eth_header->ether_dhost,entry->mac,6);
        memcpy(eth_header->ether_shost,iface->addr,6);
        ip_header->ip_ttl = ip_header->ip_ttl - 1;
        ip_header->ip_sum = 0;
        ip_header->ip_sum = cksum((uint8_t *)ip_header,SIZE_IP);
        sr_send_packet(sr,packet,len,rt->interface);
        free(entry);
    } else {
        fprintf(stderr,"Adding ARP Request\n");
        memcpy(eth_header->ether_shost,iface->addr,6);
        struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), 
                                                     (uint32_t)(rt->gw.s_addr), 
                                                     packet, 
                                                     len, 
                                                     rt->interface);
        sr_handle_arpreq(sr,req);
    }
    pthread_mutex_unlock(&(sr->cache.lock));
} /*end sendIPPacket */

/*INTERNAL TO sr_router*/
void handleARPpacket(struct sr_instance *sr,
        uint8_t* packet, 
        unsigned int len, 
        struct sr_if * rec_iface)
{
    sr_ethernet_hdr_t* eth_header = (sr_ethernet_hdr_t*) packet;
    sr_arp_hdr_t * arp_header = (sr_arp_hdr_t *) (packet+SIZE_ETH);
    struct sr_if *tgt_iface = sr_get_interface_from_ip(sr, arp_header->ar_tip);
    if (tgt_iface == NULL || strcmp(rec_iface->name, tgt_iface->name) != 0){
        fprintf(stderr,"ARP Not for us\n");
    }
    else if(ntohs(arp_header->ar_op) == arp_op_request){
        fprintf(stderr,"Replying to ARP request\n");
        /*sr_arpcache_insert(&(sr->cache), arp_header->ar_sha, arp_header->ar_sip);*/
        /*Setup ETH Header for Reply*/
        memcpy(eth_header->ether_dhost, arp_header->ar_sha,6);
        memcpy(eth_header->ether_shost, rec_iface->addr,6);
        /*Setup ARP Header for Reply*/
        arp_header->ar_op = ntohs(arp_op_reply);
        uint32_t temp = arp_header->ar_sip;
        arp_header->ar_sip = arp_header->ar_tip;
        arp_header->ar_tip = temp;
        memcpy(arp_header->ar_tha, arp_header->ar_sha,6);
        memcpy(arp_header->ar_sha, rec_iface->addr,6);
        sr_send_packet(sr, packet, SIZE_ETH+SIZE_ARP, rec_iface->name);
    } else if (ntohs(arp_header->ar_op) == arp_op_reply){/*} && strcmp(rec_iface->addr,eth_header->ether_dhost) == 0){*/
        fprintf(stderr,"Processing ARP reply\n");
        struct sr_arpreq *req;
        struct sr_packet *pckt;
        pthread_mutex_lock(&(sr->cache.lock));
        req = sr_arpcache_insert(&(sr->cache), arp_header->ar_sha, arp_header->ar_sip);
        if(req){
            fprintf(stderr,"Clearing queue\n");
            for (pckt = req->packets; pckt != NULL; pckt = pckt->next){
                sr_ethernet_hdr_t * outETH = (sr_ethernet_hdr_t *)(pckt->buf);
                memcpy(outETH->ether_shost, rec_iface->addr,6);
                memcpy(outETH->ether_dhost, arp_header->ar_sha,6);
                sr_ip_hdr_t * outIP = (sr_ip_hdr_t *)(pckt->buf+14);
                outIP->ip_ttl = outIP->ip_ttl-1;
                outIP->ip_sum = 0;
                outIP->ip_sum = cksum((uint8_t *)outIP,20);
                sr_send_packet(sr,pckt->buf,pckt->len,rec_iface->name);
            }
            sr_arpreq_destroy(&(sr->cache), req);
        }
        pthread_mutex_unlock(&(sr->cache.lock));
    }
}/* end handleARPPacket */

/*INTERNAL TO sr_router*/
void handleIPPacket(struct sr_instance* sr, 
        uint8_t* packet,
        unsigned int len, 
        struct sr_if * rec_iface)
{
    sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *)(packet+SIZE_ETH);
    struct sr_if *tgt_iface= sr_get_interface_from_ip(sr,ip_header->ip_dst);

    uint16_t incm_cksum = ip_header->ip_sum;
    ip_header->ip_sum = 0;
    uint16_t calc_cksum = cksum((uint8_t*)ip_header,20);
    ip_header->ip_sum = incm_cksum;
    if (calc_cksum != incm_cksum){
        fprintf(stderr,"Bad checksum\n");
    } else if (tgt_iface != NULL){
        fprintf(stderr,"For us\n");
        if(ip_header->ip_p==6){ /*TCP*/
            fprintf(stderr,"TCP\n");
            sr_send_icmp(sr, packet, len, 3, 3, ip_header->ip_dst);
        } else if (ip_header->ip_p==17){ /*UDP*/
            fprintf(stderr,"UDP\n");
            sr_send_icmp(sr, packet, len, 3, 3, ip_header->ip_dst);
        } else if (ip_header->ip_p==1 && ip_header->ip_tos==0){ /*ICMP PING*/
            fprintf(stderr,"ICMP\n");
            sr_icmp_hdr_t* icmp_header = (sr_icmp_hdr_t *)(packet+SIZE_ETH+SIZE_IP);
            incm_cksum = icmp_header->icmp_sum;
            icmp_header->icmp_sum = 0;
            calc_cksum = cksum((uint8_t*)icmp_header,len-SIZE_ETH-SIZE_IP);
            icmp_header->icmp_sum = incm_cksum;
            uint8_t type = icmp_header->icmp_type;
            uint8_t code = icmp_header->icmp_code;
            if (incm_cksum != calc_cksum){
                fprintf(stderr,"Bad cksum %d != %d\n", incm_cksum, calc_cksum);
            } else if (type == 8 && code == 0) {
                sr_send_icmp(sr, packet, len, 0, 0, ip_header->ip_dst);
            }
        }
    } else if (ip_header->ip_ttl <= 1){
        fprintf(stderr,"Packet died\n");
        sr_send_icmp(sr, packet, len, 11, 0,0);
    } else {
        fprintf(stderr,"Not for us\n");
        struct sr_rt* rt;
        rt = (struct sr_rt*)sr_find_routing_entry_int(sr, ip_header->ip_dst);
        if (rt){
            sendIPPacket(sr,packet,len,rt);
        } else {
            sr_send_icmp(sr, packet, len, 3, 0, 0);
        }
    }
}/* end handleIPPacket */

void natHandleIPPacket(struct sr_instance* sr, 
        uint8_t* packet,
        unsigned int len, 
        struct sr_if * rec_iface)
{
    sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *)(packet+SIZE_ETH);
    struct sr_if *tgt_iface = sr_get_interface_from_ip(sr,ip_header->ip_dst);
    struct sr_rt * rt = NULL;
    struct sr_nat_mapping *map = NULL;
    /*struct sr_if *int_if = sr_get_interface(sr,"eth1");*/
    struct sr_if *ext_if = sr_get_interface(sr,"eth2");

    uint16_t incm_cksum = ip_header->ip_sum;
    ip_header->ip_sum = 0;
    uint16_t calc_cksum = cksum((uint8_t*)ip_header,SIZE_IP);
    ip_header->ip_sum = incm_cksum;
    
    if (calc_cksum != incm_cksum){
        fprintf(stderr,"Bad checksum\n");
    } else if (strcmp(rec_iface->name, "eth1") == 0){ /*INTERNAL*/
        rt = (struct sr_rt*)sr_find_routing_entry_int(sr, ip_header->ip_dst);
        if (tgt_iface != NULL || rt == NULL){
            handleIPPacket(sr, packet, len, rec_iface);
        } else if (ip_header->ip_ttl <= 1){
            fprintf(stderr,"Packet died\n");
            sr_send_icmp(sr, packet, len, 11, 0,0);
        } else if(ip_header->ip_p==6) { /*TCP*/
            fprintf(stderr,"FWD TCP from int\n");
        } else if(ip_header->ip_p==1 ) { /*ICMP*/
            fprintf(stderr,"FWD ICMP from int\n");
            sr_icmp_t8_hdr_t * icmp_header = (sr_icmp_t8_hdr_t*)(packet+SIZE_ETH+SIZE_IP);
            incm_cksum = icmp_header->icmp_sum;
            icmp_header->icmp_sum = 0;
            calc_cksum = cksum((uint8_t*)icmp_header,len-SIZE_ETH-SIZE_IP);
            icmp_header->icmp_sum = incm_cksum;
            if (incm_cksum != calc_cksum){
                fprintf(stderr,"Bad cksum %d != %d\n", incm_cksum, calc_cksum);
            }
            else if (icmp_header->icmp_type == 8 && icmp_header->icmp_code == 0){
                map = sr_nat_lookup_internal(&(sr->nat),
                                            ip_header->ip_src,
                                            icmp_header->icmp_id,
                                            nat_mapping_icmp);
                if (map == NULL){
                    map = sr_nat_insert_mapping(&(sr->nat),
                                            ip_header->ip_src,
                                            icmp_header->icmp_id,
                                            nat_mapping_icmp);
                    map->ip_ext = ip_header->ip_dst;
                }
                icmp_header->icmp_id = map->aux_ext;
                icmp_header->icmp_sum = 0;
                icmp_header->icmp_sum = cksum((uint8_t*)icmp_header,len-SIZE_ETH-SIZE_IP);
                
                ip_header->ip_src = ext_if->ip;
                ip_header->ip_sum = 0;
                ip_header->ip_sum = cksum((uint8_t*)ip_header,SIZE_IP);
                sendIPPacket(sr, packet, len, rt);
            }
        }
    } else if (strcmp(rec_iface->name, "eth2") == 0){ /*EXTERNAL*/
        if (ip_header->ip_ttl <= 1){
            fprintf(stderr,"Packet died\n");
            sr_send_icmp(sr, packet, len, 11, 0,0);
        } else if (tgt_iface == NULL) {
            fprintf(stderr,"NAT Not for us\n");
        } else if(ip_header->ip_p==6) { /*TCP*/
            fprintf(stderr,"FWD TCP from ext\n");
        } else if(ip_header->ip_p==1 ) { /*ICMP*/
            fprintf(stderr,"FWD ICMP from ext\n");
            sr_icmp_t8_hdr_t * icmp_header = (sr_icmp_t8_hdr_t*)(packet+SIZE_ETH+SIZE_IP);
            incm_cksum = icmp_header->icmp_sum;
            icmp_header->icmp_sum = 0;
            calc_cksum = cksum((uint8_t*)icmp_header,len-SIZE_ETH-SIZE_IP);
            icmp_header->icmp_sum = incm_cksum;
            if (incm_cksum != calc_cksum){
                fprintf(stderr,"Bad cksum %d != %d\n", incm_cksum, calc_cksum);
            }
            else if (icmp_header->icmp_type == 0 && icmp_header->icmp_code == 0){
                map = sr_nat_lookup_external(&(sr->nat),
                                             icmp_header->icmp_id,
                                             nat_mapping_icmp);
                if (map != NULL){
                    rt = (struct sr_rt*)sr_find_routing_entry_int(sr, map->ip_int);
                }
                if (rt != NULL){
                    icmp_header->icmp_id = map->aux_int;
                    icmp_header->icmp_sum = 0;
                    icmp_header->icmp_sum = cksum((uint8_t*)icmp_header,len-SIZE_ETH-SIZE_IP);
                    
                    ip_header->ip_dst = map->ip_int;
                    ip_header->ip_sum = 0;
                    ip_header->ip_sum = cksum((uint8_t*)ip_header,SIZE_IP);
                    sendIPPacket(sr, packet, len, rt);
                }
            }
        } 
    }
}/* end natHandleIPPacket */

void sr_init(struct sr_instance* sr, 
             unsigned short mode,
             unsigned int icmp_timeout,
             unsigned int tcp_est_timeout,
             unsigned int tcp_trans_timeout)
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
    sr->mode = mode;
    if (mode == 1){
        fprintf(stderr,"Nat mode enabled!\n");
        sr_nat_init(&(sr->nat), icmp_timeout, tcp_est_timeout, tcp_trans_timeout);
    }
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
    assert(sr);
    assert(packet);
    assert(interface);
    fprintf(stderr,"*** -> Received packet of length %d \n",len);
    print_hdrs(packet,len);
    struct sr_if * iface = sr_get_interface(sr, interface);
    if(len>=34){
        uint8_t* ether_packet = malloc((size_t)(len+28));
        memcpy(ether_packet,packet,len);
        uint16_t packet_type = ethertype(ether_packet);
        if(packet_type == ethertype_arp){
            handleARPpacket(sr, ether_packet, len, iface);
        }else if(packet_type==ethertype_ip){
            if (sr->mode == 0){
                handleIPPacket(sr, ether_packet, len, iface);
            } else if (sr->mode == 1){
                /*handleIPPacket(sr, ether_packet, len, iface);*/
                natHandleIPPacket(sr, ether_packet, len, iface);
            }
        }else{
            fprintf(stderr,"Unsupported Protocol!\n");
        }
        free(ether_packet);
    }
}/* end sr_handlepacket */

void sr_send_icmp(struct sr_instance* sr,
        uint8_t *buf,
        unsigned int len, 
        uint8_t type, 
        uint8_t code,
        uint32_t ip_src){
	fprintf(stderr,"Send ICMP type %d code %d to\n",type, code);

    uint8_t* packet = malloc(len+SIZE_ICMP);
    memset(packet,0,len+SIZE_ICMP);
    memcpy(packet,buf,len);
    sr_ethernet_hdr_t* eth_header = (sr_ethernet_hdr_t*) packet;
    sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(packet+SIZE_ETH);
    sr_icmp_t3_hdr_t* icmp_header = (sr_icmp_t3_hdr_t*)(packet+SIZE_ETH+SIZE_IP);
    struct sr_rt* rt = sr_find_routing_entry_int(sr, ip_header->ip_src);
    
    if(rt){
        fprintf(stderr,"Found route %s\n",rt->interface);
        struct sr_if* iface = sr_get_interface(sr, rt->interface);

        if(type !=0 || code != 0){
            int data_size;
            if (len < SIZE_ETH+ICMP_DATA_SIZE){
                data_size = len-SIZE_ETH;
            } else {
                data_size = ICMP_DATA_SIZE;
            }
            fprintf(stderr,"ICMP data size = %d", data_size);
            memcpy(icmp_header->data,buf+SIZE_ETH,data_size);
            icmp_header->unused = 0;
            icmp_header->next_mtu = 0;
            len = SIZE_ETH+SIZE_IP+SIZE_ICMP;
        }
        icmp_header->icmp_type = type;
        icmp_header->icmp_code = code;
        icmp_header->icmp_sum = 0;
        icmp_header->icmp_sum = cksum((uint8_t*)icmp_header,len-SIZE_ETH-SIZE_IP);
        memcpy(eth_header->ether_shost,iface->addr,6);
        eth_header->ether_type = htons(0x0800);
        if (ip_src == 0){
            ip_src = iface->ip;
        }
        ip_header->ip_hl = 5;
        ip_header->ip_v = 4;
        ip_header->ip_tos = 0;
        ip_header->ip_len = htons(len-SIZE_ETH);
        /*ip_header->ip_id = ip_header->ip_id*/
        ip_header->ip_off = htons(IP_DF);
        ip_header->ip_ttl = INIT_TTL;
        ip_header->ip_p = 1;
        ip_header->ip_sum = 0;
        ip_header->ip_dst = ip_header->ip_src;
        ip_header->ip_src = ip_src;
        ip_header->ip_sum = cksum((uint8_t*)(ip_header),SIZE_IP);
      
        sendIPPacket(sr,packet,len,rt);
    }
}/* end sr_send_icmp */