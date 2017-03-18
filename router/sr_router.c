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
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include <inttypes.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/* TODO: Add constant definitions here... */

/* TODO: Add helper functions here... */

/* See pseudo-code in sr_arpcache.h */
void handle_arpreq(struct sr_instance* sr, struct sr_arpreq *req) {
    /* TODO: Fill this in */
    printf("HANDLE_ARPREQ FUNCTION*******\n\n");
    printf("Print out the contents of the packets:\n");
    print_hdrs(req->packets->buf, req->packets->len);
    
    /*Allocate memory for an ARP structure - Pseudo-code from Haris's presentation*/
    uint8_t* arp = (uint8_t*) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*) arp;
    sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*) (req->packets->buf + sizeof(sr_ethernet_hdr_t));
    assert(arp);
    
    /*Get an instance to the incoming gateway for ARP request*/
    struct sr_if* default_gateway = sr_get_interface(sr, req->packets->iface);
    printf("DEFAULT GATEWAY:\n");
    print_addr_ip_int(ntohl(default_gateway->ip));
    
    /*Store MAC addresses*/
    unsigned char broadcast_ethernet_address[ETHER_ADDR_LEN];
    memcpy(ethernet_header->ether_dhost, broadcast_ethernet_address, ETHER_ADDR_LEN);
    
    /*Source */
    /*add code to deal with arp reply*/
    
    /*Get an instance*/
    
    
    /*IF arp request or arp reply*/
    if (htons(arp_header->ar_op) == arp_op_request) {
        printf("THIS IS AN ARP REQUEST!**\n");
        
        /*Check for correct interface*/
        if (default_gateway != 0) {
            /*Packet is meant for the router interface*/
            
        }
        
    }
    else if (htons(arp_header->ar_op) == arp_op_reply) {
        
    }
    
    /*print_addr_ip_int(ntohl(arp_header->ar_tip));*/
    
    
    /*req->packets->buf = arp;*/
    
    
    
    /*print_hdr_arp(req->packets->buf);*/
    
    
    /*print_hdrs(req->packets->buf, req->packets->len);*/
    /*printf("Address: %s\n\n", req->packets->buf);*/
    /*printf("%d", req->x);*/
    
    /*Perform another sanity check on the packet that is received*/
    /*sr_ethernet_hdr_t *frame = (sr_ethernet_hdr_t*) req->packets->buf;
    sr_arp_hdr_t *arp_header = (sr_arp_hdr_t*) req->packets->buf;*/
    
    /*printf("This is the length of these: %d\n\n", ntohs(arp_header->ar_sip));*/
    
    /*Determine if it is an ARP request or ARP reply*/


}

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr) {
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

    /* TODO: (opt) Add initialization code here */

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
 * by sr_vns_comm.c that means do NOT free either (signified by "lent" comment).  
 * Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */) {

    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);



    /* Example ping
    1. Client sends icmp request to eth1 interface of the router.
    2. Router sends arp request to server to get mac address and receives arp reply.
    3. Router fills in ethernet parameters and send the packet to server. The server
       replies back with icmp reply which router forwards to the client.
    */

    printf("*** -> Received packet of length %u\n\n", len);
    
    /*Print out the header information for all packets received*/
    /*print_hdrs(packet, len);*/
    printf("Size of ethernet header: %lu\n", sizeof(sr_ethernet_hdr_t));
    printf("Size of ARP header: %lu\n", sizeof(sr_arp_hdr_t));
    
    
    
    /*Packet first received will always be an ethernet frame*/
    sr_ethernet_hdr_t *raw_ethernet_frame = (sr_ethernet_hdr_t*) packet;
    /*layer2_sanity_check((uint8_t *) raw_ethernet_frame, len);*/
    /*uint8_t frame_type = htons(raw_ethernet_frame->ether_type);*/

    /*Determine ARP packet or IP packet*/
    switch(ntohs(raw_ethernet_frame->ether_type)) {
        case (ethertype_arp):
            printf("***ARP PACKET***\n");
            
            
            struct sr_arpreq *arp_request = malloc(sizeof(struct sr_arpreq));
            struct sr_packet *pkt = malloc(sizeof(struct sr_packet));
            pkt->buf = packet;
            pkt->iface = interface;
            pkt->len = len;
            
            arp_request->packets = pkt;
            
            handle_arpreq(sr, arp_request);
            break;
        case (ethertype_ip):
            printf("IP PACKETS**");
            break;
        
        default:
            printf("discard faulty packets");
            return;
    }

    /* TODO: Add forwarding logic here */



    /*Print out the interface where the packet came from*/
    /*struct sr_if *incoming_interface = sr_get_interface(sr, interface);*/








}/* -- sr_handlepacket -- */

int layer2_sanity_check(uint8_t* frame, unsigned int length)
{
    int combined_header_length = 0;
    
    /*Calculate the size of ARP Header + Ethernet header*/
    sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t*) frame;
    combined_header_length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    
    if (length >= combined_header_length) {
        printf("Packet is wrong length\n");
        return -1;
    }
    
    /*Add more code to check different packet types*/
    
    
    printf("Packet has been validated");
    return 0;
}

