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
void sr_arp_receive(struct sr_instance* sr, uint8_t* packet, unsigned int length, char* interface) {
    
    printf("I AM RECEIVING AN ARP PACKET***");
    sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*) packet;
    sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
    assert(packet);
    
    /*Get an instance to the incoming gateway for ARP request*/
    struct sr_if* default_gateway = sr_get_interface(sr, interface);
    printf("DEFAULT GATEWAY:\n");
    print_addr_ip_int(ntohl(default_gateway->ip));
    
    /*Print MAC addresses*/
    print_hdrs(packet, length);
    
    /*Check if receiving ARP request or ARP reply */
    switch(ntohs(arp_header->ar_op)) {
        case (arp_op_request):
            printf("**Received an ARP request**");
            
            /*If sr_get_interface function returns anything but 0, it is the correct interface*/
            if (default_gateway != 0) {
                
              
                /*TODO: sr_arpcache_insert*/
                
                /*ARP reply will be sent back*/
                arp_header->ar_op = htons(arp_op_reply);
                
                /*Setting the ethernet header*/
                memcpy(ethernet_header->ether_shost, (uint8_t*) default_gateway->name, ETHER_ADDR_LEN);
                memcpy(ethernet_header->ether_dhost, (uint8_t*) arp_header->ar_sha, ETHER_ADDR_LEN);
                /*Set the ARP header*/
                memcpy(arp_header->ar_sha, default_gateway->addr, ETHER_ADDR_LEN);
                memcpy(arp_header->ar_tha, arp_header->ar_sha, ETHER_ADDR_LEN);
                arp_header->ar_sip = arp_header->ar_tip;
                arp_header->ar_tip = arp_header->ar_sip;
                
                /*Send the ARP reply on the wire*/
                sr_send_packet(sr, packet, length, default_gateway->name);
                  
            }
            
            
        case (arp_op_reply):
            
            
            
            
        default:
            return;
    }
    
            
    
    /*Source */
    /*add code to deal with arp reply*/
    
    /*Get an instance*/
    
    
    /*IF arp request or arp reply*/
    if (htons(arp_header->ar_op) == arp_op_request) {
        printf("THIS IS AN ARP REQUEST!**\n");
        
        /*Check for correct interface*/
        if (default_gateway != 0) {
            /*Packet is meant for the correct router interface*/
            /*Check the ARP cache*/
            
        }
        
    }
    else if (htons(arp_header->ar_op) == arp_op_reply) {
        
    }
    
    
}







void sr_send_arpreq(struct sr_instance* sr, uint32_t target_ip) {
    printf("Sending an ARP request***");
    
    /*Allocate memory for an ARP structure - Pseudo-code from Haris's presentation*/
    uint8_t* arp = (uint8_t*) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*) arp;
    sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*) (arp + sizeof(sr_ethernet_hdr_t));
    assert(arp);
    
    /*Set destination address as broadcast address - FF:FF:FF:FF:FF:FF*/
    /*memcpy(ethernet_header->ether_dhost, 0xffffffffffff, ETHER_ADDR_LEN);*/
    
    /*Loop through all interfaces on the router to send broadcast*/
    struct sr_if* current_interface = sr->if_list;
    
    while (current_interface != NULL) {
        /*Initialize an ARP packet*/
        sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*) (arp + sizeof(sr_ethernet_hdr_t));
        assert(arp);
        
        /*Get MAC address of current interface*/
        memcpy(ethernet_header->ether_shost, current_interface->addr, ETHER_ADDR_LEN);
        
        /*Set the type to an ARP request*/
        ethernet_header->ether_type = htons(ethertype_arp);
        
        /*ARP Header*/
        arp_header->ar_hrd = htons(arp_hrd_ethernet);
        arp_header->ar_pro = htons(ethertype_ip);
        arp_header->ar_hln = ETHER_ADDR_LEN;
        arp_header->ar_pln = 4; /*according to wireshark*/
        arp_header->ar_op = htons(arp_op_request);
        
        /*Set the source MAC address as the current interface of the router*/
        memcpy(arp_header->ar_sha, current_interface->addr, ETHER_ADDR_LEN);
        /*Set the source IP address as the current interface of the router*/
        arp_header->ar_sip = htonl(current_interface->ip);
        
        memset(arp_header->ar_tha, 0, ETHER_ADDR_LEN); /*Set to zero's*/
        arp_header->ar_tip = htonl(target_ip);
        
        /*Send the packet on the wire*/
        sr_send_packet(sr, arp, sizeof(arp), current_interface->name);
        
        /*Proceed to the next request*/
        /*sr_arpreq_destroy(sr->cache, )*/
        current_interface->next++;
    }
    
}


/* See pseudo-code in sr_arpcache.h */
void handle_arpreq(struct sr_instance* sr, struct sr_arpreq *req) {
    /* TODO: Fill this in */
    double time_difference = 0.0;
    
    /*Get an instance of the current time*/
    time_t current_time = time(NULL);
    
    /*Get difference in time between current time and time ARP request sent*/
    time_difference = (time(NULL), req->sent);
    if (time_difference > 1.0) {
        
        if (req->sent >= 5) {
            /*TODO: Send ICMP host unreachable to source address of all packets waiting*/
            sr_arpreq_destroy(&(sr->cache), req);
            
        }
        else {
            /*Initialize and send ARP request*/
            sr_send_arpreq(sr, req->ip);
            req->sent = current_time;
            req->times_sent++;
        }
        
    }


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
            /*
            struct sr_arpreq *arp_request = malloc(sizeof(struct sr_arpreq));
            struct sr_packet *pkt = malloc(sizeof(struct sr_packet));
            pkt->buf = packet;
            pkt->iface = interface;
            pkt->len = len;
            
            arp_request->packets = pkt;
            
            handle_arpreq(sr, arp_request);
            */
            sr_arp_receive(sr, packet, len, interface);
            
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

