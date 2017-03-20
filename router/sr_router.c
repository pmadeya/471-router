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

void sr_icmp_receive(struct sr_instance* sr, uint8_t* packet, unsigned int length, char* interface) {
    printf("***I AM RECEIVING AN ICMP PACKET\n***");
    /*layer2_sanity_check(packet, length);*/
    
    /*Get an instance of the current interface */
    /*struct sr_if* default_gateway = sr_get_interface(sr, interface);*/
    printf("\nGW:");
    /*print_addr_ip_int(ntohl(default_gateway->ip));*/
    

    
    /*Make an IP header*/
    sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
    print_hdrs(packet, length);
    
   
    
    /*Check if the incoming ICMP packet is for the router itself (interface)*/
    /*Get the list of the available gateways*/
    struct sr_if* available_gateways = sr->if_list;
    
    /*Cycle through gateway list on the router*/
    while (available_gateways != NULL) {
        if (available_gateways->ip == ip_header->ip_dst) {
            /*The destination is the router interface itself */
            break;
        }
        
        available_gateways = available_gateways->next;
    }
    
    
    if (available_gateways != NULL) {
        sr_send_icmp_reply_from_router(sr, packet, length, interface, available_gateways);
    }
    else {
        /*Calls forwarding function*/\
        free(available_gateways);
        printf("skldjflksdjflksdjfkljsdlkfjlksdjf");
        sr_forward_icmp_packet(sr, packet, length, interface);
    }

}

void sr_send_icmp_reply_from_router(struct sr_instance* sr, uint8_t* packet, unsigned int length, char* incoming_interface, struct sr_if* gateway) {
    /*Create ICMP header*/
    sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*) packet;
    sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_hdr_t* icmp_header = (sr_icmp_hdr_t*) (packet + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
    
    /*Get the name of the current interface*/
            
            
    /*Check if received an ICMP request*/
    if (icmp_header->icmp_type == 8 && icmp_header->icmp_code == 0) {
        
        struct sr_if* current_interface = sr_get_interface(sr, incoming_interface);
        
        /*Setting the ethernet header fields*/
        memcpy(ethernet_header->ether_dhost, ethernet_header->ether_shost, ETHER_ADDR_LEN);
        memcpy(ethernet_header->ether_shost, current_interface->addr, ETHER_ADDR_LEN);
        
        /*Setting the ICMP header fields*/
        icmp_header->icmp_sum = 0; /*Reply*/
        icmp_header->icmp_type = 0;
        icmp_header->icmp_code = 0;
        
        /*Recompute the checksum*/
        icmp_header->icmp_sum = cksum(icmp_header, sizeof(sr_icmp_t3_hdr_t));
        
        /*Setting the IP header fields*/
        ip_header->ip_dst = ip_header->ip_src;
        ip_header->ip_src = current_interface->ip;
        ip_header->ip_sum = 0;
        ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
        
        /*Send the reply over the wire*/
        sr_send_packet(sr, packet, length, current_interface->name);
        
    }
    
    printf("Change ICMP packet to reply and send it back to the source host");
    
    
    
    
}

/*If the destination is not destined for one of the router interfaces,
 this function will be called; It will forward the packet based on longest
 prefix matching to the end host*/
void sr_forward_icmp_packet(struct sr_instance* sr, uint8_t* packet, unsigned int length, char* interface) {
    printf("Destination host is not one of the router interfaces\n");
    printf("Must forward packet!**\n");
    
    sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*) packet;
    sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
    
    
    
    printf("RIGHT HERE!!!!");
    
    /*Check the ARP table in the router to look for destination IP-MAC mapping*/
    struct sr_arpentry* entry = sr_arpcache_lookup(&(sr->cache), ip_header->ip_dst);
    
    printf("PERFECT!!");
    
    /*Get the new routing table*/
    struct sr_if* sending_interface = sr_get_interface_prefix_matching(sr, ip_header->ip_dst);

    /*Gives us the interface we need to forward on*/
    /*struct sr_if* sending_interface = sr_get_interface(sr, (const char*) (new_routing_table->interface));*/
    printf("Sending interface:*******"); 
    print_addr_ip_int(ntohl(sending_interface->ip));
    
        
    /*If mapping exists in the table*/
    if (entry != NULL) {
        /*Find the correct gateway to get the interface that can actually forward
        on the correct interface (subnet)
        */
        /*Set the new ethernet values*/
        printf("INSIDE THE ENTRY IF STATMENT");
        memcpy(ethernet_header->ether_dhost, entry->mac, ETHER_ADDR_LEN);
        memcpy(ethernet_header->ether_shost, sending_interface->addr, ETHER_ADDR_LEN);
        
        /*Send the packet on the wire*/
        print_hdrs(packet, length);
        sr_send_packet(sr, packet, length, sending_interface->name);
           
        free(entry);
        return;
    }
    else {
        printf("HANDLE ARP QUEU!!!!");
        struct sr_arpreq* new_arp_request = sr_arpcache_queuereq(&(sr->cache), ip_header->ip_dst, packet, length, sending_interface->name);
        handle_arpreq(sr, new_arp_request);
    }
}

struct sr_if* sr_get_interface_prefix_matching(struct sr_instance* sr, uint32_t target_ip) {
    printf("We are the beginning of the prefix match function");
    
    struct sr_rt* new_routing_table = sr->routing_table;
    
    while (new_routing_table) {
        
        uint32_t maskIP = new_routing_table->mask.s_addr & target_ip;
        if (new_routing_table->dest.s_addr == maskIP) {
            
            return sr_get_interface(sr, new_routing_table->interface);
        }
        
        new_routing_table = new_routing_table->next;
        
    }
    
    return NULL;

}


/* TODO: Add helper functions here... */
void sr_arp_receive(struct sr_instance* sr, uint8_t* packet, unsigned int length, char* interface) {
    
    printf("I AM RECEIVING AN ARP PACKET***");
    printf("%s", interface);
    sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*) packet;
    sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
    assert(packet);
    
    /*Get an instance to the incoming gateway for ARP request*/
    /*Incoming */
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
                /*Always insert the arp request that we are processing*/
                sr_arpcache_insert(&(sr->cache), arp_header->ar_sha, arp_header->ar_sip);
                
                /*ARP reply will be sent back*/
                arp_header->ar_op = htons(arp_op_reply);
                
                /*Setting the ethernet header*/
                /*Set the source hardware address as the ethernet destination packet FIRST!*/
                memcpy(ethernet_header->ether_dhost, arp_header->ar_sha, ETHER_ADDR_LEN);
                memcpy(ethernet_header->ether_shost, default_gateway->addr, ETHER_ADDR_LEN);
                
                /*Set the ARP header*/
                memcpy(arp_header->ar_tha, arp_header->ar_sha, ETHER_ADDR_LEN);
                memcpy(arp_header->ar_sha, default_gateway->addr, ETHER_ADDR_LEN);
                
                /*Set the IP addresses*/
                arp_header->ar_tip = arp_header->ar_sip;
                arp_header->ar_sip = default_gateway->ip;
                
                printf("PACKET DETAILS\n");
                print_hdrs(packet, length);
                
                /*Send the ARP reply on the wire*/
                sr_send_packet(sr, packet, length, default_gateway->name);
                  
            }
            
         break;   
        case (arp_op_reply):
            printf("I FINALLY GET TO THE ARP REPLY CASE");
            
            struct sr_arpreq* arp_queue = sr_arpcache_insert(&(sr->cache), arp_header->ar_sha, arp_header->ar_sip);
            struct sr_packet* packet_to_send = arp_queue->packets;
            
            while (packet_to_send != NULL) {
                sr_forward_icmp_packet(sr, packet_to_send->buf, packet_to_send->len, interface);
                packet_to_send = packet_to_send->next;
                
            }
            
            sr_arpreq_destroy(&(sr->cache), arp_queue);
            
            
            
            
            break;
            
            
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

uint8_t* broadcast_address() {
    uint8_t* broadcast_ethernet_address  = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
   
    /*Fill with all */
    int i = 0; /*Must declare outside of initializer list, only in C99/C11*/ 
    for (; i < ETHER_ADDR_LEN; i++) {
        broadcast_ethernet_address[i] = 255;
    }
    return broadcast_ethernet_address;
}


void sr_send_arpreq(struct sr_instance* sr, uint32_t target_ip) {
    printf("Sending an ARP request***");
    
    /*Allocate memory for an ARP structure - Pseudo-code from Haris's presentation*/
    uint8_t* arp = (uint8_t*) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*) arp;
    sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*) (arp + sizeof(sr_ethernet_hdr_t));
    assert(arp);
    
    
    /*Length of arp packet*/
    unsigned int length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    
    /*Set destination address as broadcast address - FF:FF:FF:FF:FF:FF*/
    memcpy(ethernet_header->ether_dhost, broadcast_address(), ETHER_ADDR_LEN);
    printf("\nETHERNET BROADCAST ADDRESS: %d\n", (*broadcast_address(255)));
    
    /*Loop through all interfaces on the router to send broadcast*/
    struct sr_if* current_interface = sr_get_interface_prefix_matching(sr, target_ip);
    
    if (current_interface != NULL) {
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
        arp_header->ar_sip = current_interface->ip;
        
        memset(arp_header->ar_tha, 0, ETHER_ADDR_LEN); /*Set to zero's*/
        arp_header->ar_tip = target_ip;
        
        /*Send the packet on the wire*/
        sr_send_packet(sr, arp, length, current_interface->name);
        print_hdrs(arp, length);
        
        /*Proceed to the next request*/
        /*sr_arpreq_destroy(sr->cache, )*/
       
    }
    
}


/* See pseudo-code in sr_arpcache.h */
void handle_arpreq(struct sr_instance* sr, struct sr_arpreq *req) {
    /* TODO: Fill this in */
    printf("QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ");
     sr_send_arpreq(sr, req->ip);
    double time_difference = 0.0;
    
    /*Get an instance of the current time*/
    time_t current_time = time(NULL);
    
    /*Get difference in time between current time and time ARP request sent*/
    time_difference = (time(NULL), req->sent);
    if (time_difference > 1.0) {
        
        if (req->sent >= 5) {
            /*TODO: Send ICMP host unreachable to source address of all packets waiting*/
            /*sr_arpreq_destroy(&(sr->cache), req);*/
            printf("hBD");
            
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
    print_hdrs(packet, len);
    
    
    /*Packet first received will always be an ethernet frame*/
    sr_ethernet_hdr_t *raw_ethernet_frame = (sr_ethernet_hdr_t*) packet;
    /*layer2_sanity_check((uint8_t *) raw_ethernet_frame, len);*/
    /*uint8_t frame_type = htons(raw_ethernet_frame->ether_type);*/

    /*Determine ARP packet or IP packet*/
    switch(ntohs(raw_ethernet_frame->ether_type)) {
        case (ethertype_arp):
            printf("***ARP PACKET***\n");
            
            sr_arp_receive(sr, packet, len, interface);
            break;
        case (ethertype_ip):
            printf("IP PACKETS\n\n**");
            sr_icmp_receive(sr, packet, len, interface);
            
            
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

