#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "protocol.h"
#include "net_interface.h"

#define ARP_CACHE_SIZE 256
#define ARP_CACHE_TIMEOUT 300  /* 5 minutes */
#define ARP_REQUEST 1
#define ARP_REPLY 2

/* ARP cache entry structure */
typedef struct {
    uint32_t ip_addr;
    uint8_t mac_addr[6];
    time_t timestamp;
    bool valid;
} arp_cache_entry_t;

/* ARP cache table */
static arp_cache_entry_t arp_cache[ARP_CACHE_SIZE];

/* Initialize ARP cache */
void init_arp_cache(void) {
    memset(arp_cache, 0, sizeof(arp_cache));
}

/* Find entry in ARP cache */
static arp_cache_entry_t* find_arp_entry(uint32_t ip_addr) {
    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (arp_cache[i].valid && arp_cache[i].ip_addr == ip_addr) {
            /* Check if entry has expired */
            if (time(NULL) - arp_cache[i].timestamp > ARP_CACHE_TIMEOUT) {
                arp_cache[i].valid = false;
                return NULL;
            }
            return &arp_cache[i];
        }
    }
    return NULL;
}

/* Add or update entry in ARP cache */
static void update_arp_cache(uint32_t ip_addr, uint8_t* mac_addr) {
    arp_cache_entry_t* entry = find_arp_entry(ip_addr);
    
    if (entry) {
        /* Update existing entry */
        memcpy(entry->mac_addr, mac_addr, 6);
        entry->timestamp = time(NULL);
        return;
    }
    
    /* Find empty slot */
    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (!arp_cache[i].valid) {
            arp_cache[i].ip_addr = ip_addr;
            memcpy(arp_cache[i].mac_addr, mac_addr, 6);
            arp_cache[i].timestamp = time(NULL);
            arp_cache[i].valid = true;
            return;
        }
    }
    
    /* If cache is full, replace oldest entry */
    time_t oldest_time = time(NULL);
    int oldest_index = 0;
    
    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (arp_cache[i].timestamp < oldest_time) {
            oldest_time = arp_cache[i].timestamp;
            oldest_index = i;
        }
    }
    
    arp_cache[oldest_index].ip_addr = ip_addr;
    memcpy(arp_cache[oldest_index].mac_addr, mac_addr, 6);
    arp_cache[oldest_index].timestamp = time(NULL);
    arp_cache[oldest_index].valid = true;
}

/* Send ARP request */
void send_arp_request(uint32_t target_ip) {
    eth_frame_t frame;
    arp_packet_t* arp;
    
    /* Prepare Ethernet frame */
    memset(&frame, 0xFF, sizeof(eth_frame_t));  /* Broadcast */
    memcpy(frame.src_mac, net_interface_get_instance()->mac_addr, 6);
    frame.eth_type = htons(ETH_TYPE_ARP);
    
    /* Prepare ARP packet */
    arp = (arp_packet_t*)frame.payload;
    arp->hw_type = htons(1);  /* Ethernet */
    arp->protocol_type = htons(ETH_TYPE_IP);
    arp->hw_len = 6;
    arp->protocol_len = 4;
    arp->operation = htons(ARP_REQUEST);
    
    /* Set sender details */
    memcpy(arp->sender_mac, net_interface_get_instance()->mac_addr, 6);
    arp->sender_ip = net_interface_get_instance()->ip_addr;
    
    /* Set target details */
    memset(arp->target_mac, 0, 6);
    arp->target_ip = target_ip;
    
    /* Send frame */
    net_interface_send_packet(net_interface_get_instance(),
                            (uint8_t*)&frame,
                            sizeof(eth_frame_t));
}

/* Handle incoming ARP packet */
void handle_arp_packet(eth_frame_t* frame) {
    arp_packet_t* arp = (arp_packet_t*)frame->payload;
    
    /* Update ARP cache with sender's information */
    update_arp_cache(arp->sender_ip, arp->sender_mac);
    
    /* If this is an ARP request for our IP, send reply */
    if (ntohs(arp->operation) == ARP_REQUEST &&
        arp->target_ip == net_interface_get_instance()->ip_addr) {
        
        /* Swap addresses */
        memcpy(frame->dest_mac, frame->src_mac, 6);
        memcpy(frame->src_mac, net_interface_get_instance()->mac_addr, 6);
        
        /* Update ARP packet */
        arp->operation = htons(ARP_REPLY);
        memcpy(arp->target_mac, frame->dest_mac, 6);
        arp->target_ip = arp->sender_ip;
        memcpy(arp->sender_mac, net_interface_get_instance()->mac_addr, 6);
        arp->sender_ip = net_interface_get_instance()->ip_addr;
        
        /* Send reply */
        net_interface_send_packet(net_interface_get_instance(),
                                (uint8_t*)frame,
                                sizeof(eth_frame_t));
    }
}

/* Get MAC address for IP */
bool get_mac_address(uint32_t ip_addr, uint8_t* mac_addr) {
    arp_cache_entry_t* entry = find_arp_entry(ip_addr);
    
    if (entry) {
        memcpy(mac_addr, entry->mac_addr, 6);
        return true;
    }
    
    /* If not in cache, send ARP request */
    send_arp_request(ip_addr);
    return false;
}