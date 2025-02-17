#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "protocol.h"
#include "net_interface.h"

/* Calculate IP header checksum */
uint16_t calculate_ip_checksum(ip_header_t* ip_header) {
    if (!ip_header) return 0;
    
    uint32_t sum = 0;
    uint16_t* ptr = (uint16_t*)ip_header;
    
    /* Save original checksum and set to 0 for calculation */
    uint16_t orig_checksum = ip_header->header_checksum;
    ip_header->header_checksum = 0;
    
    /* Sum up all 16-bit words */
    for (size_t i = 0; i < sizeof(ip_header_t)/2; i++) {
        sum += ntohs(ptr[i]);
    }
    
    /* Restore original checksum */
    ip_header->header_checksum = orig_checksum;
    
    /* Fold 32-bit sum into 16 bits */
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~((uint16_t)sum);
}

/* Handle TCP payload data */
int handle_tcp_payload(tcp_conn_t* conn, uint8_t* payload, size_t length) {
    if (!conn || !payload || length == 0) {
        return -1;
    }
    
    /* For now, just print the payload data */
    printf("TCP payload received for connection (local_port: %d, remote_port: %d):\n",
           conn->local_port, conn->remote_port);
    
    /* Print payload as hex dump */
    for (size_t i = 0; i < length; i++) {
        printf("%02x ", payload[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
    
    return 0;
}