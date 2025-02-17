#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "protocol.h"
#include "net_interface.h"

/* TCP connection list */
static tcp_conn_t* tcp_connections = NULL;

/* Create new TCP connection */
tcp_conn_t* create_tcp_connection(void) {
    tcp_conn_t* conn = (tcp_conn_t*)malloc(sizeof(tcp_conn_t));
    if (conn) {
        memset(conn, 0, sizeof(tcp_conn_t));
    }
    return conn;
}

/* Add connection to list */
void add_tcp_connection(tcp_conn_t* conn) {
    if (!conn) return;
    conn->next = tcp_connections;
    tcp_connections = conn;
}

/* Remove connection from list */
void remove_tcp_connection(tcp_conn_t* conn) {
    if (!conn) return;
    
    tcp_conn_t** pp = &tcp_connections;
    while (*pp) {
        if (*pp == conn) {
            *pp = conn->next;
            free(conn);
            return;
        }
        pp = &((*pp)->next);
    }
}

/* Find TCP connection by ports and IP */
tcp_conn_t* find_tcp_connection(uint16_t local_port, uint16_t remote_port, uint32_t remote_ip) {
    tcp_conn_t* conn = tcp_connections;
    while (conn) {
        if (conn->local_port == local_port &&
            conn->remote_port == remote_port &&
            conn->remote_ip == remote_ip) {
            return conn;
        }
        conn = conn->next;
    }
    return NULL;
}

/* Check if port is open */
bool is_port_open(uint16_t port) {
    /* For now, consider port 80 (HTTP) as open */
    return port == 80;
}

/* Generate initial sequence number */
uint32_t generate_initial_seq(void) {
    /* Simple implementation: use random number */
    return rand();
}

/* Send TCP RST packet */
void send_tcp_rst(tcp_header_t* tcp_header) {
    if (!tcp_header) return;

    tcp_header_t rst_header;
    memset(&rst_header, 0, sizeof(tcp_header_t));
    
    /* Swap ports */
    rst_header.src_port = tcp_header->dest_port;
    rst_header.dest_port = tcp_header->src_port;
    
    /* Set sequence and ack numbers */
    rst_header.seq_num = 0;
    rst_header.ack_num = htonl(ntohl(tcp_header->seq_num) + 1);
    
    /* Set RST and ACK flags */
    rst_header.flags = htons(0x14);  /* RST + ACK */
    rst_header.window = 0;
    
    /* Set IP addresses */
    rst_header.dest_ip = tcp_header->src_ip;
    
    /* Calculate checksum */
    rst_header.checksum = calculate_tcp_checksum(&rst_header, NULL, 0);
    
    /* Send the RST packet */
    send_tcp_packet(&rst_header, NULL, 0);
}

/* Calculate TCP checksum */
uint16_t calculate_tcp_checksum(tcp_header_t* tcp_header, uint8_t* payload, size_t length) {
    if (!tcp_header) return 0;

    /* Calculate pseudo header sum */
    uint32_t sum = 0;
    uint32_t src_ip = net_interface_get_instance()->ip_addr;
    uint32_t dest_ip = tcp_header->dest_ip;
    
    /* Add source and destination IP */
    sum += (src_ip >> 16) & 0xFFFF;
    sum += src_ip & 0xFFFF;
    sum += (dest_ip >> 16) & 0xFFFF;
    sum += dest_ip & 0xFFFF;
    
    /* Add protocol and TCP length */
    uint16_t tcp_length = sizeof(tcp_header_t) + length;
    sum += htons(IP_PROTO_TCP);
    sum += htons(tcp_length);
    
    /* Add TCP header fields */
    uint16_t* ptr = (uint16_t*)tcp_header;
    for (size_t i = 0; i < sizeof(tcp_header_t)/2; i++) {
        if (i != 8) {  /* Skip checksum field */
            sum += ntohs(ptr[i]);
        }
    }
    
    /* Add payload if present */
    if (payload && length > 0) {
        ptr = (uint16_t*)payload;
        size_t words = length/2;
        for (size_t i = 0; i < words; i++) {
            sum += ntohs(ptr[i]);
        }
        if (length & 1) {  /* Handle odd byte */
            sum += (payload[length-1] << 8);
        }
    }
    
    /* Fold 32-bit sum into 16 bits */
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~((uint16_t)sum);
}

/* Send TCP packet */
void send_tcp_packet(tcp_header_t* tcp_header, uint8_t* payload, size_t length) {
    /* Validate input parameters */
    if (!tcp_header) return;
    if (length > 0 && !payload) return;
    
    /* Create IP header */
    ip_header_t ip_header;
    memset(&ip_header, 0, sizeof(ip_header_t));
    
    /* Fill IP header fields */
    ip_header.version_ihl = 0x45;  /* IPv4, 5 32-bit words */
    ip_header.total_length = htons(sizeof(ip_header_t) + sizeof(tcp_header_t) + length);
    ip_header.ttl = 64;
    ip_header.protocol = IP_PROTO_TCP;
    ip_header.src_ip = net_interface_get_instance()->ip_addr;
    ip_header.dest_ip = tcp_header->dest_ip;  /* Set destination IP from TCP header */
    
    /* Calculate IP checksum */
    ip_header.header_checksum = calculate_ip_checksum(&ip_header);
    
    /* Create Ethernet frame */
    eth_frame_t eth_frame;
    memset(&eth_frame, 0, sizeof(eth_frame_t));
    
    /* Fill Ethernet frame fields */
    eth_frame.eth_type = htons(ETH_TYPE_IP);
    memcpy(eth_frame.src_mac, net_interface_get_instance()->mac_addr, 6);
    
    /* Resolve destination MAC address using ARP */
    uint8_t dest_mac[6];
    if (!get_mac_address(ip_header.dest_ip, dest_mac)) {
        /* ARP resolution in progress, packet will be sent after resolution */
        return;
    }
    memcpy(eth_frame.dest_mac, dest_mac, 6);
    
    
    /* Calculate total packet size */
    size_t total_size = sizeof(eth_frame_t);
    size_t payload_size = sizeof(ip_header_t) + sizeof(tcp_header_t) + length;
    
    /* Validate packet size */
    if (payload_size > sizeof(eth_frame.payload) || total_size > MAX_PACKET_SIZE) {
        printf("Error: Packet size exceeds maximum allowed size (payload: %zu, max: %zu)\n",
               payload_size, sizeof(eth_frame.payload));
        return;
    }
    
    /* Ensure we have enough space for headers */
    if (sizeof(ip_header_t) + sizeof(tcp_header_t) > sizeof(eth_frame.payload)) {
        printf("Error: Not enough space for protocol headers\n");
        return;
    }
    
    /* Assemble packet */
    memcpy(eth_frame.payload, &ip_header, sizeof(ip_header_t));
    memcpy(eth_frame.payload + sizeof(ip_header_t), tcp_header, sizeof(tcp_header_t));
    if (payload && length > 0) {
        memcpy(eth_frame.payload + sizeof(ip_header_t) + sizeof(tcp_header_t), payload, length);
    }
    
    /* Send packet */
    net_interface_send_packet(net_interface_get_instance(),
                            (uint8_t*)&eth_frame,
                            total_size);
}