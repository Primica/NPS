#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "protocol.h"
#include "net_interface.h"

#define PACKET_BUFFER_SIZE 1518  /* Maximum Ethernet frame size */

/* Checksum calculation */
uint16_t calculate_checksum(void* data, int len) {
    uint16_t* buf = (uint16_t*)data;
    uint32_t sum = 0;
    
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    
    if (len > 0) {
        sum += *(uint8_t*)buf;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

/* Process Ethernet frame */
void process_ethernet_frame(eth_frame_t* frame, size_t length) {
    /* Check if frame is for us */
    if (memcmp(frame->dest_mac, net_interface_get_instance()->mac_addr, 6) != 0 &&
        memcmp(frame->dest_mac, (uint8_t[6]){0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 6) != 0) {
        return;
    }

    switch(frame->eth_type) {
        case ETH_TYPE_IP:
            process_ip_packet(frame,
                            (ip_header_t*)frame->payload, 
                            frame->payload + sizeof(ip_header_t),
                            length - sizeof(ip_header_t));
            break;
        case ETH_TYPE_ARP:
            process_arp_packet((arp_packet_t*)frame->payload);
            break;
        default:
            printf("Unsupported Ethernet type: 0x%04x\n", frame->eth_type);
    }
}

/* Process UDP datagram */
void process_udp_datagram(udp_header_t* udp_header, uint8_t* payload, size_t length) {
    /* Basic validation */
    if (!udp_header || !payload || length > 1500) {
        printf("Invalid UDP datagram parameters\n");
        return;
    }

    /* Process UDP payload based on port */
    uint16_t dest_port = ntohs(udp_header->dest_port);
    uint16_t src_port = ntohs(udp_header->src_port);
    
    /* Handle DNS queries (port 53) */
    if (dest_port == 53) {
        uint8_t response[1500];  /* Maximum response size */
        size_t response_length = 0;
        
        process_dns_query(payload, length, response, &response_length);
        
        if (response_length > 0 && response_length <= 1500) {
            /* Create UDP response header */
            udp_header_t udp_response;
            udp_response.src_port = htons(53);
            udp_response.dest_port = htons(src_port);
            udp_response.length = htons(sizeof(udp_header_t) + response_length);
            udp_response.checksum = 0;  /* Calculate checksum */
            
            /* Create IP header */
            ip_header_t ip_header;
            memset(&ip_header, 0, sizeof(ip_header_t));
            ip_header.version_ihl = 0x45;
            ip_header.total_length = htons(sizeof(ip_header_t) + sizeof(udp_header_t) + response_length);
            ip_header.ttl = 64;
            ip_header.protocol = IP_PROTO_UDP;
            ip_header.src_ip = net_interface_get_instance()->ip_addr;
            ip_header.dest_ip = ip_header.src_ip;  /* Use source IP from request */
            ip_header.header_checksum = calculate_checksum(&ip_header, sizeof(ip_header_t));
            
            /* Create Ethernet frame */
            eth_frame_t eth_frame;
            memset(&eth_frame, 0, sizeof(eth_frame_t));
            eth_frame.eth_type = htons(ETH_TYPE_IP);
            memcpy(eth_frame.dest_mac, eth_frame.src_mac, 6);  /* Use source MAC from request */
            memcpy(eth_frame.src_mac, net_interface_get_instance()->mac_addr, 6);
            
            /* Assemble packet */
            memcpy(eth_frame.payload, &ip_header, sizeof(ip_header_t));
            memcpy(eth_frame.payload + sizeof(ip_header_t), &udp_response, sizeof(udp_header_t));
            memcpy(eth_frame.payload + sizeof(ip_header_t) + sizeof(udp_header_t), response, response_length);
            
            /* Send packet */
            net_interface_send_packet(net_interface_get_instance(),
                                    (uint8_t*)&eth_frame,
                                    sizeof(eth_frame_t) + sizeof(ip_header_t) + sizeof(udp_header_t) + response_length);
            printf("DNS response sent: %zu bytes\n", response_length);
        } else {
            printf("Invalid DNS response size: %zu\n", response_length);
        }
    } else {
        printf("UDP datagram received: %zu bytes for port %d\n", length, dest_port);
    }
}

/* Process IP packet */
void process_ip_packet(eth_frame_t* eth_frame, ip_header_t* ip_header, uint8_t* payload, size_t length) {
    /* Verify checksum */
    uint16_t orig_checksum = ip_header->header_checksum;
    ip_header->header_checksum = 0;
    uint16_t calc_checksum = calculate_checksum(ip_header, sizeof(ip_header_t));
    
    if (orig_checksum != calc_checksum) {
        printf("IP checksum mismatch\n");
        return;
    }

    /* Check if packet is for us */
    if (ip_header->dest_ip != net_interface_get_instance()->ip_addr) {
        return;
    }

    switch(ip_header->protocol) {
        case IP_PROTO_TCP:
            process_tcp_segment((tcp_header_t*)payload,
                              payload + sizeof(tcp_header_t),
                              length - sizeof(tcp_header_t));
            break;
        case IP_PROTO_ICMP:
            {
                icmp_header_t* icmp = (icmp_header_t*)payload;
                
                /* Verify ICMP checksum */
                uint16_t orig_checksum = icmp->checksum;
                icmp->checksum = 0;
                uint16_t calc_checksum = calculate_checksum(icmp, sizeof(icmp_header_t));
                
                if (orig_checksum != calc_checksum) {
                    printf("ICMP checksum mismatch\n");
                    return;
                }
                
                /* Handle ICMP echo request */
                if (icmp->type == 8 && icmp->code == 0) {  /* Echo Request */
                    printf("ICMP Echo Request received\n");
                    
                    /* Calculate total ICMP data length with proper bounds checking */
                    size_t icmp_data_length = length - sizeof(icmp_header_t);
                    if (icmp_data_length > 1500 - sizeof(icmp_header_t)) {  /* Corrected size check */
                        printf("ICMP data too large\n");
                        return;
                    }
                
                    /* Prepare echo reply */
                    icmp_header_t reply;
                    memset(&reply, 0, sizeof(icmp_header_t));
                    
                    /* Copy header fields */
                    reply.identifier = icmp->identifier;
                    reply.sequence = icmp->sequence;
                    
                    /* Set ICMP type to Echo Reply */
                    reply.type = 0;  /* Echo Reply */
                    reply.code = 0;
                    reply.checksum = 0;
                    
                    /* Copy ICMP data from request with size validation */
                    if (icmp_data_length > 0) {
                        memcpy(reply.data, icmp->data, icmp_data_length);
                    }
                
                    /* Calculate checksum for reply including data */
                    reply.checksum = calculate_checksum(&reply, sizeof(icmp_header_t) + icmp_data_length);
                    
                    /* Create IP header for reply */
                    ip_header_t ip_reply;
                    memset(&ip_reply, 0, sizeof(ip_header_t));
                    ip_reply.version_ihl = 0x45;  /* IPv4, 5 32-bit words */
                    ip_reply.dest_ip = ip_header->src_ip;
                    ip_reply.src_ip = net_interface_get_instance()->ip_addr;
                    ip_reply.total_length = htons(sizeof(ip_header_t) + sizeof(icmp_header_t) + icmp_data_length);
                    ip_reply.ttl = 64;
                    ip_reply.protocol = IP_PROTO_ICMP;
                    ip_reply.header_checksum = calculate_checksum(&ip_reply, sizeof(ip_header_t));
                    
                    /* Create Ethernet frame */
                    eth_frame_t eth_reply;
                    memset(&eth_reply, 0, sizeof(eth_frame_t));
                    memcpy(eth_reply.dest_mac, eth_frame->src_mac, 6);
                    memcpy(eth_reply.src_mac, net_interface_get_instance()->mac_addr, 6);
                    eth_reply.eth_type = htons(ETH_TYPE_IP);
                    
                    /* Assemble packet with proper bounds checking */
                    memcpy(eth_reply.payload, &ip_reply, sizeof(ip_header_t));
                    memcpy(eth_reply.payload + sizeof(ip_header_t), &reply, sizeof(icmp_header_t) + icmp_data_length);
                    
                    /* Send packet */
                    net_interface_send_packet(net_interface_get_instance(),
                                            (uint8_t*)&eth_reply,
                                            sizeof(eth_frame_t) + sizeof(ip_header_t) + sizeof(icmp_header_t) + icmp_data_length);
                    printf("ICMP Echo Reply sent\n");
                } else {
                    printf("Unsupported ICMP type: %d\n", icmp->type);
                }
            }
            break;
        case IP_PROTO_UDP:
            {
                udp_header_t* udp = (udp_header_t*)payload;
                
                /* Verify UDP checksum */
                uint16_t orig_checksum = udp->checksum;
                udp->checksum = 0;
                uint16_t calc_checksum = calculate_checksum(udp, sizeof(udp_header_t));
                
                if (orig_checksum != calc_checksum) {
                    printf("UDP checksum mismatch\n");
                    return;
                }
                
                /* Process UDP datagram */
                process_udp_datagram(udp, 
                                   payload + sizeof(udp_header_t),
                                   length - sizeof(udp_header_t));
            }
            break;
        default:
            printf("Unsupported IP protocol: %d\n", ip_header->protocol);
    }
}

/* Process ARP packet */
void process_arp_packet(arp_packet_t* arp_packet) {
    /* Basic validation */
    if (!arp_packet) {
        printf("Invalid ARP packet\n");
        return;
    }

    /* Check if ARP request is for our IP */
    if (ntohs(arp_packet->operation) == 1 && /* ARP request */
        arp_packet->target_ip == net_interface_get_instance()->ip_addr) {
        /* Prepare ARP reply */
        arp_packet_t arp_reply;
        memcpy(&arp_reply, arp_packet, sizeof(arp_packet_t));
        
        /* Fill in the reply fields */
        arp_reply.operation = htons(2); /* ARP reply */
        memcpy(arp_reply.target_mac, arp_packet->sender_mac, 6);
        arp_reply.target_ip = arp_packet->sender_ip;
        memcpy(arp_reply.sender_mac, net_interface_get_instance()->mac_addr, 6);
        arp_reply.sender_ip = net_interface_get_instance()->ip_addr;
        
        /* Create Ethernet frame for reply */
        eth_frame_t eth_reply;
        memcpy(eth_reply.dest_mac, arp_packet->sender_mac, 6);
        memcpy(eth_reply.src_mac, net_interface_get_instance()->mac_addr, 6);
        eth_reply.eth_type = htons(ETH_TYPE_ARP);
        
        /* Copy ARP reply to frame payload */
        memcpy(eth_reply.payload, &arp_reply, sizeof(arp_packet_t));
        
        /* Send ARP reply */
        net_interface_send_packet(net_interface_get_instance(),
                                (uint8_t*)&eth_reply,
                                sizeof(eth_frame_t));
        printf("ARP reply sent to %02x:%02x:%02x:%02x:%02x:%02x\n",
               arp_packet->sender_mac[0], arp_packet->sender_mac[1],
               arp_packet->sender_mac[2], arp_packet->sender_mac[3],
               arp_packet->sender_mac[4], arp_packet->sender_mac[5]);
    }
}

/* Process TCP segment */
void process_tcp_segment(tcp_header_t* tcp_header, uint8_t* payload, size_t length) {
    if (!tcp_header || length > 1500) {
        printf("Invalid TCP segment parameters\n");
        return;
    }

    /* Process TCP flags and header fields */
    uint16_t flags = ntohs(tcp_header->flags);
    uint16_t src_port = ntohs(tcp_header->src_port);
    uint16_t dest_port = ntohs(tcp_header->dest_port);
    uint8_t data_offset = (flags >> 12) & 0x0F;  /* Data offset is in the upper 4 bits of flags field */

    /* Validate TCP header size */
    if (data_offset < 5 || data_offset * 4 > length) {  /* Check both minimum size and against total length */
        printf("Invalid TCP header size\n");
        return;
    }

    printf("TCP segment received: src_port=%d, dest_port=%d, flags=0x%04x\n",
           src_port, dest_port, flags);

    if (flags & 0x02) { /* SYN flag */
        printf("TCP SYN received on port %d\n", dest_port);
        /* Check if port is open in our services */
        if (!is_port_open(dest_port)) {
            /* Send RST packet if port is closed */
            send_tcp_rst(tcp_header);
            return;
        }

        /* Create new TCP connection structure */
        tcp_conn_t* new_conn = create_tcp_connection();
        if (!new_conn) {
            printf("Failed to create TCP connection\n");
            return;
        }

        /* Initialize connection state */
        new_conn->state = TCP_STATE_SYN_RECEIVED;
        new_conn->local_port = dest_port;
        new_conn->remote_port = src_port;
        new_conn->seq_num = generate_initial_seq();
        new_conn->ack_num = ntohl(tcp_header->seq_num) + 1;

        /* Add to active connections list */
        add_tcp_connection(new_conn);

        /* Prepare and send SYN-ACK response */
        tcp_header_t syn_ack;
        memset(&syn_ack, 0, sizeof(tcp_header_t));
        
        syn_ack.src_port = htons(dest_port);
        syn_ack.dest_port = htons(src_port);
        syn_ack.seq_num = htonl(new_conn->seq_num);
        syn_ack.ack_num = htonl(new_conn->ack_num);
        syn_ack.flags |= (5 << 12);  /* Set data offset to 5 32-bit words in flags field */
        syn_ack.flags = htons(0x12);   /* SYN + ACK flags */
        syn_ack.window = htons(TCP_WINDOW_SIZE);
        syn_ack.urgent_ptr = 0;
        
        /* Calculate and set checksum */
        syn_ack.checksum = calculate_tcp_checksum(&syn_ack, NULL, 0);
        
        /* Send the SYN-ACK packet */
        send_tcp_packet(&syn_ack, NULL, 0);
    }
    
    if (flags & 0x01) { /* FIN flag */
        printf("TCP FIN received on port %d\n", dest_port);
/* Find the associated connection */
tcp_conn_t* conn = find_tcp_connection(src_port, dest_port, tcp_header->seq_num);
if (!conn) {
    printf("No connection found for FIN\n");
    return;
}

/* Update connection state */
switch (conn->state) {
    case TCP_STATE_ESTABLISHED:
        conn->state = TCP_STATE_CLOSE_WAIT;
        
        /* Send ACK for the FIN */
        tcp_header_t ack;
        memset(&ack, 0, sizeof(tcp_header_t));
        
        ack.src_port = htons(dest_port);
        ack.dest_port = htons(src_port);
        ack.seq_num = htonl(conn->seq_num);
        ack.ack_num = htonl(conn->ack_num + 1);
        ack.flags = htons(0x10);  /* ACK flag */
        ack.flags |= (5 << 12);   /* Data offset */
        ack.window = htons(TCP_WINDOW_SIZE);
        ack.checksum = calculate_tcp_checksum(&ack, NULL, 0);
        
        send_tcp_packet(&ack, NULL, 0);
        
        /* Send FIN-ACK */
        tcp_header_t fin_ack;
        memset(&fin_ack, 0, sizeof(tcp_header_t));
        
        fin_ack.src_port = htons(dest_port);
        fin_ack.dest_port = htons(src_port);
        fin_ack.seq_num = htonl(conn->seq_num + 1);
        fin_ack.ack_num = htonl(conn->ack_num + 1);
        fin_ack.flags = htons(0x11);  /* FIN + ACK flags */
        fin_ack.flags |= (5 << 12);   /* Data offset */
        fin_ack.window = htons(TCP_WINDOW_SIZE);
        fin_ack.checksum = calculate_tcp_checksum(&fin_ack, NULL, 0);
        
        send_tcp_packet(&fin_ack, NULL, 0);
        
        conn->state = TCP_STATE_LAST_ACK;
        break;
        
    case TCP_STATE_FIN_WAIT_1:
        conn->state = TCP_STATE_CLOSING;
        break;
        
    case TCP_STATE_FIN_WAIT_2:
        conn->state = TCP_STATE_TIME_WAIT;
        /* Start TIME_WAIT timer */
        start_time_wait_timer(conn);
        break;
        
    default:
        printf("Unexpected FIN in state %d\n", conn->state);
        break;
}
    }

    /* Process TCP data */
    if (length > 0) {
        printf("TCP data received: %zu bytes for port %d\n", length, dest_port);
/* Find the associated connection */
tcp_conn_t* conn = find_tcp_connection(src_port, dest_port, tcp_header->seq_num);
if (!conn) {
    printf("No connection found for data segment\n");
    return;
}

/* Validate sequence number */
uint32_t expected_seq = ntohl(tcp_header->seq_num);
if (expected_seq != conn->ack_num) {
    printf("Out of order segment received\n");
    /* Send duplicate ACK */
    tcp_header_t dup_ack;
    memset(&dup_ack, 0, sizeof(tcp_header_t));
    dup_ack.src_port = htons(dest_port);
    dup_ack.dest_port = htons(src_port);
    dup_ack.seq_num = htonl(conn->seq_num);
    dup_ack.ack_num = htonl(conn->ack_num);
    dup_ack.flags = htons(0x10);  /* ACK flag */
    dup_ack.flags |= (5 << 12);   /* Data offset */
    dup_ack.window = htons(TCP_WINDOW_SIZE);
    dup_ack.checksum = calculate_tcp_checksum(&dup_ack, NULL, 0);
    send_tcp_packet(&dup_ack, NULL, 0);
    return;
}

/* Process the payload data */
if (handle_tcp_payload(conn, payload, length) != 0) {
    printf("Error processing TCP payload\n");
    return;
}

/* Update connection state */
conn->ack_num += length;

/* Send ACK for received data */
tcp_header_t ack;
memset(&ack, 0, sizeof(tcp_header_t));
ack.src_port = htons(dest_port);
ack.dest_port = htons(src_port);
ack.seq_num = htonl(conn->seq_num);
ack.ack_num = htonl(conn->ack_num);
ack.flags = htons(0x10);  /* ACK flag */
ack.flags |= (5 << 12);   /* Data offset */
ack.window = htons(TCP_WINDOW_SIZE);
ack.checksum = calculate_tcp_checksum(&ack, NULL, 0);

send_tcp_packet(&ack, NULL, 0);
    }
}

/* Main entry point */
int main() {
    printf("Lightweight TCP/IP Stack Started\n");
    
    /* Initialize network interface */
    uint8_t mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint32_t ip = 0xC0A80101;      /* 192.168.1.1 */
    uint32_t netmask = 0xFFFFFF00;  /* 255.255.255.0 */
    uint32_t gateway = 0xC0A80101;  /* 192.168.1.1 */
    
    net_interface_init(net_interface_get_instance(), mac, ip, netmask, gateway);
    
    /* Main event loop */
    uint8_t packet_buffer[PACKET_BUFFER_SIZE];
    size_t packet_size;
    
    while (1) {
        /* Check for received packets */
        if (net_interface_receive_packet(net_interface_get_instance(), packet_buffer, (uint32_t*)&packet_size) == 0) {
            /* Process received packet */
            process_ethernet_frame((eth_frame_t*)packet_buffer, packet_size);
        }
        
        /* Process TCP timers */
        process_tcp_timers();
        
        /* Small delay to prevent busy waiting */
        usleep(1000);
    }
    
    return 0;
}