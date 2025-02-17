#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Protocol definitions */
#define ETH_TYPE_IP    0x0800
#define ETH_TYPE_ARP   0x0806
#define IP_PROTO_ICMP  1
#define IP_PROTO_TCP   6
#define IP_PROTO_UDP   17
#define MAX_PACKET_SIZE 1500

/* Layer 2 - Ethernet frame structure */
typedef struct {
    uint8_t  dest_mac[6];
    uint8_t  src_mac[6];
    uint16_t eth_type;
    uint8_t  payload[1500]; /* Maximum MTU size */
} eth_frame_t;

/* Layer 3 - IP header structure */
typedef struct {
    uint8_t  version_ihl;
    uint8_t  tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t header_checksum;
    uint32_t src_ip;
    uint32_t dest_ip;
} ip_header_t;

/* Layer 3 - ARP packet structure */
typedef struct {
    uint16_t hw_type;
    uint16_t protocol_type;
    uint8_t  hw_len;
    uint8_t  protocol_len;
    uint16_t operation;
    uint8_t  sender_mac[6];
    uint32_t sender_ip;
    uint8_t  target_mac[6];
    uint32_t target_ip;
} arp_packet_t;

/* Layer 3 - ICMP header structure */
typedef struct {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequence;
    uint8_t  data[1500];
} icmp_header_t;

/* Layer 4 - UDP header structure */
typedef struct {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
} udp_header_t;

/* Layer 4 - TCP header structure */
typedef struct {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint16_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
    uint32_t src_ip;    /* Source IP address */
    uint32_t dest_ip;   /* Destination IP address */
} tcp_header_t;

/* DNS message structures */
#define DNS_MAX_NAME_LENGTH 256
#define DNS_MAX_RECORDS 10

/* DNS header structure */
typedef struct {
    uint16_t id;          /* Query ID */
    uint16_t flags;       /* Flags and codes */
    uint16_t qdcount;     /* Number of questions */
    uint16_t ancount;     /* Number of answers */
    uint16_t nscount;     /* Number of authority records */
    uint16_t arcount;     /* Number of additional records */
} dns_header_t;

/* Function declarations */
uint16_t calculate_ip_checksum(ip_header_t* ip_header);
bool get_mac_address(uint32_t ip_addr, uint8_t* mac_addr);

/* Add missing function declarations */
void process_ip_packet(eth_frame_t* eth_frame, ip_header_t* ip_header, uint8_t* payload, size_t length);
void process_arp_packet(arp_packet_t* arp_packet);
void process_dns_query(uint8_t* query, size_t query_length, uint8_t* response, size_t* response_length);
void process_tcp_segment(tcp_header_t* tcp_header, uint8_t* payload, size_t length);

/* DNS question structure */
typedef struct {
    char name[DNS_MAX_NAME_LENGTH];
    uint16_t type;
    uint16_t class;
} dns_question_t;

/* DNS resource record structure */
typedef struct {
    char name[DNS_MAX_NAME_LENGTH];
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
    uint32_t rdata;       /* For A records, this is the IP address */
} dns_record_t;

/* TCP connection states */
#define TCP_STATE_CLOSED      0
#define TCP_STATE_LISTEN      1
#define TCP_STATE_SYN_SENT    2
#define TCP_STATE_SYN_RECEIVED 3
#define TCP_STATE_ESTABLISHED 4
#define TCP_STATE_FIN_WAIT_1 5
#define TCP_STATE_FIN_WAIT_2 6
#define TCP_STATE_CLOSE_WAIT 7
#define TCP_STATE_CLOSING    8
#define TCP_STATE_LAST_ACK   9
#define TCP_STATE_TIME_WAIT  10

#define TCP_WINDOW_SIZE 65535

/* TCP connection structure */
typedef struct tcp_conn {
    uint8_t state;
    uint16_t local_port;
    uint16_t remote_port;
    uint32_t remote_ip;
    uint32_t seq_num;
    uint32_t ack_num;
    struct tcp_conn* next;
} tcp_conn_t;

/* TCP function declarations */
bool is_port_open(uint16_t port);
void send_tcp_rst(tcp_header_t* tcp_header);
uint16_t calculate_tcp_checksum(tcp_header_t* tcp_header, uint8_t* payload, size_t length);
tcp_conn_t* create_tcp_connection(void);
void add_tcp_connection(tcp_conn_t* conn);
tcp_conn_t* find_tcp_connection(uint16_t src_port, uint16_t dest_port, uint32_t seq_num);
uint32_t generate_initial_seq(void);
int handle_tcp_payload(tcp_conn_t* conn, uint8_t* payload, size_t length);
void send_tcp_packet(tcp_header_t* tcp_header, uint8_t* payload, size_t length);
void start_time_wait_timer(tcp_conn_t* conn);
void process_tcp_timers(void);
void remove_tcp_connection(tcp_conn_t* conn);

#endif /* PROTOCOL_H */