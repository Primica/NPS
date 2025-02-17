#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "protocol.h"

/* DNS constants */
#define DNS_MAX_NAME_LENGTH 256

/* DNS header structure */
typedef struct dns_header {
    uint16_t id;           /* Query ID */
    uint16_t flags;        /* DNS flags */
    uint16_t qdcount;      /* Question count */
    uint16_t ancount;      /* Answer count */
    uint16_t nscount;      /* Authority count */
    uint16_t arcount;      /* Additional count */
} __attribute__((packed)) dns_header;

/* DNS record types */
#define DNS_TYPE_A     1
#define DNS_TYPE_NS    2
#define DNS_TYPE_CNAME 5
#define DNS_CLASS_IN   1

/* DNS flags */
#define DNS_FLAG_QR     0x8000  /* Query/Response flag */
#define DNS_FLAG_AA     0x0400  /* Authoritative Answer */
#define DNS_FLAG_TC     0x0200  /* Truncation flag */
#define DNS_FLAG_RD     0x0100  /* Recursion Desired */
#define DNS_FLAG_RA     0x0080  /* Recursion Available */
#define DNS_FLAG_RCODE  0x000F  /* Response code mask */

/* Static DNS records */
static struct {
    const char* name;
    uint32_t ip;
} dns_records[] = {
    {"example.com", 0xC0A80101},      /* 192.168.1.1 */
    {"test.example.com", 0xC0A80102}, /* 192.168.1.2 */
    {"www.example.com", 0xC0A80103},  /* 192.168.1.3 */
    {NULL, 0}
};

/* DNS name compression utilities */
static int dns_encode_name(const char* name, uint8_t* buffer) {
    int offset = 0;
    const char* label = name;
    const char* next;

    while (label && *label) {
        next = strchr(label, '.');
        int len = next ? (int)(next - label) : strlen(label);
        
        if (len > 63) return -1;  /* Label too long */
        
        buffer[offset++] = len;
        memcpy(buffer + offset, label, len);
        offset += len;
        
        if (!next) break;
        label = next + 1;
    }
    
    buffer[offset++] = 0;  /* Root label */
    return offset;
}

static int dns_decode_name(const uint8_t* query, int query_len, int offset, char* name, int name_len) {
    int i = 0;
    int jumped = 0;
    int jump_count = 0;
    int name_offset = 0;
    
    while (offset < query_len && query[offset] != 0) {
        if (jump_count++ > 5) return -1;  /* Too many jumps */
        
        if ((query[offset] & 0xC0) == 0xC0) {
            if (!jumped) {
                jumped = 1;
                i = offset + 2;
            }
            offset = ((query[offset] & 0x3F) << 8) | query[offset + 1];
            continue;
        }
        
        int len = query[offset++];
        if (name_offset + len + 1 >= name_len) return -1;
        
        if (name_offset > 0) name[name_offset++] = '.';
        memcpy(name + name_offset, query + offset, len);
        name_offset += len;
        offset += len;
    }
    
    name[name_offset] = '\0';
    return jumped ? i : offset + 1;
}

/* Find DNS record by name */
static uint32_t find_dns_record(const char* name) {
    for (int i = 0; dns_records[i].name != NULL; i++) {
        if (strcasecmp(name, dns_records[i].name) == 0) {
            return dns_records[i].ip;
        }
    }
    return 0;
}

/* Process DNS query and generate response */
void process_dns_query(uint8_t* query, size_t length, uint8_t* response, size_t* response_length) {
    if (length < sizeof(dns_header_t)) {
        printf("DNS query too short\n");
        return;
    }

    struct dns_header* query_header = (struct dns_header*)query;
    dns_header_t* response_header = (dns_header_t*)response;
    
    /* Initialize response header */
    memcpy(response_header, query_header, sizeof(dns_header_t));
    response_header->flags = htons(DNS_FLAG_QR | DNS_FLAG_AA);  /* Response + Authoritative */
    response_header->ancount = 0;
    
    int offset = sizeof(dns_header_t);
    char qname[DNS_MAX_NAME_LENGTH];
    
    /* Decode query name */
    int name_end = dns_decode_name(query, length, offset, qname, sizeof(qname));
    if (name_end < 0) {
        printf("Failed to decode DNS query name\n");
        return;
    }
    
    /* Copy question to response */
    memcpy(response + offset, query + offset, name_end - offset + 4);  /* Include QTYPE and QCLASS */
    offset = name_end + 4;
    
    /* Look up the name in our records */
    uint32_t ip = find_dns_record(qname);
    if (ip) {
        /* Add answer section */
        uint8_t* answer = response + offset;
        
        /* Compressed name pointer */
        answer[0] = 0xC0;
        answer[1] = sizeof(dns_header_t);
        offset += 2;
        
        /* Type A */
        *(uint16_t*)(response + offset) = htons(DNS_TYPE_A);
        offset += 2;
        
        /* Class IN */
        *(uint16_t*)(response + offset) = htons(DNS_CLASS_IN);
        offset += 2;
        
        /* TTL: 300 seconds */
        *(uint32_t*)(response + offset) = htonl(300);
        offset += 4;
        
        /* RDLENGTH: 4 bytes for IPv4 */
        *(uint16_t*)(response + offset) = htons(4);
        offset += 2;
        
        /* RDATA: IP address */
        *(uint32_t*)(response + offset) = ip;
        offset += 4;
        
        response_header->ancount = htons(1);
        printf("DNS response for %s: %u.%u.%u.%u\n", 
               qname,
               (ip >> 24) & 0xFF,
               (ip >> 16) & 0xFF,
               (ip >> 8) & 0xFF,
               ip & 0xFF);
    } else {
        printf("No DNS record found for %s\n", qname);
        response_header->flags |= htons(3);  /* Name Error */
    }
    
    *response_length = offset;
}