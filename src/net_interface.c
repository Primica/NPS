#include "net_interface.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define RING_BUFFER_SIZE 32
#define MAX_PACKET_SIZE 1518  /* Maximum Ethernet frame size */

/* Ring buffer structure for packet reception */
typedef struct {
    uint8_t data[RING_BUFFER_SIZE][MAX_PACKET_SIZE];
    size_t sizes[RING_BUFFER_SIZE];
    volatile uint32_t head;
    volatile uint32_t tail;
} packet_ring_buffer_t;

/* Static variables */
static net_interface_t g_interface;
static packet_ring_buffer_t g_rx_buffer;

/* Initialize network interface */
void net_interface_init(net_interface_t* interface, 
                       const uint8_t* mac, 
                       uint32_t ip, 
                       uint32_t netmask, 
                       uint32_t gateway) {
    /* Copy interface configuration */
    memcpy(interface->mac_addr, mac, 6);
    interface->ip_addr = ip;
    interface->netmask = netmask;
    interface->gateway = gateway;

    /* Initialize ring buffer */
    memset(&g_rx_buffer, 0, sizeof(packet_ring_buffer_t));
}

/* Get global interface instance */
net_interface_t* net_interface_get_instance(void) {
    return &g_interface;
}

/* Add packet to ring buffer */
int packet_buffer_add(const uint8_t* data, size_t size) {
    uint32_t next_head = (g_rx_buffer.head + 1) % RING_BUFFER_SIZE;
    
    /* Check for buffer full condition */
    if (next_head == g_rx_buffer.tail) {
        return -1;  /* Buffer full */
    }

    /* Copy packet data */
    if (size <= MAX_PACKET_SIZE) {
        memcpy(g_rx_buffer.data[g_rx_buffer.head], data, size);
        g_rx_buffer.sizes[g_rx_buffer.head] = size;
        g_rx_buffer.head = next_head;
        return 0;
    }

    return -2;  /* Packet too large */
}

/* Get packet from ring buffer */
int packet_buffer_get(uint8_t* data, size_t* size) {
    /* Check for empty buffer */
    if (g_rx_buffer.head == g_rx_buffer.tail) {
        return -1;  /* Buffer empty */
    }

    /* Copy packet data */
    *size = g_rx_buffer.sizes[g_rx_buffer.tail];
    memcpy(data, g_rx_buffer.data[g_rx_buffer.tail], *size);
    
    /* Update tail pointer */
    g_rx_buffer.tail = (g_rx_buffer.tail + 1) % RING_BUFFER_SIZE;
    
    return 0;
}

/* Receive packet from network interface */
int net_interface_receive_packet(net_interface_t* interface, uint8_t* data, uint32_t* size) {
    size_t packet_size;
    int result = packet_buffer_get(data, &packet_size);
    
    if (result == 0) {
        *size = (uint32_t)packet_size;
    }
    
    return result;
}

/* Send packet through network interface */
int net_interface_send_packet(net_interface_t* interface, const uint8_t* data, uint32_t size) {
    /* Basic validation */
    if (!interface || !data || size == 0 || size > MAX_PACKET_SIZE) {
        return -1;
    }

    /* In a real implementation, this would interface with the network hardware */
    /* For now, we'll just print the packet details */
    printf("Sending packet: size=%u bytes\n", (unsigned int)size);
    
    return 0;
}
