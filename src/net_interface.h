#ifndef NET_INTERFACE_H
#define NET_INTERFACE_H

#include <stdint.h>

/* Network interface structure */
typedef struct {
    uint8_t mac_addr[6];
    uint32_t ip_addr;
    uint32_t netmask;
    uint32_t gateway;
} net_interface_t;

/* Interface initialization and management functions */
void net_interface_init(net_interface_t* interface, 
                       const uint8_t* mac, 
                       uint32_t ip, 
                       uint32_t netmask, 
                       uint32_t gateway);

/* Get global interface instance */
net_interface_t* net_interface_get_instance(void);

/* Packet reception function */
int net_interface_receive_packet(net_interface_t* interface, uint8_t* data, uint32_t* size);

/* Send packet through network interface */
int net_interface_send_packet(net_interface_t* interface, const uint8_t* data, uint32_t size);

#endif /* NET_INTERFACE_H */