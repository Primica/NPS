#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "protocol.h"

#define TIME_WAIT_DURATION 60  /* 60 seconds for TIME_WAIT state */

/* Timer structure for TCP connections */
typedef struct tcp_timer {
    tcp_conn_t* conn;
    time_t expiry;
    struct tcp_timer* next;
} tcp_timer_t;

/* Global timer list */
static tcp_timer_t* timer_list = NULL;

/* Start TIME_WAIT timer for a connection */
void start_time_wait_timer(tcp_conn_t* conn) {
    if (!conn) return;
    
    tcp_timer_t* timer = (tcp_timer_t*)malloc(sizeof(tcp_timer_t));
    if (!timer) {
        printf("Failed to allocate timer\n");
        return;
    }
    
    /* Initialize timer */
    timer->conn = conn;
    timer->expiry = time(NULL) + TIME_WAIT_DURATION;
    timer->next = timer_list;
    timer_list = timer;
}

/* Check and process expired timers */
void process_tcp_timers(void) {
    tcp_timer_t** pp = &timer_list;
    time_t now = time(NULL);
    
    while (*pp) {
        tcp_timer_t* timer = *pp;
        
        if (now >= timer->expiry) {
            /* Timer expired */
            if (timer->conn->state == TCP_STATE_TIME_WAIT) {
                /* Move connection to CLOSED state */
                remove_tcp_connection(timer->conn);
            }
            
            /* Remove timer from list */
            *pp = timer->next;
            free(timer);
        } else {
            pp = &timer->next;
        }
    }
}