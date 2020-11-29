#ifndef __PEER_H__
#define __PEER_H__

#include <openssl/ssl.h>

#include <transport.h>

typedef struct
{
    int                     peer_type;
    int                     state;
    int                     prev_state;
    t_wan_intf_node         *p_wan_intf;
    int                     listener_fd;
    struct event            *p_ev_listener;
    SSL                     *ssl;
    struct t_timer          *ssl_handshake_timer;
    struct event            *handshake_evtimer;

    SSL_CTX             *ctx;
    struct bufferevent  *bev;
    struct event        *timer_ev;
    struct timeval      tv;
} t_peer;

int create_global_peer(t_wan_intf_node *p_wan_intf);

#endif
