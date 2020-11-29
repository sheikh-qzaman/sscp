#ifndef __TRANSPORT_H__
#define __TRANSPORT_H__

#include <dll.h>
#include <ip_util.h>
#include <common.h>
#include <globals.h>
#include <openssl/ssl.h>

#define DEFAULT_TCP_PORT        4433
/*
* This represents a WAN interface through which connection can be established or application should listen for connection
*/
typedef struct wan_intf_node
{
    t_dlnode                dl_node;
    char                    name[MAX_IF_NAME_LEN];
	e_state                 oper_state;	

    struct sockaddr_in      pub_loc;
    struct sockaddr_in      priv_loc;

    struct evconnlistener   *tcp_listener;

    SSL_CTX                 *tls_server_ctx;
    SSL_CTX                 *ssl_client_ctx;
} t_wan_intf_node;

void populate_wan_intf_list(t_dll *wan_intf_list_p);

#endif
