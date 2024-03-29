#ifndef __SSCP_H__
#define __SSCP_H__

#include <dll.h>
#include <globals.h>
#include <common.h>
#include <transport.h>
#include <security.h>
#include <peer.h>
#include <timer.h>
#include <logging.h>

typedef struct init_cfg
{
    e_transport_proto   trans_proto;
    e_oper_mode         oper_mode;
} t_init_cfg;

/*
 * Control Plane Manager
 */
typedef struct cpmgr_ctx
{
    struct event_base       *event_base;
    struct event            *base_timer;
    t_timer_mgr             timer_mgr;
    t_dll                   wan_intf_list;
    t_dll                   globaldb_dll;

    SSL_CTX                 *tls_client_ctx;
    SSL_CTX                 *tls_server_ctx;
} t_cpmgr_ctx;

extern t_peer   *g_peer;

t_cpmgr_ctx* cpmgr_get_ctx();
void tls_readcb(struct bufferevent * bev, void * arg);

#endif
