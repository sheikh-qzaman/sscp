#ifndef __SSCP_H__
#define __SSCP_H__

#include <dll.h>
#include <globals.h>
#include <common.h>
#include <transport.h>

typedef struct init_cfg
{
    t_transport_proto t_proto;
} t_init_cfg;

/*
 * Control Plane Manager
 */
typedef struct cpmgr_ctx
{
    struct event_base       *event_base;
    t_dll                   wan_intf_list;
} t_cpmgr_ctx;

t_cpmgr_ctx* cpmgr_get_ctx();
void tls_readcb(struct bufferevent * bev, void * arg);

#endif
