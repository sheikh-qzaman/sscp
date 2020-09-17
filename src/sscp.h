#ifndef __SSCP_H__
#define __SSCP_H__

#include <dll.h>
#include <globals.h>
#include <common.h>

typedef struct init_cfg
{
    t_transport_proto t_proto;
} t_init_cfg;

/*
 * Control Plane Manager
 */
typedef struct cpmgr_ctx
{
    struct event_base       *p_event_base;
    t_dll                   wan_intf_list;
} t_cpmgr_ctx;

extern void set_config_params(int argc, char *argv[], t_init_cfg *cfg);
#endif
