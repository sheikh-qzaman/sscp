#ifndef __SSCP_H__
#define __SSCP_H__

#include <sscp_debug.h>

typedef enum transport_proto
{
    PROTO_TCP,
    PROTO_UDP
} t_transport_proto;

typedef struct init_cfg
{
    t_transport_proto t_proto;
} t_init_cfg;

extern void set_config_params(int argc, char *argv[], t_init_cfg *cfg);

#endif
