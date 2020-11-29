#ifndef __COMMON_H__
#define __COMMON_H__

typedef enum
{
    PROTO_TCP,
    PROTO_UDP,
    PROTO_ALL
} e_transport_proto;

typedef enum
{
    MODE_CLIENT,
    MODE_SERVER,
    MODE_BOTH
} e_oper_mode;

typedef enum
{
    STATE_UNKNOWN = 0,
    STATE_UP      = 1,
    STATE_DOWN    = 2,
} e_state;

#endif
