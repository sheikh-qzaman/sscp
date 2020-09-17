#ifndef __COMMON_H__
#define __COMMON_H__

typedef enum transport_proto
{
    PROTO_TCP,
    PROTO_UDP
} t_transport_proto;

typedef enum e_state
{
    STATE_UNKNOWN = 0,
    STATE_UP      = 1,
    STATE_DOWN    = 2,
} e_state;

#endif
