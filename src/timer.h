#ifndef __TIMER_H__
#define __TIMER_H__

#include <event2/event.h>

typedef enum
{
    TIMER_TYPE_ONESHOT,
    TIMER_TYPE_PERIODIC,
} e_timer_type;

typedef enum
{
    TIMER_PRI_MIN,
    TIMER_PRI_NORMAL,
    TIMER_PRI_HIGH,
    NUM_TIMER_PRIORITIES,
} e_timer_priority;

struct t_timer;

typedef void (*f_timer_callback) (struct t_timer *p_timer);

typedef struct
{
    char                *name[40];
    struct event        *ev;
    e_timer_type        type;
    e_timer_priority    priority;
    uint64_t            interval_msecs;
    f_timer_callback    cb;
} t_timer;

typedef struct
{
    struct event_base       *event_base;
} t_timer_mgr;

t_timer* sscp_timer_create(t_timer_mgr *p_mgr, e_timer_priority priority, e_timer_type type, uint64_t interval_msecs, f_timer_callback cb, char *name);
void sscp_timer_enable(t_timer *p_timer);
void sscp_timer_disable(t_timer *p_timer);
void sscp_timer_delete(t_timer *p_timer);

#endif
