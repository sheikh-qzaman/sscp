#ifndef __TIMER_H__
#define __TIMER_H__

#include <event2/event.h>

typedef struct
{
    struct event        *ev;
} t_timer;

t_timer* timer_create(struct event_base *base, int dummy);

#endif
