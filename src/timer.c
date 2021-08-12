#include <event2/event.h>

#include <timer.h>
#include <logging.h>

static inline
msecs_to_timeval(uint64_t msecs, struct timeval *tv)
{
    uint64_t    usecs = msecs * 1000;

    tv->tv_sec = usecs / 1000000;
    tv->tv_usec = usecs % 1000000; 
}

void
timer_callback(evutil_socket_t fd, short what, void *arg)
{
    t_timer             *p_timer = (t_timer*) arg;
    struct timeval      tv;

    p_timer->cb(p_timer);

    /*
     * As the libevent timers are not persistent, need to add the timer again if it is recurrent timer.
     * The timer is getting re-activated after the callback is returned to make sure timer is not
     * not triggered too soon. Checking if the timer is pending might be unnecessary.
     */
    if (p_timer->type == TIMER_TYPE_PERIODIC && !evtimer_pending(p_timer->ev, NULL)) {
        evtimer_add(p_timer->ev, msecs_to_timeval(p_timer->interval_msecs, &tv));
    }
}

t_timer*
sscp_timer_create(t_timer_mgr       *p_mgr,
             e_timer_priority       priority,
             e_timer_type           type,
             uint64_t               interval_msecs,
             f_timer_callback       cb,
             char                   *name)
{
    t_timer *p_timer = calloc(1, sizeof(t_timer));
    p_timer->priority = priority;
    p_timer->type = type;
    p_timer->interval_msecs = interval_msecs;
    p_timer->cb = cb;

    /*
     * libevent timer by default is not persistent. So if the timer is persistent, in the callback
     * we need to add the timer to pending state again.
     */
    SSCP_DEBUGLOG("Adding timer %s", p_timer->name);
    p_timer->ev = evtimer_new(p_mgr->event_base, timer_callback, p_timer);

    return p_timer;
}

void
sscp_timer_enable(t_timer *p_timer)
{
    struct timeval tv;

    SSCP_DEBUGLOG("Enabling timer %s", p_timer->name);
    msecs_to_timeval(p_timer->interval_msecs, &tv);
    evtimer_add(p_timer->ev, &tv);
}

void
sscp_timer_disable(t_timer *p_timer)
{
    SSCP_DEBUGLOG("Disabling timer %s", p_timer->name);
    evtimer_del(p_timer->ev);
}

void
sscp_timer_remove(t_timer *p_timer)
{
}

