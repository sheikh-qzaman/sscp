#include <string.h>
#include <event2/event.h>
#include <event2/event-config.h>
#include <event2/util.h>

#include <sscp.h>
#include <sscp_debug.h>
#include <transport.h>

/* GLOBAL VARIABLES*/
static t_cpmgr_ctx                 g_cpmgr_ctx;

t_cpmgr_ctx*
cpmgr_get_ctx()
{
    return &g_cpmgr_ctx;
}

void
sscp_init()
{
    t_cpmgr_ctx         *cpmgr_ctx_p = cpmgr_get_ctx();

    DLL_INIT(&cpmgr_ctx_p->wan_intf_list);
    populate_wan_intf_list(&cpmgr_ctx_p->wan_intf_list);
}

void
sscp_destroy()
{
}

e_err
event_base_create()
{
    t_cpmgr_ctx             *p_cpmgr_ctx = &g_cpmgr_ctx;
	struct event_config     *p_cfg;
    struct event_base       *p_event_base;

    p_cfg = event_config_new();
    if (NULL == p_cfg) {
        return ERR_ALLOC;
    }

    /*
     * TODO Why we are using edge-triggered over level triggered
     * Enable edge-trigger, O(1) event insertion/deletion and all FD types.
     */
    event_config_require_features(p_cfg, EV_FEATURE_ET | EV_FEATURE_O1);

    event_config_set_flag(p_cfg, EVENT_BASE_FLAG_NOLOCK); /* TODO Set lib-event to be fully lockless. */
    p_event_base = event_base_new_with_config(p_cfg);

    event_base_priority_init(p_event_base, 2); /* TODO assume two priority levels for different events for now */
    event_config_free(p_cfg);

    if (NULL == p_event_base) {
        return ERR_ALLOC;
    }

	p_cpmgr_ctx->p_event_base = p_event_base;
    return ERR_OK;
}

int
main(int argc, char *argv[])
{
    t_cpmgr_ctx             *p_cpmgr_ctx = &g_cpmgr_ctx;
    t_init_cfg              cfg;

    SSCP_SYSLOG_INIT("SSCP");
    SSCP_DEBUGLOG("Secure Scalabale Control Plane.");
    
    memset(&cfg, 0x0, sizeof(t_init_cfg));
    set_config_params(argc, argv, &cfg);

    sscp_init();

    event_base_create();
    event_base_loop(p_cpmgr_ctx->p_event_base, 0); /* TODO Any flags needed in second parameter?*/

    sscp_destroy();

    SSCP_SYSLOG_DONE();

    return 0;
}
