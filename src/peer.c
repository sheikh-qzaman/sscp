#include <sscp.h>

/* This represents the peer on the local side corresponding the connection
 * TODO Need more info
 */
int
create_global_peer(t_wan_intf_node *p_wan_intf)
{
    t_peer              *p_peer = NULL;
    t_cpmgr_ctx         *p_cpmgr_ctx = cpmgr_get_ctx();
    struct timeval      timeout;

    timeout.tv_sec = 6;
    timeout.tv_usec = 0;

    if (!(p_peer = calloc(1, sizeof(t_peer)))) {
        SSCP_ERRLOG("Memory allocation failure for ssl global peer.");
        return ERR_ALLOC;
    }

    p_peer->listener_fd     = -1;
    p_peer->p_wan_intf      = p_wan_intf;

    // TODO Expiary timer
    // TODO Handshake timer
    p_peer->p_wan_intf->g_tcp_peer = p_peer;

    return 0;
}
