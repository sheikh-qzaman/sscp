#include <arpa/inet.h>
#include <stdlib.h>
#include <bsd/string.h>

#include <dll.h>
#include <transport.h>
#include <sscp_debug.h>

static inline void IPADDR_INIT2(t_wan_intf_node *wan_intf)
{
        memset(&wan_intf->pub_loc.addr, 0, sizeof(t_ipaddr));
        memset(&wan_intf->priv_loc.addr, 0, sizeof(t_ipaddr));
        memset(&wan_intf->pub6_loc.addr, 0, sizeof(t_ipaddr));
        memset(&wan_intf->priv6_loc.addr, 0, sizeof(t_ipaddr));

        wan_intf->pub_loc.addr.addr_type = IP_ADDR_V4;
        wan_intf->priv_loc.addr.addr_type = IP_ADDR_V4;
        wan_intf->pub6_loc.addr.addr_type = IP_ADDR_V6;
        wan_intf->priv6_loc.addr.addr_type = IP_ADDR_V6;
}

void
populate_wan_intf_list(t_dll *wan_intf_list_p)
{
    t_wan_intf_node         *wan_intf_p;

    wan_intf_p = calloc(1, sizeof(t_wan_intf_node));
    IPADDR_INIT2(wan_intf_p);
    memcpy(&wan_intf_p->name, "ens3", 4); /* memcpy is fine here as source is null terminated*/
    wan_intf_p->pub_loc.addr.v4addr = inet_addr("15.0.0.1"); /* v4addr is in_addr of network order. inet_addr returns in network order */
    wan_intf_p->pub_loc.port = htons(DEFAULT_TCP_PORT);      /* in_port_t is in network order, so convert from host order. */

    DLL_ADD(wan_intf_list_p, &wan_intf_p->dl_node);
}
