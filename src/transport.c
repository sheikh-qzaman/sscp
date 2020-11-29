#include <arpa/inet.h>
#include <stdlib.h>
#include <bsd/string.h>

#include <dll.h>
#include <transport.h>
#include <logging.h>

void
populate_wan_intf_list(t_dll *p_wan_intf_list)
{
    t_wan_intf_node         *p_wan_intf;

    p_wan_intf = calloc(1, sizeof(t_wan_intf_node));
    memcpy(&p_wan_intf->name, "ens3", 4); /* memcpy is fine here as source is null terminated*/
    p_wan_intf->pub_loc.sin_addr.s_addr = inet_addr("15.0.0.1"); /* v4addr is in_addr of network order. inet_addr returns in network order */
    p_wan_intf->pub_loc.sin_port = htons(DEFAULT_TCP_PORT);      /* in_port_t is in network order, so convert from host order. */

    DLL_ADD(p_wan_intf_list, &p_wan_intf->dl_node);
}
