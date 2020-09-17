#include <dll.h>

void
wan_intf_deinit(t_dll *wan_intf_list)
{
    t_wan_intf_node *wan_intf, *wan_intf_next;

    wan_intf = DLL_FIRST(t_wan_intf_node, dl_node, wan_intf_list);
    while (wan_intf) {
    }
}
