#ifndef __TRANSPORT_H__
#define __TRANSPORT_H__

#include <dll.h>
#include <ip_util.h>
#include <common.h>
#include <globals.h>

#define DEFAULT_TCP_PORT        12356
/*
* This represents a WAN interface through which connection can be established or application should listen for connection
*/
typedef struct wan_intf_node
{
    t_dlnode                dl_node;
    char                    name[MAX_IF_NAME_LEN];
	e_state                 oper_state;	

    t_ipaddr_port  pub_loc;
    t_ipaddr_port  priv_loc;
    t_ipaddr_port  pub6_loc;
    t_ipaddr_port  priv6_loc;
} t_wan_intf_node;

void populate_wan_intf_list(t_dll *wan_intf_list_p);

#endif
