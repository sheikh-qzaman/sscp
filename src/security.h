#ifndef __SECURITY_H__
#define __SECURITY_H__

#include <transport.h>
#include <peer.h>

//const char *CIPHER_LIST = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:!SHA1:!MD5";

typedef enum
{
    TLS_SERVER,
    TLS_CLIENT,
    DTLS_SERVER,
    DTLS_CLIENT
} t_conn_mode;

int tls_init(t_wan_intf_node *wan_intf, t_peer *peer, t_conn_mode mode);
#endif
