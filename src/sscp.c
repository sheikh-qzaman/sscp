/* Simple echo server using OpenSSL bufferevents */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <event.h>
#include <event2/listener.h>
#include <event2/bufferevent_ssl.h>

#include <logging.h>
#include <sscp.h>
#include <transport.h>
#include <conn_mgr.h>
#include <peer.h>
#include <client.h>

extern void set_config_params(int argc, char *argv[], t_init_cfg *cfg);

static t_cpmgr_ctx                  g_cpmgr_ctx;
t_init_cfg                          cfg;

t_cpmgr_ctx*
cpmgr_get_ctx()
{
    return &g_cpmgr_ctx;
}

void
populate_wan_intf_list(t_dll *p_wan_intf_list)
{
    t_wan_intf_node         *p_wan_intf;

    p_wan_intf = calloc(1, sizeof(t_wan_intf_node));
    memcpy(&p_wan_intf->name, "ens3", 4); /* memcpy is fine here as source is null terminated*/
    p_wan_intf->pub_loc.sin_family = AF_INET;
    p_wan_intf->pub_loc.sin_addr.s_addr = inet_addr("15.0.0.1"); /* v4addr is in_addr of network order. inet_addr returns in network order */
    p_wan_intf->pub_loc.sin_port = htons(DEFAULT_TCP_PORT);      /* in_port_t is in network order, so convert from host order. */

    DLL_ADD(p_wan_intf_list, &p_wan_intf->dl_node);
}

void
sscp_init()
{
    t_cpmgr_ctx         *cpmgr_ctx_p = &g_cpmgr_ctx;

    create_ssl_ctx();

    DLL_INIT(&cpmgr_ctx_p->wan_intf_list);
    populate_wan_intf_list(&cpmgr_ctx_p->wan_intf_list);
}

e_err
event_base_create()
{
    t_cpmgr_ctx             *p_cpmgr_ctx = &g_cpmgr_ctx;
    struct event_base       *p_event_base;

    p_event_base = event_base_new();
    p_cpmgr_ctx->event_base = p_event_base;

    return ERR_OK;
}

void
tls_readcb(struct bufferevent * bev, void * arg)
{
    printf("Reading from buffer\n");
    struct evbuffer *in = bufferevent_get_input(bev);

    printf("Received %zu bytes\n", evbuffer_get_length(in));
    printf("----- data ----\n");
    printf("%.*s\n", (int)evbuffer_get_length(in), evbuffer_pullup(in, -1));

    printf("Writing to buffer\n");
    bufferevent_write_buffer(bev, in);
    printf("Wrote to buffer\n");
}

void
sscp_listen()
{
    t_cpmgr_ctx             *p_cpmgr_ctx = &g_cpmgr_ctx;
    t_wan_intf_node         *p_wan_intf;

    SSCP_DEBUGLOG("Starting in server mode.");

    p_wan_intf = DLL_FIRST(t_wan_intf_node, dl_node, &p_cpmgr_ctx->wan_intf_list);
    tcp_listener_create(p_wan_intf);
}

void
sscp_connect()
{
    t_cpmgr_ctx             *p_cpmgr_ctx = &g_cpmgr_ctx;
    t_wan_intf_node         *p_wan_intf;

    SSCP_DEBUGLOG("Starting in client mode.");

    p_wan_intf = DLL_FIRST(t_wan_intf_node, dl_node, &p_cpmgr_ctx->wan_intf_list);
    create_ssl_client(p_wan_intf);
}

void
sscp_destroy()
{
    t_cpmgr_ctx             *p_cpmgr_ctx = &g_cpmgr_ctx;
    t_wan_intf_node         *p_wan_intf;

    p_wan_intf = DLL_FIRST(t_wan_intf_node, dl_node, &p_cpmgr_ctx->wan_intf_list);

    while (p_wan_intf) {
        if (p_wan_intf->tcp_listener) {
            evconnlistener_free(p_wan_intf->tcp_listener);
        }

        p_wan_intf = DLL_NEXT(t_wan_intf_node, dl_node, p_wan_intf);
    }

    if (p_cpmgr_ctx->ssl_client_ctx) {
        SSL_CTX_free(p_cpmgr_ctx->ssl_client_ctx);
    }

    if (p_cpmgr_ctx->ssl_server_ctx) {
        SSL_CTX_free(p_cpmgr_ctx->ssl_server_ctx);
    }
}

int
main(int argc, char **argv)
{
    t_cpmgr_ctx             *p_cpmgr_ctx = &g_cpmgr_ctx;

    SSL_CTX *ctx;

    SSCP_SYSLOG_INIT("SSCP");
    SSCP_DEBUGLOG("Secure Scalabale Control Plane.");

    memset(&cfg, 0x0, sizeof(t_init_cfg));
    set_config_params(argc, argv, &cfg);

    sscp_init();

    event_base_create();
    
    if (cfg.oper_mode == MODE_SERVER) {
        sscp_listen();
    } else {
        sscp_connect();
    }

    event_base_loop(p_cpmgr_ctx->event_base, 0);

    sscp_destroy();

    return 0;
}
