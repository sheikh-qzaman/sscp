#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent_ssl.h>

#include <sscp.h>
#include <conn_mgr.h>
#include <globals.h>
#include <transport.h>
#include <logging.h>
#include <sscp.h>
#include <ssl_utils.h>
#include <ip_util.h>

#ifdef SKIP
e_err
udp_listener_create(t_wan_intf_node *p_wan_intf) // vbond_listener_create
{
    struct sockaddr_in      sin;
    struct sockaddr_in      *wan_loc = &p_wan_intf->priv_loc;
    int                     sockfd, flag = 1, status, retry_count = 0;

    t_cpmgr_ctx             *p_cpmgr_ctx = cpmgr_get_ctx();

    memset(&sin, 0, sizeof(sin));
    sin.sin_family      = AF_INET;
    sin.sin_port        = wan_loc->sin_port;

	if (wan_loc->sin_addr.s_addr != 0) {
        sin.sin_addr.s_addr = wan_loc->sin_addr.s_addr;
    } else {
        sin.sin_addr.s_addr = INADDR_ANY;
    }

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0) {
        return ERR_SOCKET;
    }

    p_wan_intf->udp_listener_fd = sockfd;

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0) {
        close(sockfd);
        SSCP_ERRLOG("Error setting socket option %d.", errno);
        return ERR_SOCKET;
    }

    /* IP supports some protocol-specific socket options that can be set. The socket option level for IP is IPPROTO_IP */
    // TODO
    // if (setsockopt (sock, IPPROTO_IP, IP_TOS, (char*)&IpTOS, sizeof(IpTOS)) < 0) {}

    while ((status = bind(sockfd, (struct sockadd*) &sin, sizeof(sin))) < 0) {
        if (retry_count < BIND_RETRY_MAX) {
            usleep(500000);
            continue;
        }

        close(sockfd);
        SSCP_ERRLOG("Error binding socket. %d.", errno);
        return ERR_SOCKET;
    }

    /* for UPD listen is not necessary?
    if (listen(sockfd, 16) < 0) {
        close(sockfd);
        SSCP_ERRLOG("Error binding socket. %d.", errno);
        return ERR_SOCKET;
    }
    */

    p_wan_intf->udp_listener_ev = event_new(p_cpmgr_ctx->p_event_base, sockfd, EV_READ | EV_PERSIST, dtls_event_cb, NULL);

    /* This can be done with sockopt SOCK_NONBLOCK as well. libevent provides portability.*/
    if (evutil_make_socket_nonblocking(sockfd)) {
        close(sockfd);
        SSCP_ERRLOG("Error making socket nonblocking. %d.", errno);
        return ERR_LIBEVENT;
    }

    event_priority_set(p_wan_intf->udp_listener_ev, 1); // TODO revisit priority

    if (tls_init(p_wan_intf, NULL, DTLS_SERVER) != 0) {
        return ERR_SSL;
    }

    // TODO error handling
    event_add(p_wan_intf->udp_listener_ev, NULL);

    if (tls_init(p_wan_intf, NULL, DTLS_CLIENT) != 0) {
        return ERR_SSL;
    }

    return ERR_OK;
}

void
dtls_event_cb(int fd, short event, void *p_data) /* vbond_ssl_event_cb */
{
    struct sockaddr_storage     client_addr, server_addr; /* sockaddr_storage is used for AF independent code. */
    socklen_t                   server_addr_len;

    memset(&client_addr, 0, sizeof(client_addr));
    memset(&server_addr, 0, sizeof(server_addr));

    if (getsockname(fd, (struct sockaddr*) &server_addr, &server_addr_len) != 0) {
        SSCP_ERRLOG("getsockname failed. errno: %d", errno);
        return;
    }

    // TODO populate v4/v6 peer depending on AF
}

int
init_new_connection(t_peer *p_ssl_peer, t_conn_mode conn_mode) /* vdaemon_init_new_connection */
{
    SSL_CTX             *ctx;
    t_cpmgr_ctx         *p_cpmgr_ctx = cpmgr_get_ctx();

    p_ssl_peer->bio = BIO_new_dgram(p_ssl_peer->wan_intf->listener_fd, BIO_NOCLOSE); //TODO Why noclose?

    timeout.tv_sec = 6;
    timeout.tv_usec = 0;

    BIO_ctrl(p_ssl_peer->bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
    BIO_set_nbio(p_ssl_peer->bio, 0x1);

    if (conn_mode == DTLS_SERVER) {
        ctx = p_ssl_peer->p_wan_intf->dtls_server_ctx;
    } else {
        ctx = p_ssl_peer->p_wan_intf->dtls_client_ctx;
    }

    p_ssl_peer->ssl = SSL_new(ctx);
    if(p_ssl_peer->ssl == NULL) {
        SSCP_ERRLOG("Unable to allocate SSL.");
        return 1;
    }

	/*
     * Set a huge MTU so that the kernel does the fragmentation for you. And we DONOT
     * rely on the DTLS MTU query to come up with the PMTU
     */
    // TODO Understand
    SSL_set_mtu(p_ssl_peer->ssl, 1024);

    SSL_set_bio(p_ssl_peer->ssl, p_ssl_peer->bio, p_ssl_peer->bio);
    if (conn_mode == DTLS_SERVER) {
        SSL_set_options(p_ssl_peer->ssl, SSL_OP_COOKIE_EXCHANGE);
    }

    DTLSv1_get_timeout(p_ssl_peer->ssl, &timeout);
    if (!p_ssl_peer->handshake_evtimer) {
        p_ssl_peer->handshake_evtimer = evtimer_new(p_cpmgr_ctx->p_event_base, ssl_handshake_cb, p_ssl_peer);
        if (!p_vpeer->ssl_handshake_timer) {
            SSCP_ERRLOG("SSL handshake timer create failed");
            return 1;
        }
    }

    // TODO peer state
    /*p_ssl_peer->prev_state = p_vpeer->state;
    p_ssl_peer->state = VBOND_PEER_STATE_SSL_CONNECT;*/

    return 0;
}
#endif

void
tls_writecb(struct bufferevent *bev, void *ctx)
{
    printf("BEV_EVENT_WRITE\n");
}

void
tls_eventcb(struct bufferevent *bev, short event, void *ctx)
{
    if (event & BEV_EVENT_CONNECTED) {
        SSCP_DEBUGLOG("BEV_EVENT_CONNECTED\n");
    }

    /*
    if (event & BEV_EVENT_READING) {
        printf("BEV_EVENT_READING\n");
        printf(evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
        printf("\n");
    }

    if (event & BEV_EVENT_WRITING) {
        printf("BEV_EVENT_WRITING\n");
    }

    if (event & BEV_EVENT_ERROR) {
        printf("BEV_EVENT_ERROR\n");
    }
    */

    if (event & BEV_EVENT_EOF) {
        SSCP_DEBUGLOG("BEV_EVENT_EOF\n");
    }

    if (event & BEV_EVENT_TIMEOUT) {
        SSCP_DEBUGLOG("BEV_EVENT_TIMEOUT\n");
    }
}

void
ssl_acceptcb(struct evconnlistener *ev_listener, int sock, struct sockaddr *sa, int sa_len, void *arg)
{
    t_cpmgr_ctx             *p_cpmgr_ctx = cpmgr_get_ctx();
    t_wan_intf_node         *p_wan_intf = (t_wan_intf_node *) arg;
    struct bufferevent      *p_bev;
    SSL                     *p_client_ctx;
    struct event_base       *p_event_base;
    char                    ip_str[INET_ADDRSTRLEN];

	SSCP_DEBUGLOG("Client %s connected.", get_ip_str(sa, ip_str, INET_ADDRSTRLEN));

    p_client_ctx = SSL_new(p_cpmgr_ctx->ssl_server_ctx);
    p_event_base = evconnlistener_get_base(ev_listener);

    p_bev = bufferevent_openssl_socket_new(p_event_base, sock, p_client_ctx, BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE);

    bufferevent_enable(p_bev, EV_READ | EV_WRITE);
    bufferevent_setcb(p_bev, tls_readcb, tls_writecb, tls_eventcb, NULL);
}

e_err
tcp_listener_create(t_wan_intf_node *p_wan_intf)
{
    t_cpmgr_ctx             *p_cpmgr_ctx = cpmgr_get_ctx();

    if (!p_cpmgr_ctx->ssl_server_ctx) {
        create_ssl_server_ctx();
    }

    p_wan_intf->tcp_listener = evconnlistener_new_bind(p_cpmgr_ctx->event_base, ssl_acceptcb, (void *) p_wan_intf,
            LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, 1024, (struct sockaddr *) &p_wan_intf->pub_loc, sizeof(p_wan_intf->pub_loc));

    return ERR_OK;
}
