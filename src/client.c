#include <event.h>
#include <event2/event-config.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/util.h>

#include <client.h>
#include <peer.h>
#include <sscp.h>
#include <transport.h>
#include <logging.h>
#include <ssl_utils.h>

extern int    errno;

#define LINELEN                     12
#define MAX_SELECT_ATTEMPTS         50
#define CLIENT_ADD_INTERVAL_SEC     1
#define CLIENT_ADD_INTERVAL_MSEC    0 
#define CLIENT_DEL_INTERVAL_SEC     5
#define MSG_SEND_INTERVAL_SEC       1 
#define MSG_SEND_INTERVAL_MSEC      0

char                *host = "127.0.0.1";
int                 port = 4433;
int                 count = 0;

int
connectsock(t_peer *p_peer, const char *host, int port)
{
    struct sockaddr_in  sin; 	/* an Internet endpoint address         */
    int                 sock; 	/* socket descriptor                    */
    int                 ret, retry_attempts = 0, flag = 1;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;

    /* Map port number (char string) to port number (int)*/
    if ((sin.sin_port = htons(port)) == 0) {
        SSCP_ERRLOG("can't get \"%d\" port number\n", port);
        return ERR_TCP;
    }

    sin.sin_addr.s_addr = inet_addr(host);

    /* Allocate a socket */
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        SSCP_ERRLOG("can't create socket: %s\n", strerror(errno));
        return ERR_TCP;
    }

    evutil_make_socket_nonblocking(sock);

    p_peer->listener_fd = sock;

    // TODO do we need it for client?
    /*
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0) {
        close(socket);
        return 1;
    }
    */

    /* Connect the socket */
    ret = connect(sock, (struct sockaddr *)&sin, sizeof(sin));

    if (ret < 0) {
        if (errno == EINPROGRESS) {
			struct timeval l_connect_timeout;
            int l_fds, max_fd;
            fd_set filedes_set;
            l_connect_timeout.tv_sec=0;
            l_connect_timeout.tv_usec=10000;

            FD_ZERO(&filedes_set);
            max_fd = sock;
            FD_SET(sock, &filedes_set);

			while (retry_attempts < MAX_SELECT_ATTEMPTS) {
                l_fds = select(max_fd + 1, NULL, &filedes_set, NULL, &l_connect_timeout);
                if (l_fds == 0) { //timed out
                    printf("select timeout failure %d\n", errno);
                } else if(l_fds < 0) { //select failed
                    printf("select failure %d\n", errno);
                    return 1;
                } else {
                    int l_sock_optval = -1;
                    int l_sock_optval_len = sizeof(l_sock_optval);

                    if(getsockopt(sock, SOL_SOCKET, SO_ERROR, (int*)&l_sock_optval, (socklen_t*)&l_sock_optval_len) !=0) {
                        printf("connect failure %d\n", errno);
                        return 1;
                    }

                    if(l_sock_optval == 0) {
                        //connected to server
                        retry_attempts = 0;
                        break;
                    }
                }

                retry_attempts++;
            }
        }
	}

    return 0;
}

void
bev_ssl_readcb(struct bufferevent *bev, void *arg)
{
    printf("got message...\n");
}

void
bev_ssl_writecb(struct bufferevent *bev, void *arg)
{
    printf("writing to buffer\n");
}

void
bev_ssl_eventcb(struct bufferevent *bev, short event, void *arg)
{
}

void
delete_ssl_peer(t_peer *p_peer)
{
    SSL                 *ssl;
    evutil_socket_t     fd = -1;
    int                 ret;

    if (p_peer->bev == NULL) {
        return;
    }

    ssl = bufferevent_openssl_get_ssl(p_peer->bev);

    //SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN);
    SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
    //SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);

    printf("SSL %p\n", ssl);
    ret = SSL_shutdown(ssl);
    printf("SSL %p\n", ssl);
    printf("SSL Err: %d\n", SSL_get_error(ssl, ret));
    if (ret == 0) {
        printf("Sending another ssl shutdown.\n");
        ret = SSL_shutdown(ssl);
        printf("SSL Err: %d\n", SSL_get_error(ssl, ret));
    }

    //SSL_free(ssl);
    p_peer->ssl = NULL;

    //bufferevent_setcb(p_peer->bev, NULL, NULL, NULL, NULL);
    bufferevent_free(p_peer->bev);
    p_peer->bev = NULL;

    if (ssl) {
        printf("Freeing SSL\n");
        //SSL_free(ssl);
    }

    if (p_peer->listener_fd >= 0) {
        close(p_peer->listener_fd);
    }

    free(p_peer);
    p_peer = NULL;
}


static void
evbuffer_cleanup(const void *data, size_t len, void *arg)
{
    if (arg != NULL) {
        printf("Freeing up...\n");
        free(arg);
    }
}

static void
msg_timer_cb(int sock, short which, void *arg)
{
    struct evbuffer     *p_outbuf;
    t_peer              *p_peer = (t_peer *) arg;

    char *str = calloc(LINELEN, sizeof(char));
    char buf[LINELEN];

    snprintf(buf, sizeof(buf), "msg: %d", count);
    strncpy(str, buf, LINELEN);

    if (p_peer == NULL) {
        printf("No peer, not sending hello.\n");
        return;
    }

    if (!evtimer_pending(p_peer->timer_ev, NULL)) {
        event_del(p_peer->timer_ev);
        p_outbuf = bufferevent_get_output(p_peer->bev);
        evbuffer_add_reference(p_outbuf, str, LINELEN, evbuffer_cleanup, str);
        printf("Sending msg: %d\n", count++);
        if (count % 5 == 0) {
            delete_ssl_peer(p_peer);
        } else {
            evtimer_add(p_peer->timer_ev, &p_peer->tv);
        }
    }
}

int
create_ssl_client(t_wan_intf_node *p_wan_intf)
{
    t_cpmgr_ctx             *p_cpmgr_ctx = cpmgr_get_ctx();
    t_peer                  *p_peer = g_peer;
    int                     ret, err;
    
    if (!p_cpmgr_ctx->tls_client_ctx) {
        create_tls_client_ctx();
    }

    p_peer = calloc(1, sizeof(t_peer));
    // using default context
    //p_peer->ctx = client_ctx;
    /*
     * In general, an application will create just one SSL_CTX object for all of the connections it makes. From this SSL_CTX object,
     * an SSL type object can be created with the SSL_new function. This function causes the newly created SSL object to inherit all
     * of the parameters set forth in the context.
     */
    p_peer->ssl = SSL_new(p_cpmgr_ctx->tls_client_ctx);

    //  tcp connection
    if (connectsock(p_peer, host, port) != ERR_OK) {
        printf("Error in tcp connection.\n");
        return ERR_TCP;
    }

    printf("Connected to host %s on %d\n", host, p_peer->listener_fd);

    if (!(ret = SSL_set_fd(p_peer->ssl, p_peer->listener_fd))) {
        printf("SSL error: %d setting fd.", SSL_get_error(p_peer->ssl, ret));
    }

    // enable ssl communication
    // TODO in viptela we don't use it but free it, probably being used only for dtls
    //p_peer->sbio = BIO_new_socket(sock, BIO_NOCLOSE);
    //SSL_set_bio(p_peer->ssl, p_peer->sbio, p_peer->sbio);

    printf("Trying SSL connect again.\n");
    ret = SSL_connect(p_peer->ssl);
    printf("%d", ret);
    while (!(ret = SSL_connect(p_peer->ssl))) {
        err = SSL_get_error(p_peer->ssl, ret);
        if (err == SSL_ERROR_WANT_READ    ||
                   SSL_ERROR_WANT_WRITE   ||
                   SSL_ERROR_WANT_CONNECT) {
            printf("SSL connect error %d", err);
        } else {
            printf("SSL connect error.\n");
            return 1;
        }
    }

    printf("SSL connect successfull..\n");

    // we should probably put -1 as socket as the socket already present in p_peer->ssl
    // For socket-based bufferevent if the SSL object already has a socket set, you do not need to provide the socket: just pass -1.
    // TODO In viptela we're not using BEV_OPT_CLOSE_ON_FREE as option
    //p_peer->bev = bufferevent_openssl_socket_new(evbase, -1, p_peer->ssl, BUFFEREVENT_SSL_OPEN, BEV_OPT_CLOSE_ON_FREE);
    p_peer->bev = bufferevent_openssl_socket_new(p_cpmgr_ctx->event_base, -1, p_peer->ssl, BUFFEREVENT_SSL_OPEN, 0);

    // once we have bev we don't need the SSL pointer as bev will have the SSL
    p_peer->ssl = NULL;

    bufferevent_enable(p_peer->bev, EV_READ | EV_WRITE);

    bufferevent_setcb(p_peer->bev, bev_ssl_readcb, bev_ssl_writecb, bev_ssl_eventcb, NULL);

    p_peer->tv.tv_sec = MSG_SEND_INTERVAL_SEC;
    p_peer->tv.tv_usec = MSG_SEND_INTERVAL_MSEC;

    p_peer->timer_ev = evtimer_new(p_cpmgr_ctx->event_base, msg_timer_cb, p_peer);

    evtimer_add(p_peer->timer_ev, &p_peer->tv);

    return 0;
}
