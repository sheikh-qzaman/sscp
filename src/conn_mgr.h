#ifndef __CONN_MGR_H__
#define __CONN_MGR_H__

#include <transport.h>

e_err tcp_listener_create(t_wan_intf_node *p_wan_intf);
void ssl_acceptcb(struct evconnlistener *serv, int sock, struct sockaddr *sa, int sa_len, void *arg);
void tls_eventcb(struct bufferevent *bev, short event, void *ctx);
void tls_writecb(struct bufferevent *bev, void *ctx);

#endif
