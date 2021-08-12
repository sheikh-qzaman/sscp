bin_PROGRAMS = sscp
sscp_SOURCES = sscp.c misc.c conn_mgr.c ssl_utils.c client.c peer.c timer.c\
			   sscp.h logging.h conn_mgr.h ssl_utils.h ip_util.h timer.h \
			   transport.h globals.h common.h client.h peer.h

AM_CFLAGS   = -Wall -Wextra -Wunused-parameter -g -O0 -levent -lcrypto -lssl -levent_openssl
