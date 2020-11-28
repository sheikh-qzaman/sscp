bin_PROGRAMS = sscp
sscp_SOURCES = sscp.c sscp_misc.c conn_mgr.c ssl_utils.c\
			   sscp.h logging.h conn_mgr.h ssl_utils.h\
			   transport.h globals.h

AM_CFLAGS   = -Wall -Wextra -Wunused-parameter -g -O0 -levent -lcrypto -lssl -levent_openssl
