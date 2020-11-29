#ifndef __IP_UTIL_H__
#define __IP_UTIL_H__

#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>

#define IPV4_ADDR_LEN       32
#define IPV6_ADDR_LEN       128
#define IPV4_PREFIX_LEN     32
#define IPV6_PREFIX_LEN    	128

typedef enum e_ipaddr_type
{
    IP_ADDR_UNKNOWN = 0,
    IP_ADDR_V4 = AF_INET,
    IP_ADDR_V6 = AF_INET6,
} e_ipaddr_type;

typedef struct t_ipaddr
{
#define IPADDR_IS_V4(p)           ((p)->addr_type == IP_ADDR_V4)
#define IPADDR_IS_V6(p)           ((p)->addr_type == IP_ADDR_V6)
    e_ipaddr_type   addr_type;
    union
    {
        struct in_addr  addr4;      /* network order    */
        uint64_t        addr6[2];   /* network order */
        uint8_t         addr6_b[IPV6_ADDR_LEN];
        uint16_t        addr16_b[8];
        uint32_t        addr32_b[4];
    } u;
#define v4addr          u.addr4.s_addr
#define v6addr          u.addr6
#define v6addr_bytes    u.addr6_b
#define v6addr_words    u.addr32_b
} t_ipaddr;

typedef struct t_ipaddr_port
{
#define IPPORT_ADDR_TYPE(p)         ((p)->addr.addr_type)
#define IPPORT_IS_V4(p)             (IPPORT_ADDR_TYPE(p) == IP_ADDR_V4)
#define IPPORT_IS_V6(p)             (IPPORT_ADDR_TYPE(p) == IP_ADDR_V6)
    t_ipaddr     addr;
    in_port_t    port;              /* network order */
} t_ipaddr_port;

static inline void IPADDR_SET_V4(t_ipaddr *p_ip, in_addr_t val)
{
        p_ip->addr_type = IP_ADDR_V4;
        p_ip->v4addr    = val;
}

static inline void IPADDR_INIT(t_ipaddr *p_ip, e_ipaddr_type type)
{
        memset(p_ip, 0, sizeof(t_ipaddr));
        p_ip->addr_type = type;
}

static inline char *
get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen)
{
    switch(sa->sa_family) {
        case AF_INET:
            inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
                    s, maxlen);
            break;

        case AF_INET6:
            inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
                    s, maxlen);
            break;

        default:
            strncpy(s, "Unknown AF", maxlen);
            return NULL;
    }

    return s;
}

#endif
