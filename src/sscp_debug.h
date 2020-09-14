#ifndef __SSCP_DEBUG_H__
#define __SSCP_DEBUG_H__

#include <syslog.h>

#define SSCP_SYSLOG_INIT(progname)                                   		\
{                                                                       	\
    openlog(progname, LOG_NDELAY|LOG_PID, LOG_LOCAL7);                  	\
}

#define SSCP_SYSLOG_DONE()                                           	\
{                                                                       	\
    closelog();                                                         	\
}

#define SSCP_DEBUGLOG(fmt, args...)                                   		\
{                                                                        	\
    syslog(LOG_DEBUG | LOG_LOCAL7, "%s[%d]: " fmt, __FUNCTION__, __LINE__, 	\
                ##args);                                                 	\
}

#define SSCP_INFOLOG(fmt, args...)                                   		\
{                                                                        	\
    syslog(LOG_INFO | LOG_LOCAL7, "%s[%d]: " fmt, __FUNCTION__, __LINE__, 	\
                ##args);                                                 	\
}

#define SSCP_ERRLOG(fmt, args...)                                   		\
{                                                                        	\
    syslog(LOG_ERR | LOG_LOCAL7, "%s[%d]: " fmt, __FUNCTION__, __LINE__, 	\
                ##args);                                                 	\
}

#endif
