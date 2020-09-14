#include <sscp.h>

int
main()
{
    SSCP_SYSLOG_INIT("SSCP");
    SSCP_DEBUGLOG("Secure Scalabale Control Plane.\n");
    SSCP_SYSLOG_DONE();
}
