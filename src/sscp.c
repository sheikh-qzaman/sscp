#include <string.h>

#include <sscp.h>

int
main(int argc, char *argv[])
{
    t_init_cfg              cfg;

    SSCP_SYSLOG_INIT("SSCP");
    SSCP_DEBUGLOG("Secure Scalabale Control Plane.");
    SSCP_SYSLOG_DONE();
    
    memset(&cfg, 0x0, sizeof(t_init_cfg));
    set_config_params(argc, argv, &cfg);

    SSCP_DEBUGLOG("Protocol selected %d.", cfg.t_proto);
}
