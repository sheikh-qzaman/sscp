#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#include <sscp.h>
#include <sscp_debug.h>

void
set_config_params(int argc, char *argv[], t_init_cfg *cfg)
{
    char ch;

    memset(cfg, 0, sizeof(*cfg));

    while ((ch = getopt(argc, argv, ":p:cd")) != -1) {
        switch(ch) {
            case 'c':
                break;
            case 'd':
                break;
            case 'p':
                cfg->t_proto = atoi(optarg);
                SSCP_DEBUGLOG("Proto: %d", cfg->t_proto);
                break;
            default:
                exit(1);
        }
    }
}

