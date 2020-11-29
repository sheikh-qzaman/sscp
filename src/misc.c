#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#include <sscp.h>
#include <common.h>
#include <logging.h>

void
set_config_params(int argc, char *argv[], t_init_cfg *cfg)
{
    char ch;

    memset(cfg, 0, sizeof(*cfg));

    while ((ch = getopt(argc, argv, ":pcsd:itu")) != -1) {
        switch(ch) {
            case 'c':
                cfg->oper_mode = MODE_CLIENT;
                SSCP_DEBUGLOG("Oper Mode: %d", cfg->oper_mode);
                break;
            case 'd':
                break;
            case 'i':
                break;
            case 'p':
                cfg->trans_proto = atoi(optarg);
                SSCP_DEBUGLOG("Proto: %d", cfg->trans_proto);
                break;
            case 's':
                cfg->oper_mode = MODE_SERVER;
                SSCP_DEBUGLOG("Oper Mode: %d", cfg->oper_mode);
                break;
            default:
                exit(1);
        }
    }
}

