/*  =========================================================================
    fty_alert_flexible - description

    Copyright (C) 2016 - 2017 Tomas Halman

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
    =========================================================================
*/

/*
@header
    fty_alert_flexible - agent for creating / evaluating alerts
@discuss
@end
*/

#include "audit_log.h"
#include "flexible_alert.h"
#include <fty_log.h>
#include <fty_proto.h>
#include <fty_common_mlm.h>
#include <czmq.h>

#define ACTOR_NAME      "fty-alert-flexible"

#define RULES_DIR       "/var/lib/fty/fty-alert-flexible/rules"
#define CONFIG_FILE     "/etc/fty-alert-flexible/fty-alert-flexible.cfg"
#define METRICS_PATTERN ".*"
#define ASSETS_PATTERN  ".*"

static const char* s_zc_get(zconfig_t *config, const char* key, const char* dfl)
{
    if (!config) return dfl;
    const char *ret = reinterpret_cast<const char *>(zconfig_get(config, key, dfl));
    if (!ret || streq(ret, ""))
        return dfl;
    return ret;
}

int main (int argc, char *argv [])
{
    const char *endpoint        = MLM_ENDPOINT;
    const char *rules_dir       = RULES_DIR;
    const char *config_file     = CONFIG_FILE;
    const char *metrics_pattern = METRICS_PATTERN;
    const char *assets_pattern  = ASSETS_PATTERN;

    bool verbose = false;
    bool isArgEndpoint = false;
    bool isArgRules = false;

    for (int i = 1; i < argc; i++) {
        const std::string arg{argv[i]};
        const char *param = ((i + 1) < argc) ? argv[i + 1] : NULL;

        if (arg == "--help" || arg == "-h") {
            printf("%s [options] ...\n", argv[0]);
            printf("  -v|--verbose              verbose output\n");
            printf("  -h|--help                 this information\n");
            printf("  -e|--endpoint <endpoint>  malamute endpoint\n");
            printf("  -r|--rules <path>         rules directory\n");
            printf("  -c|--config <path>        config file\n");
            return EXIT_SUCCESS;
        }
        else if (arg == "--verbose" || arg == "-v") {
            verbose = true;
        }
        else if (arg == "--endpoint" || arg == "-e") {
            if (!param) {
                printf("ERROR: Missing parameter (option: %s)\n", arg.c_str());
                return EXIT_FAILURE;
            }
            endpoint = param;
            isArgEndpoint = true;
            i++;
        }
        else if (arg == "--rules" || arg == "-r") {
            if (!param) {
                printf("ERROR: Missing parameter (option: %s)\n", arg.c_str());
                return EXIT_FAILURE;
            }
            rules_dir = param;
            isArgRules = true;
            i++;
        }
        else if (arg == "--config" || arg == "-c") {
            if (!param) {
                printf("ERROR: Missing parameter (option: %s)\n", arg.c_str());
                return EXIT_FAILURE;
            }
            config_file = param;
            i++;
        }
        else {
            printf("Unknown option: %s\n", arg.c_str());
            return EXIT_FAILURE;
        }
    }

    ManageFtyLog::setInstanceFtylog(ACTOR_NAME, FTY_COMMON_LOGGING_DEFAULT_CFG);
    if (verbose) {
        ManageFtyLog::getInstanceFtylog()->setVerboseMode();
    }

    // parse config file
    zconfig_t *config = zconfig_load(config_file);
    if (config) {
        log_info("%s - Loading config file '%s'", ACTOR_NAME, config_file);

        // verbose
        if (streq(s_zc_get(config, "server/verbose", (verbose ? "1" : "0")), "1")) {
            verbose = true;
        }
        // rules
        if (!isArgRules){
            rules_dir = s_zc_get(config, "server/rules", rules_dir);
        }
        // patterns
        assets_pattern = s_zc_get(config, "server/assets_pattern", assets_pattern);
        metrics_pattern = s_zc_get(config, "server/metrics_pattern", metrics_pattern);
        // endpoint
        if (!isArgEndpoint){
            endpoint = s_zc_get(config, "malamute/endpoint", endpoint);
        }
    }
    else {
        log_error("%s - Failed to load config file %s", ACTOR_NAME, config_file);
    }

    // initialize log for auditability
    AuditLog::init(ACTOR_NAME);

    log_debug ("%s starting...", ACTOR_NAME);

    // create main actor
    zlist_t *server_args = zlist_new();
    if (!server_args) {
        log_fatal("%s - Failed to create args list", ACTOR_NAME);
        return EXIT_FAILURE;
    }
    zlist_append(server_args, const_cast<char*>(assets_pattern));
    zlist_append(server_args, const_cast<char*>(metrics_pattern));

    zactor_t *server = zactor_new(fty_flexible_alert_actor, server_args);
    if (!server) {
        zlist_destroy(&server_args);
        log_fatal("%s - Failed to create main actor", ACTOR_NAME);
        return EXIT_FAILURE;
    }

    // server config
    zstr_sendx(server, "CONNECT", endpoint, ACTOR_NAME, NULL);
    zstr_sendx(server, "PRODUCER", FTY_PROTO_STREAM_ALERTS_SYS, NULL);
    zstr_sendx(server, "CONSUMER", FTY_PROTO_STREAM_ASSETS, ".*", NULL);

    // Note: 'licensing.expire.*' pattern don't work ! (nothing appears on stream) BUT IT SHOULD WORK
    // TODO: investigate on regex with malamute/zmq
    // Was: zstr_sendx (server, "CONSUMER", FTY_PROTO_STREAM_LICENSING_ANNOUNCEMENTS, "licensing.expire.*", NULL);
    zstr_sendx(server, "CONSUMER", FTY_PROTO_STREAM_LICENSING_ANNOUNCEMENTS, ".*", NULL);

    zstr_sendx(server, "LOADRULES", rules_dir, NULL);

    log_info("%s started", ACTOR_NAME);

    // main loop, accept any message back from server
    // copy from src/malamute.c under MPL license
    while (!zsys_interrupted) {
        char* msg = zstr_recv(server);
        if (!msg)
            break;

        log_debug("%s: recv msg '%s'", ACTOR_NAME, msg);
        zstr_free(&msg);
    }

    log_info("%s ended", ACTOR_NAME);

    zactor_destroy(&server);
    zlist_destroy(&server_args);
    zconfig_destroy(&config);

    // release audit context
    AuditLog::deinit();

    return EXIT_SUCCESS;
}
