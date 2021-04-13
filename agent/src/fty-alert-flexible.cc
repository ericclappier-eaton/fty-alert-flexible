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

#include "fty_alert_flexible_classes.h"
#include "fty_alert_flexible_audit_log.h"

#define ACTOR_NAME      "fty-alert-flexible"
#define ENDPOINT        "ipc://@/malamute"
#define RULES_DIR       "/var/lib/fty/fty-alert-flexible/rules"
#define CONFIG          "/etc/fty-alert-flexible/fty-alert-flexible.cfg"
#define METRICS_PATTERN ".*"
#define ASSETS_PATTERN  ".*"
#define LOG_CONFIG      "/etc/fty/ftylog.cfg"

static const char*
s_get (zconfig_t *config, const char* key, const char*dfl) {
    assert (config);
    const char *ret = (const char *)zconfig_get (config, key, dfl);
    if (!ret || streq (ret, ""))
        return dfl;
    return ret;
}

int main (int argc, char *argv [])
{
    const char * logConfigFile = FTY_COMMON_LOGGING_DEFAULT_CFG;
    ftylog_setInstance("fty-alert-flexible","");
    bool  verbose               = false;
    const char *endpoint        = ENDPOINT;
    bool isCmdEndpoint           = false;
    const char *config_file     = CONFIG;
    const char *rules           = RULES_DIR;
    bool isCmdRules              = false;
    const char *metrics_pattern = METRICS_PATTERN;
    const char *assets_pattern = ASSETS_PATTERN;

    int argn;
    for (argn = 1; argn < argc; argn++) {
        const char *param = NULL;
        if (argn < argc - 1) param = argv [argn+1];

        if (streq (argv [argn], "--help")
        ||  streq (argv [argn], "-h")) {
            puts ("fty-alert-flexible [options] ...");
            puts ("  -v|--verbose          verbose test output");
            puts ("  -h|--help             this information");
            puts ("  -e|--endpoint         malamute endpoint [ipc://@/malamute]");
            puts ("  -r|--rules            directory with rules [./rules]");
            puts ("  -c|--config           path to config file[/etc/fty-alert-flexible/fty-alert-flexible.cfg]\n");
            return 0;
        }
        else if (streq (argv [argn], "--verbose") || streq (argv [argn], "-v")) {
            verbose = true;
        }
        else if (streq (argv [argn], "--endpoint") || streq (argv [argn], "-e")) {
            if (param) {
                endpoint = param;
                isCmdEndpoint = true;
            }
            ++argn;
        }
        else if (streq (argv [argn], "--rules") || streq (argv [argn], "-r")) {
            if (param) {
                rules = param;
                isCmdRules = true;
            }
            ++argn;
        }
        else if (streq (argv [argn], "--config") || streq (argv [argn], "-c")) {
            if (param) config_file = param;
            ++argn;
        }
        else {
            printf ("Unknown option: %s\n", argv [argn]);
            return 1;
        }
    }
    //parse config file
    zconfig_t *config = zconfig_load(config_file);
    if (config) {
        // verbose
        if (streq (zconfig_get (config, "server/verbose", (verbose?"1":"0")), "1")) {
            verbose = true;
        }
        //rules
        if (!isCmdRules){
            rules = s_get (config, "server/rules", rules);
        }

        // endpoint
        if (!isCmdEndpoint){
            endpoint = s_get (config, "malamute/endpoint", endpoint);
        }

        // patterns
        assets_pattern = s_get (config, "malamute/assets_pattern", assets_pattern);
        metrics_pattern = s_get (config, "malamute/metrics_pattern", metrics_pattern);

        logConfigFile = s_get (config, "log/config", "");
    } else {
        log_error ("Failed to load config file %s",config_file);
    }

    if (!streq(logConfigFile, ""))
    {
        log_debug("Try to load log4cplus configuration file : %s", logConfigFile);
        ftylog_setConfigFile(ftylog_getInstance(), logConfigFile);

        // initialize log for auditability
        AlertsFlexibleAuditLogManager::init(logConfigFile);
    }

    if (verbose)
        ftylog_setVeboseMode(ftylog_getInstance());

    log_debug ("fty_alert_flexible - started");
    //  Insert main code here
    zlist_t *params = zlist_new ();
    zlist_append (params, (void*) assets_pattern);
    zlist_append (params, (void*) metrics_pattern);

    zactor_t *server = zactor_new (flexible_alert_actor, (void*) params);
    assert (server);
    zstr_sendx (server, "BIND", endpoint, ACTOR_NAME, NULL);
    zstr_sendx (server, "PRODUCER", FTY_PROTO_STREAM_ALERTS_SYS, NULL);
    //zstr_sendx (server, "CONSUMER", FTY_PROTO_STREAM_METRICS, metrics_pattern, NULL);
    zstr_sendx (server, "CONSUMER", FTY_PROTO_STREAM_METRICS_SENSOR, "status.*", NULL);
    zstr_sendx (server, "CONSUMER", FTY_PROTO_STREAM_ASSETS, ".*", NULL);

    // Note: 'licensing.expire.*' pattern don't work ! (nothing appears on stream) BUT IT SHOULD WORK
    // TODO: investigate on regex with malamute/zmq
    // Was: zstr_sendx (server, "CONSUMER", FTY_PROTO_STREAM_LICENSING_ANNOUNCEMENTS, "licensing.expire.*", NULL);
    zstr_sendx (server, "CONSUMER", FTY_PROTO_STREAM_LICENSING_ANNOUNCEMENTS, ".*", NULL);

    zstr_sendx (server, "LOADRULES", rules, NULL);

    while (!zsys_interrupted) {
        zmsg_t *msg = zactor_recv (server);
        zmsg_destroy (&msg);
    }
    log_debug ("fty_alert_flexible - exited");
    zactor_destroy (&server);

    // release audit context
    AlertsFlexibleAuditLogManager::deinit();

    return 0;
}
