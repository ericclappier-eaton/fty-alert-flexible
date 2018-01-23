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

static const char *ACTOR_NAME = "fty-alert-flexible";
static const char *ENDPOINT = "ipc://@/malamute";
static const char *RULES_DIR = "./rules";

int main (int argc, char *argv [])
{
    bool verbose = false;
    int argn;
    for (argn = 1; argn < argc; argn++) {
        const char *param = NULL;
        if (argn < argc - 1) param = argv [argn+1];

        if (streq (argv [argn], "--help")
        ||  streq (argv [argn], "-h")) {
            puts ("fty-alert-flexible [options] ...");
            puts ("  --verbose / -v         verbose test output");
            puts ("  --help / -h            this information");
            puts ("  --endpoint / -e        malamute endpoint [ipc://@/malamute]");
            puts ("  --rules / -r           directory with rules [./rules]");
            return 0;
        }
        else if (streq (argv [argn], "--verbose") || streq (argv [argn], "-v")) {
            verbose = true;
        }
        else if (streq (argv [argn], "--endpoint") || streq (argv [argn], "-e")) {
            if (param) ENDPOINT = param;
            ++argn;
        }
        else if (streq (argv [argn], "--rules") || streq (argv [argn], "-r")) {
            if (param) RULES_DIR = param;
            ++argn;
        }
        else {
            printf ("Unknown option: %s\n", argv [argn]);
            return 1;
        }
    }
    //  Insert main code here
    if (verbose)
        zsys_info ("fty_alert_flexible - started");
    zactor_t *server = zactor_new (flexible_alert_actor, NULL);
    assert (server);
    zstr_sendx (server, "BIND", ENDPOINT, ACTOR_NAME, NULL);
    zstr_sendx (server, "PRODUCER", FTY_PROTO_STREAM_ALERTS_SYS, NULL);
    zstr_sendx (server, "CONSUMER", FTY_PROTO_STREAM_METRICS, ".*@sts-.*", NULL);
    zstr_sendx (server, "CONSUMER", FTY_PROTO_STREAM_METRICS_SENSOR, "status.*", NULL);
    zstr_sendx (server, "CONSUMER", FTY_PROTO_STREAM_ASSETS, ".*", NULL);
    zstr_sendx (server, "LOADRULES", RULES_DIR, NULL);
    if (verbose)
        zstr_sendx (server, "VERBOSE", NULL);

    while (!zsys_interrupted) {
        zmsg_t *msg = zactor_recv (server);
        zmsg_destroy (&msg);
    }
    zactor_destroy (&server);
    if (verbose)
        zsys_info ("fty_alert_flexible - exited");

    return 0;
}
