/*  =========================================================================
    flexible_alert - Main class for evaluating alerts

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
    flexible_alert - Main class for evaluating alerts
@discuss
@end
*/

#include "fty_alert_flexible_classes.h"

//  Structure of our class

struct _flexible_alert_t {
    zhash_t *rules;
    zhash_t *assets;
    zhash_t *metrics;
    zhash_t *enames;
    mlm_client_t *mlm;
    bool verbose;
};

static void rule_freefn (void *rule)
{
    if (rule) {
        rule_t *self = (rule_t *) rule;
        rule_destroy (&self);
    }
}

static void asset_freefn (void *asset)
{
    if (asset) {
        zlist_t *self = (zlist_t *) asset;
        zlist_destroy (&self);
    }
}

void ftymsg_freefn (void *ptr)
{
    if (!ptr) return;
    fty_proto_t *fty = (fty_proto_t *)ptr;
    fty_proto_destroy (&fty);
}

static void ename_freefn (void *ename)
{
    if (ename) free (ename);
}

//  --------------------------------------------------------------------------
//  Create a new flexible_alert

flexible_alert_t *
flexible_alert_new (void)
{
    flexible_alert_t *self = (flexible_alert_t *) zmalloc (sizeof (flexible_alert_t));
    assert (self);
    //  Initialize class properties here
    self->rules = zhash_new ();
    self->assets = zhash_new ();
    self->metrics = zhash_new ();
    self->enames = zhash_new ();
    zhash_autofree (self->enames);
    self->mlm = mlm_client_new ();
    self->verbose = false;
    return self;
}

//  --------------------------------------------------------------------------
//  Destroy the flexible_alert

void
flexible_alert_destroy (flexible_alert_t **self_p)
{
    assert (self_p);
    if (*self_p) {
        flexible_alert_t *self = *self_p;
        //  Free class properties here
        zhash_destroy (&self->rules);
        zhash_destroy (&self->assets);
        zhash_destroy (&self->metrics);
        zhash_destroy (&self->enames);
        mlm_client_destroy (&self->mlm);
        //  Free object itself
        free (self);
        *self_p = NULL;
    }
}

//  --------------------------------------------------------------------------
//  Load all rules in directory. Rule MUST have ".rule" extension.

void
flexible_alert_load_one_rule (flexible_alert_t *self, const char *fullpath)
{
    rule_t *rule = rule_new();
    if (rule_load (rule, fullpath) == 0) {
        zsys_debug ("rule %s loaded", fullpath);
        zhash_update (self->rules, rule_name (rule), rule);
        zhash_freefn (self->rules, rule_name (rule), rule_freefn);
    } else {
        zsys_error ("failed to load rule '%s'", fullpath);
        rule_destroy (&rule);
    }
}

//  --------------------------------------------------------------------------
//  Load all rules in directory. Rule MUST have ".rule" extension.

void
flexible_alert_load_rules (flexible_alert_t *self, const char *path)
{
    if (!self || !path) return;
    char fullpath [PATH_MAX];

    DIR *dir = opendir(path);
    if (!dir) {
        zsys_error ("cannot open rule dir '%s'", path);
        return;
    }
    struct dirent * entry;
    while ((entry = readdir(dir)) != NULL) {
        zsys_debug ("checking dir entry %s type %i", entry -> d_name, entry -> d_type);
        if (entry -> d_type == DT_LNK || entry -> d_type == DT_REG || entry -> d_type == 0) {
            // file or link
            int l = strlen (entry -> d_name);
            zsys_debug ("loading rule file: %s", entry -> d_name);
            if ( l > 5 && streq (&(entry -> d_name[l - 5]), ".rule")) {
                // json file
                snprintf (fullpath, PATH_MAX, "%s/%s", path, entry -> d_name);
                flexible_alert_load_one_rule (self, fullpath);
            }
        }
    }
    closedir(dir);
}

void
flexible_alert_send_alert (flexible_alert_t *self, const char *rulename, zlist_t *actions, const char *asset, int result, const char *message, int ttl)
{
    char *severity = "OK";
    if (result == -1 || result == 1) severity = "WARNING";
    if (result == -2 || result == 2) severity = "CRITICAL";

    // topic
    char *topic = zsys_sprintf ("%s/%s@%s", rulename, severity, asset);

    // message
    zmsg_t *alert = fty_proto_encode_alert (
        NULL,
        time(NULL),
        ttl,
        rulename,
        asset,
        result == 0 ? "RESOLVED" : "ACTIVE",
        severity,
        message,
        actions); // action list

    mlm_client_send (self -> mlm, topic, &alert);

    zstr_free (&topic);
    zmsg_destroy (&alert);
}


void
flexible_alert_evaluate (flexible_alert_t *self, rule_t *rule, const char *assetname, const char *ename)
{
    zlist_t *params = zlist_new ();
    zlist_autofree (params);

    // prepare lua function parameters
    int ttl = 0;

    const char *param = rule_metric_first (rule);
    while (param) {
        char *topic = zsys_sprintf ("%s@%s", param, assetname);
        fty_proto_t *ftymsg = (fty_proto_t *) zhash_lookup (self->metrics, topic);
        if (!ftymsg) {
            // some metrics are missing
            zlist_destroy (&params);
            zsys_debug ("missing metric %s", topic);
            zstr_free (&topic);
            return;
        }
        // TTL should be set accorning shortest ttl in metric
        if (ttl == 0 || ttl > fty_proto_ttl (ftymsg)) ttl = fty_proto_ttl (ftymsg);
        zstr_free (&topic);
        zlist_append (params, (char *) fty_proto_value (ftymsg));
        param = rule_metric_next (rule);
    }

    // call the lua function
    char *message;
    int result;

    rule_evaluate (rule, params, assetname, ename, &result, &message);
    if (result != RULE_ERROR);
    flexible_alert_send_alert (
        self,
        rule_name (rule),
        rule_result_actions (rule, result),
        assetname,
        result,
        message, ttl * 5 / 2
    );
    zstr_free (&message);
    zlist_destroy (&params);
}

//  --------------------------------------------------------------------------
//  drop expired metrics

void
flexible_alert_clean_metrics (flexible_alert_t *self)
{
    zlist_t *topics = zhash_keys (self->metrics);
    char *topic = (char *) zlist_first (topics);
    while (topic) {
        fty_proto_t *ftymsg = (fty_proto_t *) zhash_lookup (self->metrics, topic);
        if (fty_proto_time (ftymsg) + fty_proto_ttl (ftymsg) < time (NULL)) {
            zhash_delete (self->metrics, topic);
        }
        topic = (char *) zlist_next (topics);
    }
    zlist_destroy (&topics);
}


// --------------------------------------------------------------------------
// returns true if metric message belong to gpi sensor
bool
is_gpi_metric (fty_proto_t* metric)
{
    assert (metric);
    const char * port = fty_proto_aux_string (metric, FTY_PROTO_METRICS_AUX_PORT, "");
    if (strstr (port, "GPI"))
        return true;
    else
        return false;
}


//  --------------------------------------------------------------------------
//  Function handles incoming metrics, drives lua evaluation

void
flexible_alert_handle_metric (flexible_alert_t *self, fty_proto_t **ftymsg_p)
{
    if (!self || !ftymsg_p || !*ftymsg_p) return;
    fty_proto_t *ftymsg = *ftymsg_p;
    if (fty_proto_id (ftymsg) != FTY_PROTO_METRIC) return;

    if (zhash_lookup (self->metrics, mlm_client_subject (self->mlm))) {
        flexible_alert_clean_metrics (self);
    }

    const char *assetname = fty_proto_name (ftymsg);
    const char *quantity = fty_proto_type (ftymsg);
    const char *description = fty_proto_aux_string (ftymsg, "description", "");
    const char *ename = (const char *) zhash_lookup (self->enames, assetname);
    const char *extport = fty_proto_aux_string (ftymsg, "ext-port", NULL);
    char * qty_dup = (char *)quantity;

    // fix quantity for sensors connected to other sensors
    if (extport) {
        // only sensors connected to other sensors have ext-name set
        const char *qty_len_helper = quantity;
        // second . marks the length
        while ((*qty_len_helper != '\0') && (*qty_len_helper != '.')) ++qty_len_helper;
        ++qty_len_helper;
        if (qty_len_helper == '\0') return; // malformed quantity
        while ((*qty_len_helper != '\0') && (*qty_len_helper != '.')) ++qty_len_helper;
        qty_dup = strndup(quantity, qty_len_helper - quantity);
    }

    // produce nagios style alerts
    if (strncmp (quantity, "nagios.", 7) == 0 && strlen (description)) {
        int ivalue = atoi (fty_proto_value (ftymsg));
        if (ivalue >=0 && ivalue <=2) {
            flexible_alert_send_alert (
                self,
                quantity,
                NULL,
                fty_proto_name (ftymsg),
                ivalue,
                description,
                fty_proto_ttl (ftymsg)
            );
            if (extport) {
                free(qty_dup);
            }
            return;
        }
    }
    zlist_t *functions_for_asset = (zlist_t *) zhash_lookup (self->assets, assetname);
    if (! functions_for_asset) {
        if (extport) {
            free(qty_dup);
        }
        return;
    }

    // this asset has some evaluation functions
    char *func = (char *) zlist_first (functions_for_asset);
    bool metric_saved =  false;
    while (func) {
        rule_t *rule = (rule_t *) zhash_lookup (self -> rules, func);
        if (rule_metric_exists (rule, qty_dup)) {
            // we have to evaluate this function for our asset
            // save metric into cache
            if (! metric_saved) {
                fty_proto_set_time (ftymsg, time (NULL));
                char *topic = zsys_sprintf ("%s@%s", qty_dup, assetname);
                zhash_update (self->metrics, topic, ftymsg);
                zhash_freefn (self->metrics, topic, ftymsg_freefn);
                *ftymsg_p = NULL;
                zstr_free (&topic);
                metric_saved = true;
            }
            // evaluate
            flexible_alert_evaluate (self, rule, assetname, ename);
        }
        func = (char *) zlist_next (functions_for_asset);
    }
    if (extport) {
        free(qty_dup);
    }
}

int
ask_for_sensor (flexible_alert_t *self, const char* sensor_name)
{

    if (!zhash_lookup (self->assets, sensor_name))
    {
        if (self->verbose)
            zsys_info ("I have to ask for sensor  %s", sensor_name);

        zmsg_t *msg = zmsg_new ();
        zmsg_addstr (msg, "REPUBLISH");
        zmsg_addstr (msg, sensor_name);

        int rv = mlm_client_sendto (self->mlm, "asset-agent", "REPUBLISH" , NULL, 5000, &msg);
        if (rv != 0)
        {
            zsys_error ("mlm_client_sendto (address = '%s', subject = '%s', timeout = '5000') for '%s' failed.",
                        "asset-agent", "REPUBLISH", sensor_name);
        }
        return rv;
    }
    if (self->verbose)
        zsys_info ("I know this sensor %s", sensor_name);
    return 0;
}

//  --------------------------------------------------------------------------
//  Function handles infoming metric sensors, fix message and pass it to metrics evaluation

void
flexible_alert_handle_metric_sensor (flexible_alert_t *self, fty_proto_t **ftymsg_p)
{
    if (!self || !ftymsg_p || !*ftymsg_p) return;
    fty_proto_t *ftymsg = *ftymsg_p;
    if (fty_proto_id (ftymsg) != FTY_PROTO_METRIC) return;

    // get name of asset based on GPIO port
    const char *sensor_name = fty_proto_aux_string (ftymsg, FTY_PROTO_METRICS_SENSOR_AUX_SNAME, NULL);
    if (!sensor_name) {
        zsys_debug ("No sensor name provided in sensor message");
        return;
    }

    ask_for_sensor (self, sensor_name);
    fty_proto_set_name (ftymsg, "%s", sensor_name);
    flexible_alert_handle_metric(self, ftymsg_p);
}

//  --------------------------------------------------------------------------
//  Function returns true if function should be evaluated for particular asset.
//  This is decided by asset name (json "assets": []) or group (json "groups":[])

static int
is_rule_for_this_asset (rule_t *rule, fty_proto_t *ftymsg)
{
    if (!rule || !ftymsg) return 0;

    const char *subtype = fty_proto_aux_string (ftymsg, FTY_PROTO_ASSET_SUBTYPE, "");
    if (streq (subtype, "sensorgpio") )
    {
        if (rule_asset_exists (rule, fty_proto_name (ftymsg)) &&
            rule_model_exists (rule, fty_proto_ext_string (ftymsg, FTY_PROTO_ASSET_EXT_MODEL, "")) )
            return 1;
        else
            return 0;
    }

    if (rule_asset_exists (rule, fty_proto_name (ftymsg)))
        return 1;

    zhash_t *ext = fty_proto_ext (ftymsg);
    zlist_t *keys = zhash_keys (ext);
    char *key = (char *)zlist_first (keys);
    while (key) {
        if (strncmp ("group.", key, 6) == 0) {
            // this is group
            if (rule_group_exists (rule, (char *) zhash_lookup (ext, key))) {
                zlist_destroy (&keys);
                return 1;
            }
        }
        key = (char *)zlist_next (keys);
    }
    zlist_destroy (&keys);

    if (rule_model_exists (rule, fty_proto_ext_string (ftymsg, FTY_PROTO_ASSET_EXT_MODEL, "")))
        return 1;
    if (rule_model_exists (rule, fty_proto_ext_string (ftymsg, FTY_PROTO_ASSET_EXT_DEVICE_PART, "")))
        return 1;

    if (rule_type_exists (rule, fty_proto_aux_string (ftymsg, FTY_PROTO_ASSET_AUX_TYPE, "")))
        return 1;
    if (rule_type_exists (rule, fty_proto_aux_string (ftymsg, FTY_PROTO_ASSET_AUX_SUBTYPE, "")))
        return 1;

    return 0;
}

//  --------------------------------------------------------------------------
//  When asset message comes, function checks if we have rule for it and stores
//  list of rules valid for this asset.

void
flexible_alert_handle_asset (flexible_alert_t *self, fty_proto_t *ftymsg)
{
    if (!self || !ftymsg) return;
    if (fty_proto_id (ftymsg) != FTY_PROTO_ASSET) return;

    const char *operation = fty_proto_operation (ftymsg);
    const char *assetname = fty_proto_name (ftymsg);

    if (streq (operation, "delete")) {
        if (zhash_lookup (self->assets, assetname)) {
            zhash_delete (self->assets, assetname);
        }
        if (zhash_lookup (self->enames, assetname)) {
            zhash_delete (self->enames, assetname);
        }
        return;
    }
    if (streq (operation, "update") || streq (operation, "inventory")) {
        zlist_t *functions_for_asset = zlist_new ();
        zlist_autofree (functions_for_asset);

        rule_t *rule = (rule_t *)zhash_first (self->rules);
        while (rule) {
            if (is_rule_for_this_asset (rule, ftymsg)) {
                zlist_append (functions_for_asset, (char *)rule_name (rule));
                zsys_debug ("rule '%s' is valid for '%s'", rule_name (rule), assetname);
            }
            rule = (rule_t *)zhash_next (self->rules);
        }
        if (! zlist_size (functions_for_asset)) {
            zsys_debug ("no rule for %s", assetname);
            zhash_delete (self->assets, assetname);
            zlist_destroy (&functions_for_asset);
            return;
        }
        zhash_update (self->assets, assetname, functions_for_asset);
        zhash_freefn (self->assets, assetname, asset_freefn);
        const char *ename = fty_proto_ext_string (ftymsg, "name", NULL);
        if (ename) {
            zhash_update (self->enames, assetname, (void *)ename);
            zhash_freefn (self->enames, assetname, ename_freefn);
        }
    }

}

//  --------------------------------------------------------------------------
//  handling requests for list of rules.
//  type can be all or flexible in this agent
//  class is just for compatibility with alert engine protocol

zmsg_t *
flexible_alert_list_rules (flexible_alert_t *self, char *type, char *ruleclass)
{
    if (! self || ! type) return NULL;

    zmsg_t *reply = zmsg_new ();
    if (! streq (type, "all") && ! streq (type, "flexible")) {
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "INVALID_TYPE");
        return reply;
    }
    zmsg_addstr (reply, "LIST");
    zmsg_addstr (reply, type);
    zmsg_addstr (reply, ruleclass ? ruleclass : "");
    rule_t *rule = (rule_t *) zhash_first (self->rules);
    while (rule) {
        char *json = rule_json (rule);
        if (json) {
            char *uistyle = zsys_sprintf ("{\"flexible\": %s }", json);
            if (uistyle) {
                zmsg_addstr (reply, uistyle);
                zstr_free (&uistyle);
            }
            zstr_free (&json);
        }
        rule = (rule_t *) zhash_next (self->rules);
    }
    return reply;
}

//  --------------------------------------------------------------------------
//  handling requests for getting rule.

zmsg_t *
flexible_alert_get_rule (flexible_alert_t *self, char *name)
{
    if (! self || !name) return NULL;

    rule_t *rule = (rule_t *) zhash_lookup (self->rules, name);
    zmsg_t *reply = zmsg_new ();
    if (rule) {
        char *json = rule_json (rule);
        zmsg_addstr (reply, "OK");
        zmsg_addstr (reply, json);
        zstr_free (&json);
    } else {
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "NOT_FOUND");
    }
    return reply;
}

//  --------------------------------------------------------------------------
//  handling requests for deleting rule.

zmsg_t *
flexible_alert_delete_rule (flexible_alert_t *self, const char *name, const char *dir)
{
    if (! self || !name || !dir) return NULL;

    zmsg_t *reply = zmsg_new ();
    zmsg_addstr (reply, "DELETE");
    zmsg_addstr (reply, name);

    rule_t *rule = (rule_t *) zhash_lookup (self->rules, name);
    if (rule) {
        char *path = zsys_sprintf ("%s/%s.rule", dir, name);
        if (unlink (path) == 0) {
            zmsg_addstr (reply, "OK");
            zhash_delete (self->rules, name);
        } else {
            zsys_error ("Can't remove %s", path);
            zmsg_addstr (reply, "ERROR");
            zmsg_addstr (reply, "CAN_NOT_REMOVE");
        }
        zstr_free (&path);
    } else {
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "DOES_NOT_EXISTS");
    }
    return reply;
}

//  --------------------------------------------------------------------------
//  handling requests for adding rule.

zmsg_t *
flexible_alert_add_rule (flexible_alert_t *self, const char *json, const char *old_name, const char *dir)
{
    if (! self || !json || !dir) return NULL;

    rule_t *newrule = rule_new ();
    zmsg_t *reply = zmsg_new ();
    if(rule_parse (newrule, json) != 0) {
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "INVALID_JSON");
        rule_destroy (&newrule);
        return reply;
    };
    if (old_name) {
        zsys_info ("deleting rule %s", old_name);
        zmsg_t *msg = flexible_alert_delete_rule (self, old_name, dir);
        zmsg_destroy (&msg);
    }
    rule_t *rule = (rule_t *) zhash_lookup (self->rules, rule_name (newrule));
    if (rule && strstr (rule_name (rule), "sensorgpio") == NULL) {
        zsys_error ("Rule %s exists", rule_name (rule));
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "ALREADY_EXISTS");
    } else {
        char *path = zsys_sprintf ("%s/%s.rule", dir, rule_name(newrule));
        int x = rule_save (newrule, path);
        if ( x != 0) {
            zsys_error ("Error while saving rule %s (%i)", path, x);
            zmsg_addstr (reply, "ERROR");
            zmsg_addstr (reply, "SAVE_FAILURE");
        } else {
            zmsg_addstr (reply, "OK");
            zmsg_addstr (reply, json);
            zsys_info ("Loading rule %s", path);
            flexible_alert_load_one_rule (self, path);
            zsys_info ("Loading rule %s done", path);
        }
        zstr_free (&path);
    }

    rule_destroy (&newrule);
    return reply;
}

//  --------------------------------------------------------------------------
//  Actor running one instance of flexible alert class

void
flexible_alert_actor (zsock_t *pipe, void *args)
{
    flexible_alert_t *self = flexible_alert_new ();
    assert (self);
    zsock_signal (pipe, 0);
    char *ruledir = NULL;

    zpoller_t *poller = zpoller_new (mlm_client_msgpipe(self->mlm), pipe, NULL);
    while (!zsys_interrupted) {
        void *which = zpoller_wait (poller, -1);
        if (which == pipe) {
            zmsg_t *msg = zmsg_recv (pipe);
            char *cmd = zmsg_popstr (msg);
            if (cmd) {
                if (streq (cmd, "$TERM")) {
                    zstr_free (&cmd);
                    zmsg_destroy (&msg);
                    break;
                }
                else if (streq (cmd, "BIND")) {
                    char *endpoint = zmsg_popstr (msg);
                    char *myname = zmsg_popstr (msg);
                    assert (endpoint && myname);
                    mlm_client_connect (self->mlm, endpoint, 5000, myname);
                    zstr_free (&endpoint);
                    zstr_free (&myname);
                }
                else if (streq (cmd, "PRODUCER")) {
                    char *stream = zmsg_popstr (msg);
                    assert (stream);
                    mlm_client_set_producer (self->mlm, stream);
                    zstr_free (&stream);
                }
                else if (streq (cmd, "CONSUMER")) {
                    char *stream = zmsg_popstr (msg);
                    char *pattern = zmsg_popstr (msg);
                    assert (stream && pattern);
                    mlm_client_set_consumer (self->mlm, stream, pattern);
                    zstr_free (&stream);
                    zstr_free (&pattern);
                }
                else if (streq (cmd, "LOADRULES")) {
                    zstr_free (&ruledir);
                    ruledir = zmsg_popstr (msg);
                    assert (ruledir);
                    flexible_alert_load_rules (self, ruledir);
                }
                else if (streq (cmd, "VERBOSE")) {
                    self->verbose = true;
                }
                else {
                    zsys_debug ("Unknown command.");
                }

                zstr_free (&cmd);
            }
            zmsg_destroy (&msg);
        }
        else if (which == mlm_client_msgpipe (self->mlm)) {
            zmsg_t *msg = mlm_client_recv (self->mlm);
            if (is_fty_proto (msg)) {
                fty_proto_t *fmsg = fty_proto_decode (&msg);
                if (fty_proto_id (fmsg) == FTY_PROTO_ASSET) {
                    flexible_alert_handle_asset (self, fmsg);
                }
                if (fty_proto_id (fmsg) == FTY_PROTO_METRIC) {
                    const char *address = mlm_client_address(self->mlm);
                    if (0 == strcmp(address, FTY_PROTO_STREAM_METRICS)) {
                        // messages from FTY_PROTO_STREAM_METRICS are regular metrics
                        flexible_alert_handle_metric (self, &fmsg);
                    } else if (0 == strcmp(address, FTY_PROTO_STREAM_METRICS_SENSOR)) {
                        // messages from FTY_PROTO_STREAM_METRICS_SENSORS are gpi sensors
                        if (is_gpi_metric (fmsg))
                            flexible_alert_handle_metric_sensor (self, &fmsg);
                    } else {
                        zsys_debug("Message proto ID = FTY_PROTO_METRIC, message address not valid = '%s'", address);
                    }
                }
                fty_proto_destroy (&fmsg);
            } else if (streq (mlm_client_command (self->mlm), "MAILBOX DELIVER")) {
                // someone is addressing us directly
                // protocol frames COMMAND/param1/param2
                char *cmd = zmsg_popstr (msg);
                char *p1 = zmsg_popstr (msg);
                char *p2 = zmsg_popstr (msg);
                zmsg_t *reply = NULL;
                if (cmd) {
                    if (streq (cmd, "LIST")) {
                        // request: LIST/type/class
                        // reply: LIST/type/class/name1/name2/...nameX
                        // reply: ERROR/reason
                        reply = flexible_alert_list_rules (self, p1, p2);
                    }
                    else if (streq (cmd, "GET")) {
                        // request: GET/name
                        // reply: OK/rulejson
                        // reply: ERROR/reason
                        reply = flexible_alert_get_rule (self, p1);
                    }
                    else if (streq (cmd, "ADD")) {
                        // request: ADD/rulejson -- this is create
                        // request: ADD/rulejson/rulename -- this is replace
                        // reply: OK/rulejson
                        // reply: ERROR/reason
                        reply = flexible_alert_add_rule (self, p1, p2, ruledir);
                    }
                    else if (streq (cmd, "DELETE")) {
                        // request: DELETE/name
                        // reply: DELETE/name/OK
                        // reply: DELETE/name/ERROR/reason
                        reply = flexible_alert_delete_rule (self, p1, ruledir);
                    }
                }
                if (reply) {
                    mlm_client_sendto (
                        self->mlm,
                        mlm_client_sender (self->mlm),
                        mlm_client_subject (self->mlm),
                        mlm_client_tracker (self->mlm),
                        1000,
                        &reply
                    );
                    if (reply) {
                        zsys_error ("Failed to send LIST reply to %s", mlm_client_sender (self->mlm));
                        zmsg_destroy (&reply);
                    }
                }
                zstr_free (&cmd);
                zstr_free (&p1);
                zstr_free (&p2);
            }
            zmsg_destroy (&msg);
        }
    }
    zstr_free (&ruledir);
    zpoller_destroy (&poller);
    flexible_alert_destroy (&self);
}

//  --------------------------------------------------------------------------
//  Self test of this class

void
flexible_alert_test (bool verbose)
{
    printf (" * flexible_alert:\n");

    // Note: If your selftest reads SCMed fixture data, please keep it in
    // src/selftest-ro; if your test creates filesystem objects, please
    // do so under src/selftest-rw. They are defined below along with a
    // usecase (asert) to make compilers happy.
    const char *SELFTEST_DIR_RO = "src/selftest-ro";
    const char *SELFTEST_DIR_RW = "src/selftest-rw";
    assert (SELFTEST_DIR_RO);
    assert (SELFTEST_DIR_RW);
    // std::string str_SELFTEST_DIR_RO = std::string(SELFTEST_DIR_RO);
    // std::string str_SELFTEST_DIR_RW = std::string(SELFTEST_DIR_RW);

    //  @selftest
    //  Simple create/destroy test
    flexible_alert_t *self = flexible_alert_new ();
    assert (self);
    flexible_alert_destroy (&self);

    // start malamute
    static const char *endpoint = "inproc://fty-metric-snmp";
    zactor_t *malamute = zactor_new (mlm_server, (void*) "Malamute");
    zstr_sendx (malamute, "BIND", endpoint, NULL);
    if (verbose) zstr_send (malamute, "VERBOSE");

    // create flexible alert actor
    zactor_t *fs = zactor_new (flexible_alert_actor, NULL);
    assert (fs);
    zstr_sendx (fs, "BIND", endpoint, "me", NULL);
    zstr_sendx (fs, "PRODUCER", FTY_PROTO_STREAM_ALERTS_SYS, NULL);
    zstr_sendx (fs, "CONSUMER", FTY_PROTO_STREAM_ASSETS, ".*", NULL);
    zstr_sendx (fs, "CONSUMER", FTY_PROTO_STREAM_METRICS, ".*", NULL);
    zstr_sendx (fs, "CONSUMER", FTY_PROTO_STREAM_METRICS_SENSOR, ".*", NULL);
    char *rules_dir = zsys_sprintf ("%s/rules", SELFTEST_DIR_RO);
    assert (rules_dir != NULL);
    zstr_sendx (fs, "LOADRULES", rules_dir, NULL);
    zstr_free (&rules_dir);

    // create mlm client for interaction with actor
    mlm_client_t *asset = mlm_client_new ();
    mlm_client_connect (asset, endpoint, 5000, "asset-autoupdate");
    mlm_client_set_producer (asset, FTY_PROTO_STREAM_ASSETS);
    mlm_client_set_consumer (asset, FTY_PROTO_STREAM_ALERTS_SYS, ".*");

    // metric client
    mlm_client_t *metric = mlm_client_new ();
    mlm_client_connect (metric, endpoint, 5000, "metric");
    mlm_client_set_producer (metric, FTY_PROTO_STREAM_METRICS);

    // let malamute establish everything
    zclock_sleep (200);
    {
        zhash_t *ext = zhash_new();
        zhash_autofree (ext);
        zhash_insert (ext, "group.1", "all-upses");
        zhash_insert (ext, "name", "mý děvíce");
        zmsg_t *assetmsg = fty_proto_encode_asset (
            NULL,
            "mydevice",
            "update",
            ext
        );
        mlm_client_send (asset, "myasset", &assetmsg);
        zhash_destroy (&ext);
        zmsg_destroy (&assetmsg);
    }
    zclock_sleep (200);
    {
        printf ("\t#1 Create alert ");
        // send metric, receive alert
        zmsg_t *msg = fty_proto_encode_metric (
            NULL,
            time (NULL),
            60,
            "status.ups",
            "mydevice",
            "64",
            "");
        mlm_client_send (metric, "status.ups@mydevice", &msg);

        zmsg_t *alert = mlm_client_recv (asset);
        assert (is_fty_proto (alert));
        fty_proto_t *ftymsg = fty_proto_decode (&alert);
        fty_proto_print (ftymsg);
        fty_proto_destroy (&ftymsg);
        zmsg_destroy (&alert);
        printf ("OK\n");
    }
    zclock_sleep (200);
    {
        // test LIST
        printf ("\t#2 LIST ");
        zmsg_t *msg = zmsg_new();
        zmsg_addstr (msg, "LIST");
        zmsg_addstr (msg, "all");
        zmsg_addstr (msg, "myclass");
        mlm_client_sendto (asset, "me", "status.ups@mydevice", NULL, 1000, &msg);

        zmsg_t *reply = mlm_client_recv (asset);

        char *item = zmsg_popstr (reply);
        assert (streq ("LIST", item));
        zstr_free (&item);

        item = zmsg_popstr (reply);
        assert (streq ("all", item));
        zstr_free (&item);

        item = zmsg_popstr (reply);
        assert (streq ("myclass", item));
        zstr_free (&item);

        zmsg_destroy (&reply);
        printf ("OK\n");
    }
    {
        // test GET
        printf ("\t#3 GET ");
        zmsg_t *msg = zmsg_new();
        zmsg_addstr (msg, "GET");
        zmsg_addstr (msg, "load");
        mlm_client_sendto (asset, "me", "ignored", NULL, 1000, &msg);

        zmsg_t *reply = mlm_client_recv (asset);

        char *item = zmsg_popstr (reply);
        assert (streq ("OK", item));
        zstr_free (&item);

        item = zmsg_popstr (reply);
        assert (item && item[0] == '{');
        zstr_free (&item);

        zmsg_destroy (&reply);
        printf ("OK\n");
    }
    {
        // test ADD
        printf ("\t#4 ADD ");
        const char *testrulejson = "{\"name\":\"testrulejson\",\"description\":\"none\",\"evaluation\":\"function main(x) return OK, 'yes' end\"}";

        // For ADD and DELETE tests use the RW directory
        zstr_sendx (fs, "LOADRULES", SELFTEST_DIR_RW, NULL);
        zclock_sleep (200);

        zmsg_t *msg = zmsg_new();
        zmsg_addstr (msg, "ADD");
        zmsg_addstr (msg, testrulejson);
        mlm_client_sendto (asset, "me", "ignored", NULL, 1000, &msg);

        zmsg_t *reply = mlm_client_recv (asset);
        char *item = zmsg_popstr (reply);
        assert (streq ("OK", item));
        zstr_free (&item);

        item = zmsg_popstr (reply);
        assert (item && item[0] == '{');
        zstr_free (&item);

        zmsg_destroy (&reply);
        printf ("OK\n");
    }
    {
        // test DELETE
        printf ("   #3 DELETE ");

        zmsg_t *msg = zmsg_new();
        zmsg_addstr (msg, "DELETE");
        zmsg_addstr (msg, "testrulejson");
        mlm_client_sendto (asset, "me", "ignored", NULL, 1000, &msg);

        zmsg_t *reply = mlm_client_recv (asset);

        char *item = zmsg_popstr (reply);
        assert (streq ("DELETE", item));
        zstr_free (&item);

        item = zmsg_popstr (reply);
        assert (streq ("testrulejson", item));
        zstr_free (&item);

        item = zmsg_popstr (reply);
        assert (streq ("OK", item));
        zstr_free (&item);

        zmsg_destroy (&reply);
        printf ("OK\n");
    }
    mlm_client_destroy (&metric);
    mlm_client_destroy (&asset);
    // destroy actor
    zactor_destroy (&fs);
    //destroy malamute
    zactor_destroy (&malamute);
    //  @end
    printf ("OK\n");
}
