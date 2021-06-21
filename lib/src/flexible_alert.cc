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

#include "flexible_alert.h"
#include "fty_alert_flexible_audit_log.h"
#include "rule.h"
#include <fty_log.h>
#include <fty_proto.h>
#include <fty_shm.h>
#include <sstream>

#define ANSI_COLOR_WHITE_ON_BLUE "\x1b[44;97m"
#define ANSI_COLOR_BOLD          "\x1b[1;39m"
#define ANSI_COLOR_RED           "\x1b[1;31m"
#define ANSI_COLOR_YELLOW        "\x1b[1;33m"
#define ANSI_COLOR_CYAN          "\x1b[1;36m"
#define ANSI_COLOR_RESET         "\x1b[0m"

static void rule_freefn(void* rule)
{
    if (rule) {
        rule_t* self = reinterpret_cast<rule_t*>(rule);
        rule_destroy(&self);
    }
}

static void asset_freefn(void* asset)
{
    if (asset) {
        zlist_t* self = reinterpret_cast<zlist_t*>(asset);
        zlist_destroy(&self);
    }
}

void ftymsg_freefn(void* ptr)
{
    if (!ptr)
        return;
    fty_proto_t* fty = reinterpret_cast<fty_proto_t*>(ptr);
    fty_proto_destroy(&fty);
}

static void ename_freefn(void* ename)
{
    if (ename)
        free(ename);
}

//  --------------------------------------------------------------------------
//  Create a new flexible_alert

flexible_alert_t* flexible_alert_new(void)
{
    flexible_alert_t* self = reinterpret_cast<flexible_alert_t*>(zmalloc(sizeof(flexible_alert_t)));
    assert(self);
    //  Initialize class properties here
    self->rules   = zhash_new();
    self->assets  = zhash_new();
    self->metrics = zhash_new();
    self->enames  = zhash_new();
    zhash_autofree(self->enames);
    self->mlm = mlm_client_new();
    return self;
}

//  --------------------------------------------------------------------------
//  Destroy the flexible_alert

void flexible_alert_destroy(flexible_alert_t** self_p)
{
    assert(self_p);
    if (*self_p) {
        flexible_alert_t* self = *self_p;
        //  Free class properties here
        zhash_destroy(&self->rules);
        zhash_destroy(&self->assets);
        zhash_destroy(&self->metrics);
        zhash_destroy(&self->enames);
        mlm_client_destroy(&self->mlm);
        //  Free object itself
        free(self);
        *self_p = NULL;
    }
}

//  --------------------------------------------------------------------------
//  Load one rule from path. Returns valid rule_t* on success, else NULL.

static rule_t* flexible_alert_load_one_rule(flexible_alert_t* self, const char* fullpath)
{
    rule_t* rule = rule_new();
    int     r    = rule_load(rule, fullpath);
    if (r == 0) {
        log_info("rule %s loaded", fullpath);
        zhash_update(self->rules, rule_name(rule), rule);
        zhash_freefn(self->rules, rule_name(rule), rule_freefn);
        return rule;
    }
    log_error("failed to load rule '%s' (r: %d)", fullpath, r);
    rule_destroy(&rule);
    return NULL;
}

//  --------------------------------------------------------------------------
//  Load all rules in directory. Rule MUST have ".rule" extension.

static void flexible_alert_load_rules(flexible_alert_t* self, const char* path)
{
    if (!self || !path)
        return;

    log_info("reading rules from dir '%s'", path);

    DIR* dir = opendir(path);
    if (!dir) {
        log_error("cannot open dir '%s' (%s)", path, strerror(errno));
        return;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        log_trace("checking dir entry %s type %i", entry->d_name, entry->d_type);
        if (entry->d_type == DT_LNK || entry->d_type == DT_REG || entry->d_type == 0) {
            // file or link
            int l = int(strlen(entry->d_name));
            if (l > 5 && streq(&(entry->d_name[l - 5]), ".rule")) {
                // .rule file (json payload)
                char* fullpath = NULL;
                asprintf(&fullpath, "%s/%s", path, entry->d_name);
                flexible_alert_load_one_rule(self, fullpath);
                zstr_free(&fullpath);
            }
        }
    }
    closedir(dir);
}

static void flexible_alert_send_alert(
    flexible_alert_t* self, rule_t* rule, const char* asset, int result, const char* message, int ttl)
{
    const char* severity = "OK";
    if (result == -1 || result == 1)
        severity = "WARNING";
    if (result == -2 || result == 2)
        severity = "CRITICAL";

    // topic
    char* topic = NULL;
    asprintf(&topic, "%s/%s@%s", rule_name(rule), severity, asset);

    // Logical asset if specified
    const char* la = rule_logical_asset(rule);
    if (la != NULL && !streq(la, "")) {
        asset = la;
    }

    // message
    zmsg_t* alert = fty_proto_encode_alert(NULL, uint64_t(time(nullptr)), uint32_t(ttl), rule_name(rule), asset,
        result == 0 ? "RESOLVED" : "ACTIVE", severity, message, rule_result_actions(rule, result)); // action list

    if (streq(severity, "OK")) {
        log_debug(ANSI_COLOR_BOLD "flexible_alert_send_alert %s, asset: %s: severity: %s (result: %d)" ANSI_COLOR_RESET,
            rule_name(rule), asset, severity, result);
    } else {
        log_info(ANSI_COLOR_YELLOW
            "flexible_alert_send_alert %s, asset: %s: severity: %s (result: %d)" ANSI_COLOR_RESET,
            rule_name(rule), asset, severity, result);
    }

    mlm_client_send(self->mlm, topic, &alert);

    zstr_free(&topic);
    zmsg_destroy(&alert);
}

static void flexible_alert_evaluate(flexible_alert_t* self, rule_t* rule, const char* assetname, const char* ename)
{
    zlist_t* params = zlist_new();
    zlist_autofree(params);

    bool                     isMetricMissing = false;
    std::vector<std::string> auditValues;

    // prepare lua function parameters
    int         ttl   = 0;
    const char* param = rule_metric_first(rule);
    while (param) {
        char* topic = NULL;
        asprintf(&topic, "%s@%s", param, assetname);
        fty_proto_t* ftymsg = reinterpret_cast<fty_proto_t*>(zhash_lookup(self->metrics, topic));
        if (!ftymsg) {
            // some metrics are missing
            zlist_destroy(&params);
            log_trace("abort evaluation of rule %s because %s metric is missing", rule_name(rule), topic);
            zstr_free(&topic);
            std::stringstream ss;
            ss << param << " = "
               << "NaN";
            auditValues.push_back(ss.str());
            isMetricMissing = true;
            break;
        }
        // TTL should be set accorning shortest ttl in metric
        if (ttl == 0 || ttl > int(fty_proto_ttl(ftymsg)))
            ttl = int(fty_proto_ttl(ftymsg));
        zstr_free(&topic);
        const char* value = fty_proto_value(ftymsg);
        zlist_append(params, const_cast<char*>(value));

        std::stringstream ss;
        ss << param << " = " << value;
        auditValues.push_back(ss.str());

        param = rule_metric_next(rule);
    }

    int   result  = 0;
    char* message = NULL;

    // if no metric is missing
    if (!isMetricMissing) {

        // call the lua function
        rule_evaluate(rule, params, assetname, ename, &result, &message);

        log_debug(ANSI_COLOR_WHITE_ON_BLUE "rule_evaluate %s, assetname: %s: result = %d" ANSI_COLOR_RESET,
            rule_name(rule), assetname, result);

        if (result != RULE_ERROR) {
            flexible_alert_send_alert(self, rule, assetname, result, message, ttl * 5 / 2);
        } else {
            log_error(ANSI_COLOR_RED "error evaluating rule %s" ANSI_COLOR_RESET, rule_name(rule));
        }
        zstr_free(&message);
        zlist_destroy(&params);
    }

    // log audit alarm
    std::stringstream ss;
    std::for_each(begin(auditValues), end(auditValues), [&ss](const std::string& elem) {
        if (ss.str().empty())
            ss << elem;
        else
            ss << ", " << elem;
    });
    std::string sResult;
    switch (result) {
        case 0:
            sResult = !isMetricMissing ? "OK" : "MISSING_VALUE";
            break;
        case 1:
            sResult = "HIGH_WARNING";
            break;
        case 2:
            sResult = "HIGH_CRITICAL";
            break;
        case -1:
            sResult = "LOW_WARNING";
            break;
        case -2:
            sResult = "LOW_CRITICAL";
            break;
        case 255:
            sResult = "RULE_ERROR";
            break;
        default:
            sResult = "BAD_VALUE";
            break;
    }
    log_info_alarms_flexible_audit("Evaluate rule '%s', assetname: %s [%s] -> result = %s, message = '%s'",
        rule_name(rule), assetname, ss.str().c_str(), sResult.c_str(), message ? message : "");
}

//  --------------------------------------------------------------------------
//  drop expired metrics

static void flexible_alert_clean_metrics(flexible_alert_t* self)
{
    zlist_t* topics = zhash_keys(self->metrics);
    char*    topic  = reinterpret_cast<char*>(zlist_first(topics));
    while (topic) {
        fty_proto_t* ftymsg = reinterpret_cast<fty_proto_t*>(zhash_lookup(self->metrics, topic));
        if (int(fty_proto_time(ftymsg) + fty_proto_ttl(ftymsg)) < time(nullptr)) {
            log_warning("delete topic %s", topic);
            zhash_delete(self->metrics, topic);
        }
        topic = reinterpret_cast<char*>(zlist_next(topics));
    }
    zlist_destroy(&topics);
}


// --------------------------------------------------------------------------
// returns true if metric message belong to gpi sensor
static bool is_gpi_metric(fty_proto_t* metric)
{
    assert(metric);
    const char* port     = fty_proto_aux_string(metric, FTY_PROTO_METRICS_AUX_PORT, "");
    const char* ext_port = fty_proto_aux_string(metric, "ext-port", "");
    if (strstr(port, "GPI") || ext_port != NULL)
        return true;
    else
        return false;
}


//  --------------------------------------------------------------------------
//  Function handles incoming metrics, drives lua evaluation

static void flexible_alert_handle_metric(flexible_alert_t* self, fty_proto_t** ftymsg_p, bool isShm)
{
    if (!self || !ftymsg_p || !*ftymsg_p)
        return;
    fty_proto_t* ftymsg = *ftymsg_p;
    if (fty_proto_id(ftymsg) != FTY_PROTO_METRIC)
        return;

    if (isShm) {
        char* subject = NULL;
        asprintf(&subject, "%s@%s", fty_proto_type(ftymsg), fty_proto_name(ftymsg));
        if (zhash_lookup(self->metrics, subject)) {
            flexible_alert_clean_metrics(self);
        }
        zstr_free(&subject);
    } else if (zhash_lookup(self->metrics, mlm_client_subject(self->mlm))) {
        flexible_alert_clean_metrics(self);
    }

    const char* assetname = fty_proto_name(ftymsg);
    const char* quantity  = fty_proto_type(ftymsg);
    const char* ename     = reinterpret_cast<const char*>(zhash_lookup(self->enames, assetname));
    const char* extport   = fty_proto_aux_string(ftymsg, "ext-port", NULL);

    char* qty_dup = strdup(quantity);

    log_trace("handle metric: assetname: %s, qty: %s, isShm: %s", assetname, qty_dup, (isShm ? "true" : "false"));

    // fix quantity for sensors connected to other sensors
    if (extport) {
        // only sensors connected to other sensors have ext-name set
        const char* qty_len_helper = quantity;
        // second . marks the length
        while ((*qty_len_helper != '\0') && (*qty_len_helper != '.'))
            ++qty_len_helper;
        ++qty_len_helper;
        if (*qty_len_helper == '\0') {
            log_error("malformed quantity");
            return;
        }
        while ((*qty_len_helper != '\0') && (*qty_len_helper != '.'))
            ++qty_len_helper;

        zstr_free(&qty_dup);
        qty_dup = strndup(quantity, size_t(qty_len_helper - quantity));

        log_trace("sensor '%s', new qty: %s", assetname, qty_dup);
    }

    zlist_t* functions_for_asset = reinterpret_cast<zlist_t*>(zhash_lookup(self->assets, assetname));
    if (!functions_for_asset) {
        zstr_free(&qty_dup);
        // log_debug("asset '%s' has no associated function", assetname);
        return;
    }

    // this asset has some evaluation functions
    bool  metric_saved = false;
    char* func         = reinterpret_cast<char*>(zlist_first(functions_for_asset));
    for (; func; func = reinterpret_cast<char*>(zlist_next(functions_for_asset))) {
        rule_t* rule = reinterpret_cast<rule_t*>(zhash_lookup(self->rules, func));
        if (!rule)
            continue;
        if (!rule_metric_exists(rule, qty_dup))
            continue;

        log_debug("qty '%s' exists in '%s'", qty_dup, rule_name(rule));

        // we have to evaluate this function/rule for our asset
        // save metric into cache
        if (!metric_saved) {
            fty_proto_set_time(ftymsg, uint64_t(time(nullptr)));
            // char *topic = zsys_sprintf ("%s@%s", qty_dup, assetname);
            char* topic = NULL;
            asprintf(&topic, "%s@%s", qty_dup, assetname);
            zhash_update(self->metrics, topic, ftymsg);
            zhash_freefn(self->metrics, topic, ftymsg_freefn);
            *ftymsg_p = NULL;
            zstr_free(&topic);
            metric_saved = true;
        }

        // evaluate
        flexible_alert_evaluate(self, rule, assetname, ename);
    }
    zstr_free(&qty_dup);
}

static int ask_for_sensor(flexible_alert_t* self, const char* sensor_name)
{

    if (!zhash_lookup(self->assets, sensor_name)) {
        log_debug("I have to ask for sensor  %s", sensor_name);

        zmsg_t* msg = zmsg_new();
        zmsg_addstr(msg, "REPUBLISH");
        zmsg_addstr(msg, sensor_name);

        int rv = mlm_client_sendto(self->mlm, "asset-agent", "REPUBLISH", NULL, 5000, &msg);
        if (rv != 0) {
            log_error("mlm_client_sendto (address = '%s', subject = '%s', timeout = '5000') for '%s' failed.",
                "asset-agent", "REPUBLISH", sensor_name);
        }
        return rv;
    }
    log_trace("I know this sensor %s", sensor_name);
    return 0;
}

//  --------------------------------------------------------------------------
//  Function handles infoming metric sensors, fix message and pass it to metrics evaluation

static void flexible_alert_handle_metric_sensor(flexible_alert_t* self, fty_proto_t** ftymsg_p)
{
    if (!self || !ftymsg_p || !*ftymsg_p)
        return;
    fty_proto_t* ftymsg = *ftymsg_p;
    if (fty_proto_id(ftymsg) != FTY_PROTO_METRIC)
        return;

    // get name of asset based on GPIO port
    const char* sensor_name = fty_proto_aux_string(ftymsg, FTY_PROTO_METRICS_SENSOR_AUX_SNAME, NULL);
    if (!sensor_name) {
        log_warning("No sensor name provided in sensor message");
        return;
    }

    ask_for_sensor(self, sensor_name);
    fty_proto_set_name(ftymsg, "%s", sensor_name);
    flexible_alert_handle_metric(self, ftymsg_p, false);
}

//  --------------------------------------------------------------------------
//  Function returns true if rule should be evaluated for particular asset.
//  This is decided by asset name (json "assets": []) or group (json "groups":[])

static int is_rule_for_this_asset(rule_t* rule, fty_proto_t* ftymsg)
{
    if (!rule || !ftymsg)
        return 0;

    const char* subtype = fty_proto_aux_string(ftymsg, FTY_PROTO_ASSET_SUBTYPE, "");
    if (streq(subtype, "sensorgpio")) {
        if (rule_asset_exists(rule, fty_proto_name(ftymsg)) &&
            rule_model_exists(rule, fty_proto_ext_string(ftymsg, FTY_PROTO_ASSET_EXT_MODEL, "")))
            return 1;
        else
            return 0;
    }

    if (rule_asset_exists(rule, fty_proto_name(ftymsg)))
        return 1;

    zhash_t* ext  = fty_proto_ext(ftymsg);
    zlist_t* keys = zhash_keys(ext);
    char*    key  = reinterpret_cast<char*>(zlist_first(keys));
    while (key) {
        if (strncmp("group.", key, 6) == 0) {
            // this is group
            if (rule_group_exists(rule, reinterpret_cast<char*>(zhash_lookup(ext, key)))) {
                zlist_destroy(&keys);
                return 1;
            }
        }
        key = reinterpret_cast<char*>(zlist_next(keys));
    }
    zlist_destroy(&keys);

    if (rule_model_exists(rule, fty_proto_ext_string(ftymsg, FTY_PROTO_ASSET_EXT_MODEL, "")))
        return 1;
    if (rule_model_exists(rule, fty_proto_ext_string(ftymsg, FTY_PROTO_ASSET_EXT_DEVICE_PART, "")))
        return 1;

    if (rule_type_exists(rule, fty_proto_aux_string(ftymsg, FTY_PROTO_ASSET_AUX_TYPE, "")))
        return 1;
    if (rule_type_exists(rule, fty_proto_aux_string(ftymsg, FTY_PROTO_ASSET_AUX_SUBTYPE, "")))
        return 1;

    return 0;
}

//  --------------------------------------------------------------------------
//  When asset message comes, function checks if we have rule for it and stores
//  list of rules valid for this asset.

static void flexible_alert_handle_asset(flexible_alert_t* self, fty_proto_t* ftymsg)
{
    if (!self || !ftymsg)
        return;
    if (fty_proto_id(ftymsg) != FTY_PROTO_ASSET)
        return;

    const char* operation = fty_proto_operation(ftymsg);
    const char* assetname = fty_proto_name(ftymsg);

    if (streq(operation, FTY_PROTO_ASSET_OP_DELETE) ||
        !streq(fty_proto_aux_string(ftymsg, FTY_PROTO_ASSET_STATUS, "active"), "active")) {
        if (zhash_lookup(self->assets, assetname)) {
            zhash_delete(self->assets, assetname);
        }
        if (zhash_lookup(self->enames, assetname)) {
            zhash_delete(self->enames, assetname);
        }
        return;
    }

    if (streq(operation, FTY_PROTO_ASSET_OP_UPDATE) || streq(operation, FTY_PROTO_ASSET_OP_INVENTORY)) {
        zlist_t* functions_for_asset = zlist_new();
        zlist_autofree(functions_for_asset);

        rule_t* rule = reinterpret_cast<rule_t*>(zhash_first(self->rules));
        while (rule) {
            if (is_rule_for_this_asset(rule, ftymsg)) {
                zlist_append(functions_for_asset, const_cast<char*>(rule_name(rule)));
                log_debug("rule '%s' is valid for '%s'", rule_name(rule), assetname);
            }
            rule = reinterpret_cast<rule_t*>(zhash_next(self->rules));
        }

        if (zlist_size(functions_for_asset) == 0) {
            log_trace("no rule for %s", assetname);
            zhash_delete(self->assets, assetname);
            zlist_destroy(&functions_for_asset);
            return;
        }
        zhash_update(self->assets, assetname, functions_for_asset);
        zhash_freefn(self->assets, assetname, asset_freefn);

        const char* ename = fty_proto_ext_string(ftymsg, "name", NULL);
        if (ename) {
            zhash_update(self->enames, assetname, const_cast<char*>(ename));
            zhash_freefn(self->enames, assetname, ename_freefn);
        }
    }
}

//  --------------------------------------------------------------------------
//  handling requests for list of rules.
//  type can be all or flexible in this agent
//  class is just for compatibility with alert engine protocol

static zmsg_t* flexible_alert_list_rules(flexible_alert_t* self, char* type, char* ruleclass)
{
    if (!self || !type)
        return NULL;

    zmsg_t* reply = zmsg_new();

    if (!streq(type, "all") && !streq(type, "flexible")) {
        zmsg_addstr(reply, "ERROR");
        zmsg_addstr(reply, "INVALID_TYPE");
        return reply;
    }

    zmsg_addstr(reply, "LIST");
    zmsg_addstr(reply, type);
    zmsg_addstr(reply, ruleclass ? ruleclass : "");

    rule_t* rule = reinterpret_cast<rule_t*>(zhash_first(self->rules));
    while (rule) {
        char* json = rule_json(rule);
        if (json) {
            char* uistyle = NULL;
            asprintf(&uistyle, "{\"flexible\": %s }", json);
            if (uistyle) {
                zmsg_addstr(reply, uistyle);
                zstr_free(&uistyle);
            }
            zstr_free(&json);
        }
        rule = reinterpret_cast<rule_t*>(zhash_next(self->rules));
    }
    return reply;
}

//  --------------------------------------------------------------------------
//  handling requests for getting rule.

static zmsg_t* flexible_alert_get_rule(flexible_alert_t* self, char* name)
{
    if (!self || !name)
        return NULL;

    rule_t* rule  = reinterpret_cast<rule_t*>(zhash_lookup(self->rules, name));
    zmsg_t* reply = zmsg_new();
    if (rule) {
        char* json = rule_json(rule);
        zmsg_addstr(reply, "OK");
        zmsg_addstr(reply, json);
        zstr_free(&json);
    } else {
        zmsg_addstr(reply, "ERROR");
        zmsg_addstr(reply, "NOT_FOUND");
    }
    return reply;
}

//  --------------------------------------------------------------------------
//  handling requests for deleting rule.

static zmsg_t* flexible_alert_delete_rule(flexible_alert_t* self, const char* name, const char* dir)
{
    if (!self || !name || !dir)
        return NULL;

    zmsg_t* reply = zmsg_new();
    zmsg_addstr(reply, "DELETE");
    zmsg_addstr(reply, name);

    rule_t* rule = reinterpret_cast<rule_t*>(zhash_lookup(self->rules, name));
    if (rule) {
        char* path = NULL;
        asprintf(&path, "%s/%s.rule", dir, name);
        if (unlink(path) == 0) {
            zmsg_addstr(reply, "OK");
            zhash_delete(self->rules, name);
        } else {
            log_error("Can't remove %s", path);
            zmsg_addstr(reply, "ERROR");
            zmsg_addstr(reply, "CAN_NOT_REMOVE");
        }
        zstr_free(&path);
    } else {
        zmsg_addstr(reply, "ERROR");
        zmsg_addstr(reply, "DOES_NOT_EXISTS");
    }
    return reply;
}

//  --------------------------------------------------------------------------
//  handling requests for adding rule.

static zmsg_t* flexible_alert_add_rule(
    flexible_alert_t* self, const char* json, const char* old_name, bool incomplete, const char* dir)
{
    if (!self || !json || !dir)
        return NULL;

    rule_t* newrule = rule_new();
    zmsg_t* reply   = zmsg_new();
    if (rule_parse(newrule, json) != 0) {
        zmsg_addstr(reply, "ERROR");
        zmsg_addstr(reply, "INVALID_JSON");
        rule_destroy(&newrule);
        return reply;
    };

    rule_t* oldrule = reinterpret_cast<rule_t*>(zhash_lookup(self->rules, rule_name(newrule)));
    // we probably shouldn't merge other rules
    if (incomplete && oldrule && strstr(rule_name(oldrule), "sensorgpio")) {
        log_info("merging incomplete rule %s from fty-alert-engine", rule_name(newrule));
        rule_merge(oldrule, newrule);
    }
    if (old_name) {
        log_info("deleting rule %s", old_name);
        zmsg_t* msg = flexible_alert_delete_rule(self, old_name, dir);
        zmsg_destroy(&msg);
    }
    rule_t* rule = reinterpret_cast<rule_t*>(zhash_lookup(self->rules, rule_name(newrule)));
    if (rule && strstr(rule_name(rule), "sensorgpio") == NULL) {
        log_error("Rule %s exists", rule_name(rule));
        zmsg_addstr(reply, "ERROR");
        zmsg_addstr(reply, "ALREADY_EXISTS");
    } else {

        char* path = NULL;
        asprintf(&path, "%s/%s.rule", dir, rule_name(newrule));
        int r = rule_save(newrule, path);
        if (r != 0) {
            log_error("Error while saving rule %s (%i)", path, r);
            zmsg_addstr(reply, "ERROR");
            zmsg_addstr(reply, "SAVE_FAILURE");
        } else {
            zmsg_addstr(reply, "OK");
            zmsg_addstr(reply, json);

            log_info("Loading rule %s", path);
            rule_t* rule1 = flexible_alert_load_one_rule(self, path);
            log_info("Loading rule %s done (%s)", path, (rule1 ? "success" : "failed"));

            if (rule1) {
                // we need to update our lists
                zlist_t*    assets = zhash_keys(self->assets);
                const char* asset  = reinterpret_cast<const char*>(zlist_first(assets));
                while (asset) {
                    if (rule_asset_exists(rule1, asset)) {
                        zmsg_t* msg = zmsg_new();
                        zmsg_addstr(msg, "REPUBLISH");
                        zmsg_addstr(msg, asset);
                        mlm_client_sendto(self->mlm, "asset-agent", "REPUBLISH", NULL, 5000, &msg);
                        zmsg_destroy(&msg);
                    }
                    asset = reinterpret_cast<const char*>(zlist_next(assets));
                }
                zlist_destroy(&assets);
            }
        }
        zstr_free(&path);
    }
    rule_destroy(&newrule);
    return reply;
}

static void flexible_alert_metric_polling(zsock_t* pipe, void* args)
{
    zpoller_t* poller = zpoller_new(pipe, NULL);
    zsock_signal(pipe, 0);
    zlist_t*          params          = reinterpret_cast<zlist_t*>(args);
    char*             assets_pattern  = reinterpret_cast<char*>(zlist_first(params));
    char*             metrics_pattern = reinterpret_cast<char*>(zlist_next(params));
    flexible_alert_t* self            = reinterpret_cast<flexible_alert_t*>(zlist_next(params));

    log_info("flexible_alert_metric_polling started (assets_pattern: %s, metrics_pattern: %s)", assets_pattern,
        metrics_pattern);

    while (!zsys_interrupted) {
        void* which = zpoller_wait(poller, fty_get_polling_interval() * 1000);
        if (zpoller_terminated(poller) || zsys_interrupted) {
            break;
        }

        if (zpoller_expired(poller)) {
            fty::shm::shmMetrics result;
            fty::shm::read_metrics(assets_pattern, metrics_pattern, result);
            log_debug("poll: read metrics from SHM (size: %d, assets: %s, metrics: %s)", result.size(), assets_pattern,
                metrics_pattern);
            for (auto& element : result) {
                flexible_alert_handle_metric(self, &element, true);
            }
        } else if (which == pipe) {
            zmsg_t* message = zmsg_recv(pipe);
            if (message) {
                char* cmd = zmsg_popstr(message);
                if (cmd) {
                    if (streq(cmd, "$TERM")) {
                        zstr_free(&cmd);
                        zmsg_destroy(&message);
                        break;
                    }
                    zstr_free(&cmd);
                }
                zmsg_destroy(&message);
            }
        }
    }

    log_info("flexible_alert_metric_polling: Terminating.");

    zlist_destroy(&params);
    zpoller_destroy(&poller);
}

//  --------------------------------------------------------------------------
//  Actor running one instance of flexible alert class

void flexible_alert_actor(zsock_t* pipe, void* args)
{
    flexible_alert_t* self = flexible_alert_new();
    assert(self);
    zsock_signal(pipe, 0);
    char* ruledir = NULL;

    zlist_t* params = reinterpret_cast<zlist_t*>(args);
    zlist_append(params, self);
    zactor_t* metric_polling = zactor_new(flexible_alert_metric_polling, params);

    zpoller_t* poller = zpoller_new(mlm_client_msgpipe(self->mlm), pipe, NULL);
    while (!zsys_interrupted) {
        void* which = zpoller_wait(poller, -1);
        if (which == pipe) {
            zmsg_t* msg = zmsg_recv(pipe);
            char*   cmd = zmsg_popstr(msg);
            if (cmd) {
                if (streq(cmd, "$TERM")) {
                    zstr_free(&cmd);
                    zmsg_destroy(&msg);
                    break;
                } else if (streq(cmd, "BIND")) {
                    char* endpoint = zmsg_popstr(msg);
                    char* myname   = zmsg_popstr(msg);
                    assert(endpoint && myname);
                    mlm_client_connect(self->mlm, endpoint, 5000, myname);
                    zstr_free(&endpoint);
                    zstr_free(&myname);
                } else if (streq(cmd, "PRODUCER")) {
                    char* stream = zmsg_popstr(msg);
                    assert(stream);
                    mlm_client_set_producer(self->mlm, stream);
                    zstr_free(&stream);
                } else if (streq(cmd, "CONSUMER")) {
                    char* stream  = zmsg_popstr(msg);
                    char* pattern = zmsg_popstr(msg);
                    assert(stream && pattern);
                    mlm_client_set_consumer(self->mlm, stream, pattern);
                    zstr_free(&stream);
                    zstr_free(&pattern);
                } else if (streq(cmd, "LOADRULES")) {
                    zstr_free(&ruledir);
                    ruledir = zmsg_popstr(msg);
                    assert(ruledir);
                    flexible_alert_load_rules(self, ruledir);
                } else {
                    log_warning("Unknown command.");
                }

                zstr_free(&cmd);
            }
            zmsg_destroy(&msg);
        } else if (which == mlm_client_msgpipe(self->mlm)) {
            zmsg_t* msg = mlm_client_recv(self->mlm);
            if (fty_proto_is(msg)) {
                fty_proto_t* fmsg = fty_proto_decode(&msg);
                if (fty_proto_id(fmsg) == FTY_PROTO_ASSET) {
                    const char* address = mlm_client_address(self->mlm);
                    log_trace(ANSI_COLOR_CYAN "Receive PROTO_ASSET %s@%s on stream %s" ANSI_COLOR_RESET,
                        fty_proto_operation(fmsg), fty_proto_name(fmsg), address);
                    flexible_alert_handle_asset(self, fmsg);
                } else if (fty_proto_id(fmsg) == FTY_PROTO_METRIC) {
                    const char* address = mlm_client_address(self->mlm);
                    log_trace(ANSI_COLOR_CYAN "Receive PROTO_METRIC %s@%s on stream %s" ANSI_COLOR_RESET,
                        fty_proto_type(fmsg), fty_proto_name(fmsg), address);

                    if (0 == strcmp(address, FTY_PROTO_STREAM_METRICS) ||
                        0 == strcmp(address, FTY_PROTO_STREAM_LICENSING_ANNOUNCEMENTS)) {
                        // messages from FTY_PROTO_STREAM_METRICS are regular metrics
                        // LICENSING.EXPIRE: bmsg publish licensing-limitation licensing.expire 7 days
                        flexible_alert_handle_metric(self, &fmsg, false);
                    } else if (0 == strcmp(address, FTY_PROTO_STREAM_METRICS_SENSOR)) {
                        // messages from FTY_PROTO_STREAM_METRICS_SENSORS are gpi sensors
                        if (is_gpi_metric(fmsg))
                            flexible_alert_handle_metric_sensor(self, &fmsg);
                    } else {
                        log_debug("Message proto ID = FTY_PROTO_METRIC, message address not valid = '%s'", address);
                    }
                }
                fty_proto_destroy(&fmsg);
            } else if (streq(mlm_client_command(self->mlm), "MAILBOX DELIVER")) {
                // someone is addressing us directly
                // protocol frames COMMAND/param1/param2
                char* cmd = zmsg_popstr(msg);
                char* p1  = zmsg_popstr(msg);
                char* p2  = zmsg_popstr(msg);

                log_info("MAILBOX DELIVER: %s from %s", cmd, mlm_client_sender(self->mlm));

                // XXX: fty-alert-engine does not know about configured
                // actions. The proper fix is to extend the protocol to
                // flag a rule as incomplete.
                bool incomplete = streq(mlm_client_sender(self->mlm), "fty-autoconfig");

                zmsg_t* reply = NULL;
                if (!cmd) {
                    log_error("command is NULL");
                } else if (streq(cmd, "LIST")) {
                    // request: LIST/type/class
                    // reply: LIST/type/class/name1/name2/...nameX
                    // reply: ERROR/reason
                    log_info("%s %s %s", cmd, p1, p2);
                    reply = flexible_alert_list_rules(self, p1, p2);
                } else if (streq(cmd, "GET")) {
                    // request: GET/name
                    // reply: OK/rulejson
                    // reply: ERROR/reason
                    log_info("%s %s", cmd, p1);
                    reply = flexible_alert_get_rule(self, p1);
                } else if (streq(cmd, "ADD")) {
                    // request: ADD/rulejson -- this is create
                    // request: ADD/rulejson/rulename -- this is replace
                    // reply: OK/rulejson
                    // reply: ERROR/reason
                    log_info("%s %s %s (incomplete: %s)", cmd, p1, p2, (incomplete ? "true" : "false"));
                    reply = flexible_alert_add_rule(self, p1, p2, incomplete, ruledir);
                } else if (streq(cmd, "DELETE")) {
                    // request: DELETE/name
                    // reply: DELETE/name/OK
                    // reply: DELETE/name/ERROR/reason
                    log_info("%s %s", cmd, p1);
                    reply = flexible_alert_delete_rule(self, p1, ruledir);
                } else {
                    log_warning("command '%s' not handled", cmd);
                }

                if (reply) {
                    mlm_client_sendto(self->mlm, mlm_client_sender(self->mlm), mlm_client_subject(self->mlm),
                        mlm_client_tracker(self->mlm), 1000, &reply);
                    if (reply) {
                        log_error("Failed to send %s reply to %s", cmd, mlm_client_sender(self->mlm));
                    }
                }
                zmsg_destroy(&reply);
                zstr_free(&cmd);
                zstr_free(&p1);
                zstr_free(&p2);
            }
            zmsg_destroy(&msg);
        }
    }

    zactor_destroy(&metric_polling);
    zstr_free(&ruledir);
    zpoller_destroy(&poller);
    flexible_alert_destroy(&self);
}
