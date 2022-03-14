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
#include "asset_info.h"
#include <malamute.h>
#include <fty_log.h>
#include <fty_proto.h>
#include <fty_shm.h>
#include <sstream>

#include <cxxtools/jsondeserializer.h>
#include <fty_common.h>

#define ANSI_COLOR_WHITE_ON_BLUE "\x1b[44;97m"
#define ANSI_COLOR_BOLD          "\x1b[1;39m"
#define ANSI_COLOR_RED           "\x1b[1;31m"
#define ANSI_COLOR_YELLOW        "\x1b[1;33m"
#define ANSI_COLOR_CYAN          "\x1b[1;36m"
#define ANSI_COLOR_RESET         "\x1b[0m"

// freefn() collection for zhash_t* item destructors

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

void ftymsg_freefn(void* ftymsg)
{
    if (ftymsg) {
        fty_proto_t* fty = reinterpret_cast<fty_proto_t*>(ftymsg);
        fty_proto_destroy(&fty);
    }
}

static void ename_freefn(void* ename)
{
    if (ename) {
        free(ename);
    }
}

static void asset_info_freefn(void* assetInfo)
{
    if (assetInfo) {
        asset_info_t* info = reinterpret_cast<asset_info_t*>(assetInfo);
        asset_info_destroy(&info);
    }
}

/// our class
struct flexible_alert_t
{
    zhash_t*      rules;     // <rulename, rule_t*>
    zhash_t*      metrics;   // <metric, fty_proto_t*>
    zhash_t*      assets;    // <assetiname, zlist_t*<rulename>>
    zhash_t*      enames;    // <assetiname, char* assetename>
    zhash_t*      assetInfo; // <assetiname, asset_info_t*>
    mlm_client_t* mlm;
};

//  --------------------------------------------------------------------------
//  Create a new flexible_alert

static flexible_alert_t* flexible_alert_new(void)
{
    flexible_alert_t* self = reinterpret_cast<flexible_alert_t*>(zmalloc(sizeof(flexible_alert_t)));
    if (!self)
        return NULL;

    memset(self, 0, sizeof(flexible_alert_t));

    //  Initialize class properties here
    self->rules     = zhash_new();
    self->metrics   = zhash_new();
    self->assets    = zhash_new();
    self->enames    = zhash_new();
    self->assetInfo = zhash_new();
    self->mlm = mlm_client_new();

    zhash_autofree(self->enames);

    return self;
}

//  --------------------------------------------------------------------------
//  Destroy the flexible_alert

static void flexible_alert_destroy(flexible_alert_t** self_p)
{
    if (!(self_p && (*self_p)))
        return;

    flexible_alert_t* self = *self_p;
    //  Free class properties here
    zhash_destroy(&self->rules);
    zhash_destroy(&self->metrics);
    zhash_destroy(&self->assets);
    zhash_destroy(&self->enames);
    zhash_destroy(&self->assetInfo);
    mlm_client_destroy(&self->mlm);

    //  Free object itself
    free(self);
    *self_p = NULL;
}

//  --------------------------------------------------------------------------
//  Ask the asset agent to republish assets informations

static void s_republish_asset(flexible_alert_t* self, const std::vector<std::string>& assets)
{
    if (!(self && self->mlm))
        return;

    zmsg_t* msg = zmsg_new();
    zmsg_addstr(msg, "REPUBLISH");

    std::string assetsList; // for logs
    for (auto& asset : assets) {
        if (asset.empty())
            continue;
        zmsg_addstr(msg, asset.c_str());
        assetsList += (assetsList.empty() ? "": " ") + asset;
    }

    if (zmsg_size(msg) < 2) { // nothing to send (assets is empty)
        log_trace("nothing to REPUBLISH");
        zmsg_destroy(&msg);
        return;
    }

    log_trace("%s REPUBLISH %s", AGENT_FTY_ASSET, assetsList.c_str());
    int r = mlm_client_sendto(self->mlm, AGENT_FTY_ASSET, "REPUBLISH", NULL, 5000, &msg);
    zmsg_destroy(&msg);
    if (r != 0) {
        log_error("%s REPUBLISH %s failed", AGENT_FTY_ASSET, assetsList.c_str());
    }
    else { // consume response
        msg = mlm_client_recv(self->mlm);
        zmsg_destroy(&msg);
    }
}

//  --------------------------------------------------------------------------
//  Load one rule from path. Returns valid rule_t* on success, else NULL.
//  CAUTION: returned rule_t* is referenced in self->rules

static rule_t* flexible_alert_load_one_rule(flexible_alert_t* self, const char* fullpath)
{
    rule_t* rule = rule_new();
    int r = rule_load(rule, fullpath);
    if (r == 0) {
        log_info("rule %s loaded", fullpath);
        zhash_update(self->rules, rule_name(rule), rule);
        zhash_freefn(self->rules, rule_name(rule), rule_freefn);

        // update our lists with asset referenced by rule
        const char* asset = strstr(rule_name(rule), "@");
        if (asset) {
            s_republish_asset(self, {asset + 1});
        }

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
            log_trace("abort evaluation of rule %s because %s metric is missing", rule_name(rule), topic);
            std::stringstream ss;
            ss << param << " = " << "NaN";
            auditValues.push_back(ss.str());
            isMetricMissing = true;

            zstr_free(&topic);
            break;
        }
        zstr_free(&topic);

        // TTL should be set accorning shortest ttl in metric
        if (ttl == 0 || ttl > int(fty_proto_ttl(ftymsg)))
            ttl = int(fty_proto_ttl(ftymsg));
        const char* value = fty_proto_value(ftymsg);
        zlist_append(params, const_cast<char*>(value));

        std::stringstream ss;
        ss << param << " = " << value;
        auditValues.push_back(ss.str());

        param = rule_metric_next(rule);
    }

    int   result  = 0;

    // if no metric is missing
    if (!isMetricMissing) {
        char* message = NULL;

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
    }

    zlist_destroy(&params);

    // log audit alarm

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

    std::stringstream ss;
    std::for_each(begin(auditValues), end(auditValues), [&ss](const std::string& elem) {
        if (ss.str().empty())
            ss << elem;
        else
            ss << ", " << elem;
    });

    log_info_alarms_flexible_audit("Evaluate rule '%s', assetname: %s [%s] -> result = %s",
        rule_name(rule), assetname, ss.str().c_str(), sResult.c_str());
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

//    log_trace("handle metric: assetname: %s, qty: %s, isShm: %s", assetname, qty_dup, (isShm ? "true" : "false"));

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
            zstr_free(&qty_dup);
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
            *ftymsg_p = NULL; // owned by self->metrics
            zstr_free(&topic);
            metric_saved = true;
        }

        // evaluate
        flexible_alert_evaluate(self, rule, assetname, ename);
    }
    zstr_free(&qty_dup);
}

static void ask_for_sensor(flexible_alert_t* self, const char* sensor_name)
{
    if (!(self && sensor_name))
        return;

    if (!zhash_lookup(self->assets, sensor_name)) {
        log_debug("I have to ask for sensor  %s", sensor_name);
        s_republish_asset(self, {sensor_name});
    }
    else {
        log_trace("I know this sensor %s", sensor_name);
    }
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
            rule_model_exists(rule, fty_proto_ext_string(ftymsg, FTY_PROTO_ASSET_EXT_MODEL, ""))) {
            return 1;
        }
        else {
            return 0;
        }
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

//fwd decl.
static zmsg_t* flexible_alert_delete_rule(flexible_alert_t* self, const char* name, const char* ruledir);

static void flexible_alert_handle_asset(flexible_alert_t* self, fty_proto_t* ftymsg, const char* ruledir)
{
    if (!self || !ftymsg)
        return;
    if (fty_proto_id(ftymsg) != FTY_PROTO_ASSET)
        return;

    const char* operation = fty_proto_operation(ftymsg);
    const char* assetname = fty_proto_name(ftymsg);
    const char* status = fty_proto_aux_string(ftymsg, FTY_PROTO_ASSET_STATUS, "active");
    log_debug("handle stream ASSETS operation: %s on %s (status: %s)", operation, assetname, status);

    if (streq(operation, FTY_PROTO_ASSET_OP_DELETE) || !streq(status, "active"))
    {
        zhash_delete(self->assets, assetname);
        zhash_delete(self->enames, assetname);
        zhash_delete(self->assetInfo, assetname);

        std::vector<std::string> rulesToDelete;
        rule_t* rule = reinterpret_cast<rule_t*>(zhash_first(self->rules));
        while (rule) {
            if (rule_asset_exists(rule, assetname)) {
                //log_trace("rule '%s' is valid for '%s'", rule_name(rule), assetname);
                rulesToDelete.push_back(rule_name(rule));
            }
            rule = reinterpret_cast<rule_t*>(zhash_next(self->rules));
        }

        for (auto& ruleName : rulesToDelete) {
            zmsg_t* r = flexible_alert_delete_rule(self, ruleName.c_str(), ruledir);
            zmsg_destroy(&r);
        }
    }
    else if (streq(operation, FTY_PROTO_ASSET_OP_UPDATE) || streq(operation, FTY_PROTO_ASSET_OP_INVENTORY))
    {
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
            zhash_delete(self->enames, assetname);
            zhash_delete(self->assetInfo, assetname);
            zlist_destroy(&functions_for_asset);
            return;
        }

        zhash_update(self->assets, assetname, functions_for_asset);
        zhash_freefn(self->assets, assetname, asset_freefn);

        // assetInfo update policy:
        // - if new or
        // - if proto embed aux attributes (to get locations)
        {
            bool update = !zhash_lookup(self->assetInfo, assetname)
                || (fty_proto_aux(ftymsg) && (zhash_size(fty_proto_aux(ftymsg)) != 0));
        #if 0
            log_trace(ANSI_COLOR_CYAN "Update %s assetInfo (%s)", assetname, (update ? "true" : "false"));
            fty_proto_print(ftymsg);
            log_trace(ANSI_COLOR_RESET);
        #endif
            if (update) {
                zhash_update(self->assetInfo, assetname, asset_info_new(ftymsg));
                zhash_freefn(self->assetInfo, assetname, asset_info_freefn);

                asset_info_t* info = reinterpret_cast<asset_info_t*>(zhash_lookup(self->assetInfo, assetname));
                log_trace(ANSI_COLOR_CYAN "Update %s assetInfo, locations: %s" ANSI_COLOR_RESET,
                    assetname, asset_info_dumpLocations(info).c_str());
            }
        }

        const char* ename = fty_proto_ext_string(ftymsg, "name", NULL);
        if (ename) {
            zhash_update(self->enames, assetname, const_cast<char*>(ename));
            zhash_freefn(self->enames, assetname, ename_freefn);
        }
    }
}

//  --------------------------------------------------------------------------
//  handling requests for list of rules.
//  type can be 'all' or 'flexible'
//  rule_class (ignored) is just for compatibility with alert engine protocol

static zmsg_t* flexible_alert_list_rules(flexible_alert_t* self, const char* type, const char* rule_class)
{
    if (!(self && type)) {
        log_error("bad inputs (self: %p, type: %s)", self, type);
        return NULL;
    }

    bool typeIsOk = (streq(type, "all") || streq(type, "flexible"));
    if (!typeIsOk) {
        log_warning("type '%s' is invalid", type);
        zmsg_t* reply = zmsg_new();
        zmsg_addstr(reply, "ERROR");
        zmsg_addstr(reply, "INVALID_TYPE");
        return reply;
    }

    zmsg_t* reply = zmsg_new();
    zmsg_addstr(reply, "LIST");
    zmsg_addstr(reply, type);
    zmsg_addstr(reply, rule_class ? rule_class : "");

    rule_t* rule = reinterpret_cast<rule_t*>(zhash_first(self->rules));
    while (rule) {
        char* json = rule_json(rule);
        if (json) {
            char* uistyle = NULL;
            asprintf(&uistyle, "{\"flexible\": %s }", json);
            if (uistyle) {
                log_trace("LIST add %s", rule_name(rule));
                zmsg_addstr(reply, uistyle);
            }
            zstr_free(&uistyle);
        }
        zstr_free(&json);
        rule = reinterpret_cast<rule_t*>(zhash_next(self->rules));
    }
    return reply;
}

//  --------------------------------------------------------------------------
//  handling requests for list of rules (version 2).
//  list rules, with more filters defined in a unique json payload
//  NOTICE: see fty-alert-engine rules list mailbox with identical interface

static const char* COMMAND_LIST2 = "LIST2";

static zmsg_t* flexible_alert_list_rules2(flexible_alert_t* self, const std::string& jsonFilters)
{
    if (!self) {
        log_error("bad inputs (self: %p)", self);
        return NULL;
    }

    #define RETURN_REPLY_ERROR(reason) { \
        zmsg_t* msg = zmsg_new(); \
        zmsg_addstr(msg, "ERROR"); \
        zmsg_addstr(msg, reason); \
        return msg; \
    }

    struct Filter {
        std::string type;
        std::string rule_class;
        std::string asset_type;
        std::string asset_sub_type;
        std::string in;
        std::string category;
        std::vector<std::string> categoryTokens; // splitted
    };

    // parse rule filter
    Filter filter;
    try {
        cxxtools::SerializationInfo si;
        JSON::readFromString(jsonFilters, si);

        cxxtools::SerializationInfo* p;
        if ((p = si.findMember("type")) && !p->isNull())
            { p->getValue(filter.type); }
        if ((p = si.findMember("rule_class")) && !p->isNull())
            { p->getValue(filter.rule_class); }
        if ((p = si.findMember("asset_type")) && !p->isNull())
            { p->getValue(filter.asset_type); }
        if ((p = si.findMember("asset_sub_type")) && !p->isNull())
            { p->getValue(filter.asset_sub_type); }
        if ((p = si.findMember("in")) && !p->isNull())
            { p->getValue(filter.in); }
        if ((p = si.findMember("category")) && !p->isNull())
            { p->getValue(filter.category); }
    }
    catch (const std::exception& e) {
        log_error("%s exception caught reading filter inputs (e: %s)", COMMAND_LIST2, e.what());
        RETURN_REPLY_ERROR("INVALID_INPUT");
    }

    // filter.type is regular?
    if (!filter.type.empty()) {
        const auto type{filter.type};
        if (type != "all" && type != "flexible") {
            RETURN_REPLY_ERROR("INVALID_TYPE");
        }
    }
    // filter.rule_class is regular?
    if (!filter.rule_class.empty()) {
        // free input
    }
    // filter.asset_type is regular?
    if (!filter.asset_type.empty()) {
        auto id = persist::type_to_typeid(filter.asset_type);
        if (id == persist::asset_type::TUNKNOWN) {
            RETURN_REPLY_ERROR("INVALID_ASSET_TYPE");
        }
    }
    // filter.asset_sub_type is regular?
    if (!filter.asset_sub_type.empty()) {
        auto id = persist::subtype_to_subtypeid(filter.asset_sub_type);
        if (id == persist::asset_subtype::SUNKNOWN) {
            RETURN_REPLY_ERROR("INVALID_ASSET_SUB_TYPE");
        }
    }
    // filter.in is regular?
    if (!filter.in.empty()) {
        std::string type; // empty
        if (auto pos = filter.in.rfind("-"); pos != std::string::npos)
            { type = filter.in.substr(0, pos); }
        if (type != "datacenter" && type != "room" && type != "row" && type != "rack") {
            RETURN_REPLY_ERROR("INVALID_IN");
        }
    }
    // filter.category is regular? (free list of tokens, with comma separator)
    filter.categoryTokens.clear();
    if (!filter.category.empty()) {
        // extract tokens in categoryTokens
        std::istringstream stream{filter.category};
        constexpr auto delim{','};
        std::string token;
        while (std::getline(stream, token, delim)) {
            if (!token.empty()) {
                filter.categoryTokens.push_back(token);
            }
        }
        if (filter.categoryTokens.empty()) {
            RETURN_REPLY_ERROR("INVALID_CATEGORY");
        }
    }

    // function to extract asset iname referenced by ruleName
    std::function<std::string(const std::string&)> assetFromRuleName = [](const std::string& ruleName) {
        if (auto pos = ruleName.rfind("@"); pos != std::string::npos)
            { return ruleName.substr(pos + 1); }
        return std::string{};
    };

    // function to extract asset type referenced by ruleName
    std::function<std::string(const std::string&)> assetTypeFromRuleName = [&assetFromRuleName](const std::string& ruleName) {
        std::string asset{assetFromRuleName(ruleName)};
        if (auto pos = asset.rfind("-"); pos != std::string::npos)
            { return asset.substr(0, pos); }
        return std::string{};
    };

    // function to get category tokens for a rule
    // https://confluence-prod.tcc.etn.com/display/PQRELEASE/260005+-+Migrate+Alarms+Settings
    // Note: here we handle *all* rule names, even if not handled by the agent (flexible VS threshold/single/pattern)
    // /!\ category tokens and map **must** be synchronized between:
    // /!\ - fty-alert-engine/src/fty_alert_engine_server.cc categoryTokensFromRuleName()
    // /!\ - fty-alert-flexible/lib/src/flexible_alert.cc categoryTokensFromRuleName()
    std::function<std::vector<std::string>(const std::string&)> categoryTokensFromRuleName = [](const std::string& ruleName) {
        // category tokens
        static constexpr auto T_LOAD{ "load" };
        static constexpr auto T_PHASE_IMBALANCE{ "phase_imbalance" };
        static constexpr auto T_TEMPERATURE{ "temperature" };
        static constexpr auto T_HUMIDITY{ "humidity" };
        static constexpr auto T_EXPIRY{ "expiry" };
        static constexpr auto T_INPUT_CURRENT{ "input_current" };
        static constexpr auto T_OUTPUT_CURRENT{ "output_current" };
        static constexpr auto T_BATTERY{ "battery" };
        static constexpr auto T_INPUT_VOLTAGE{ "input_voltage" };
        static constexpr auto T_OUTPUT_VOLTAGE{ "output_voltage" };
        static constexpr auto T_STS{ "sts" };
        static constexpr auto T_OTHER{ "other" };

        // /!\ **must** sync between fty-alert-engine & fty-alert-flexible
        // category tokens map based on rules name prefix (src/rule_templates/ and fty-nut inlined)
        // define tokens associated to a rule (LIST rules filter)
        // note: an empty vector means 'other'
        static const std::map<std::string, std::vector<std::string>> CAT_TOKENS = {
            { "realpower.default", { T_LOAD } },
            { "phase_imbalance", { T_PHASE_IMBALANCE } },
            { "average.temperature", { T_TEMPERATURE } },
            { "average.humidity", { T_HUMIDITY } },
            { "licensing.expiration", { T_EXPIRY } },
            { "warranty", { T_EXPIRY } },
            { "load.default", { T_LOAD } },
            { "input.L1.current", { T_INPUT_CURRENT } },
            { "input.L2.current", { T_INPUT_CURRENT } },
            { "input.L3.current", { T_INPUT_CURRENT } },
            { "charge.battery", { T_BATTERY} },
            { "runtime.battery", { T_BATTERY } },
            { "voltage.input_1phase", { T_INPUT_VOLTAGE } },
            { "voltage.input_3phase", { T_INPUT_VOLTAGE } },
            { "input.L1.voltage", { T_INPUT_VOLTAGE } },
            { "input.L2.voltage", { T_INPUT_VOLTAGE } },
            { "input.L3.voltage", { T_INPUT_VOLTAGE } },
            { "temperature.default", { T_TEMPERATURE } },
            { "average.temperature", { T_TEMPERATURE } },
            { "realpower.default_1phase", { T_LOAD } },
            { "load.input_1phase", { T_LOAD } },
            { "load.input_3phase", { T_LOAD } },
            { "section_load", { T_LOAD } },
            { "outlet.group.1.current", { T_OUTPUT_CURRENT } }, // assume 4 groups max.
            { "outlet.group.2.current", { T_OUTPUT_CURRENT } },
            { "outlet.group.3.current", { T_OUTPUT_CURRENT } },
            { "outlet.group.4.current", { T_OUTPUT_CURRENT } },
            { "outlet.group.1.voltage", { T_OUTPUT_VOLTAGE } }, // assume 4 groups max.
            { "outlet.group.2.voltage", { T_OUTPUT_VOLTAGE } },
            { "outlet.group.3.voltage", { T_OUTPUT_VOLTAGE } },
            { "outlet.group.4.voltage", { T_OUTPUT_VOLTAGE } },
            { "sts-frequency", { T_STS } },
            { "sts-preferred-source", { T_STS } },
            { "sts-voltage", { T_STS } },
            { "ambient.humidity", { T_HUMIDITY } },
            { "ambient.1.humidity.status", { T_HUMIDITY } }, // assume 3 max.
            { "ambient.2.humidity.status", { T_HUMIDITY } },
            { "ambient.3.humidity.status", { T_HUMIDITY } },
            { "ambient.temperature", { T_TEMPERATURE } },
            { "ambient.1.temperature.status", { T_TEMPERATURE } }, // assume 3 max.
            { "ambient.2.temperature.status", { T_TEMPERATURE } },
            { "ambient.3.temperature.status", { T_TEMPERATURE } },
        }; // CAT_TOKENS

        std::string ruleNamePrefix{ruleName};
        if (auto pos = ruleNamePrefix.rfind("@"); pos != std::string::npos)
            { ruleNamePrefix = ruleNamePrefix.substr(0, pos); }

        auto it = CAT_TOKENS.find(ruleNamePrefix);
        if (it == CAT_TOKENS.end()) {
            log_debug("key '%s' not found in CAT_TOKENS map", ruleNamePrefix.c_str());
            return std::vector<std::string>({ T_OTHER }); // not found
        }

        if (it->second.empty()) { // empty means 'other'
            return std::vector<std::string>({ T_OTHER });
        }
        return it->second;
    };

    // rule match filter? returns true if yes
    std::function<bool(rule_t*)> match =
    [&self, &filter, &assetFromRuleName, &assetTypeFromRuleName, &categoryTokensFromRuleName](rule_t* rule) {
        // filter.type: rule is always 'flexible'
        // filter.rule_class (ignored, deprecated?): just for compatibility with alert engine protocol

        // asset_type
        if (!filter.asset_type.empty()) {
            std::string type{assetTypeFromRuleName(rule_name(rule))};
            if (filter.asset_type == "device") { // 'device' exception
                auto id = persist::subtype_to_subtypeid(type);
                if (id == persist::asset_subtype::SUNKNOWN)
                    { return false; } // 'type' is not a device
            }
            else if (filter.asset_type != type)
                { return false; }
        }
        // asset_sub_type
        if (!filter.asset_sub_type.empty()) {
            std::string type{assetTypeFromRuleName(rule_name(rule))};
            if (filter.asset_sub_type != type)
                { return false; }
        }
        // in (location)
        if (!filter.in.empty()) {
            std::string asset{assetFromRuleName(rule_name(rule))};
            asset_info_t* info = reinterpret_cast<asset_info_t*>(zhash_lookup(self->assetInfo, asset.c_str()));
            //log_trace("LIST2 filter.in: %s locations: '%s'", asset.c_str(), asset_info_dumpLocations(info).c_str());
            if (!asset_info_isInLocations(info, const_cast<char*>(filter.in.c_str())))
                { return false; }
        }
        // category
        if (!filter.categoryTokens.empty()) {
            std::vector<std::string> ruleTokens = categoryTokensFromRuleName(rule_name(rule));
            for (auto& token : filter.categoryTokens) {
                auto it = std::find(ruleTokens.begin(), ruleTokens.end(), token);
                if (it == ruleTokens.end())
                    { return false; }
            }
        }

        return true; // match
    };

    zmsg_t* reply = zmsg_new();
    zmsg_addstr(reply, COMMAND_LIST2);
    zmsg_addstr(reply, jsonFilters.c_str());

    rule_t* rule = reinterpret_cast<rule_t*>(zhash_first(self->rules));
    while (rule) {
        if (match(rule)) {
            bool addOk{false};
            char* json = rule_json(rule);
            if (json) {
                char* flexJson = NULL;
                asprintf(&flexJson, "{\"flexible\": %s}", json);
                if (flexJson) {
                    addOk = true;
                    zmsg_addstr(reply, flexJson);
                }
                zstr_free(&flexJson);
            }
            zstr_free(&json);
            log_debug("%s add rule '%s'%s", COMMAND_LIST2, rule_name(rule), (addOk ? "" : " (FAILED)"));
        }
        else {
            log_debug("%s skip rule '%s'", COMMAND_LIST2, rule_name(rule));
        }
        rule = reinterpret_cast<rule_t*>(zhash_next(self->rules));
    }
    return reply;
    #undef RETURN_REPLY_ERROR
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
            log_trace("delete '%s'", path);
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
    }
    else {
        char* path = NULL;
        asprintf(&path, "%s/%s.rule", dir, rule_name(newrule));
        //log_trace("save rule '%s'", path);
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
                // we need to update our asset lists
                std::vector<std::string> assets;
                {
                    zlist_t* keys = zhash_keys(self->assets);
                    const char* asset = reinterpret_cast<const char*>(zlist_first(keys));
                    while (asset) {
                        if (rule_asset_exists(rule1, asset)) {
                            assets.push_back(asset);
                        }
                        asset = reinterpret_cast<const char*>(zlist_next(keys));
                    }
                    zlist_destroy(&keys);
                }
                s_republish_asset(self, assets);
            }
        }
        zstr_free(&path);
    }

    rule_destroy(&newrule);
    return reply;
}

static void flexible_alert_metric_polling(zsock_t* pipe, void* args)
{
    const char* actor_name = "flexible_alert_metric_polling";

    zpoller_t* poller = zpoller_new(pipe, NULL);
    zsock_signal(pipe, 0);

    zlist_t*          params          = reinterpret_cast<zlist_t*>(args);
    char*             assets_pattern  = reinterpret_cast<char*>(zlist_first(params));
    char*             metrics_pattern = reinterpret_cast<char*>(zlist_next(params));
    flexible_alert_t* self            = reinterpret_cast<flexible_alert_t*>(zlist_next(params));

    log_info("%s started (assets_pattern: %s, metrics_pattern: %s)",
        actor_name, assets_pattern, metrics_pattern);

    while (!zsys_interrupted) {
        void* which = zpoller_wait(poller, fty_get_polling_interval() * 1000);
        if (zpoller_terminated(poller) || zsys_interrupted) {
            break;
        }

        if (zpoller_expired(poller)) {
            fty::shm::shmMetrics result;
            fty::shm::read_metrics(assets_pattern, metrics_pattern, result);
            log_debug("%s: read %zu metrics from SHM (assets: %s, metrics: %s)",
                actor_name, result.size(), assets_pattern, metrics_pattern);
            for (auto& element : result) {
                flexible_alert_handle_metric(self, &element, true);
            }
        } else if (which == pipe) {
            zmsg_t* msg = zmsg_recv(pipe);
            char* cmd = zmsg_popstr(msg);
            if (cmd && streq(cmd, "$TERM")) {
                zstr_free(&cmd);
                zmsg_destroy(&msg);
                break;
            }
            zstr_free(&cmd);
            zmsg_destroy(&msg);
        }
    }

    zpoller_destroy(&poller);

    log_info("%s ended", actor_name);
}

//  --------------------------------------------------------------------------
//  Actor running one instance of flexible alert class

void flexible_alert_actor(zsock_t* pipe, void* args)
{
    const char* actor_name = "flexible_alert_actor";

    flexible_alert_t* self = flexible_alert_new();
    if (!self) {
        log_fatal("%s: flexible_alert_new() failed", actor_name);
        return;
    }

    zsock_signal(pipe, 0);

    zlist_t* params = reinterpret_cast<zlist_t*>(args);
    zlist_append(params, self);
    zactor_t* metric_polling = zactor_new(flexible_alert_metric_polling, params);

    zpoller_t* poller = zpoller_new(mlm_client_msgpipe(self->mlm), pipe, NULL);

    log_info("%s started", actor_name);

    const int POLL_TIMEOUT_MS = 30000; //ms
    char* ruledir = NULL;

    while (!zsys_interrupted) {
        void* which = zpoller_wait(poller, POLL_TIMEOUT_MS);

        if (which == pipe) {
            zmsg_t* msg = zmsg_recv(pipe);
            char*   cmd = zmsg_popstr(msg);

            if (!cmd) {
                log_debug("Invalid command.");
            }
            else if (streq(cmd, "$TERM")) {
                zstr_free(&cmd);
                zmsg_destroy(&msg);
                break;
            }
            else if (streq(cmd, "BIND")) {
                char* endpoint = zmsg_popstr(msg);
                char* myname   = zmsg_popstr(msg);
                assert(endpoint && myname);
                mlm_client_connect(self->mlm, endpoint, 5000, myname);
                zstr_free(&endpoint);
                zstr_free(&myname);
            }
            else if (streq(cmd, "PRODUCER")) {
                char* stream = zmsg_popstr(msg);
                assert(stream);
                mlm_client_set_producer(self->mlm, stream);
                zstr_free(&stream);
            }
            else if (streq(cmd, "CONSUMER")) {
                char* stream  = zmsg_popstr(msg);
                char* pattern = zmsg_popstr(msg);
                assert(stream && pattern);
                mlm_client_set_consumer(self->mlm, stream, pattern);
                zstr_free(&stream);
                zstr_free(&pattern);
            }
            else if (streq(cmd, "LOADRULES")) {
                zstr_free(&ruledir);
                ruledir = zmsg_popstr(msg);
                assert(ruledir);
                flexible_alert_load_rules(self, ruledir);
            }
            else {
                log_warning("Unknown command (%s).", cmd);
            }
            zstr_free(&cmd);
            zmsg_destroy(&msg);
        }
        else if (which == mlm_client_msgpipe(self->mlm)) {
            zmsg_t* msg = mlm_client_recv(self->mlm);
            const char* command = mlm_client_command(self->mlm);

            if (fty_proto_is(msg)) { // eg. STREAM DELIVER command
	            const char* address = mlm_client_address(self->mlm);
                fty_proto_t* fmsg = fty_proto_decode(&msg);

                if (fty_proto_id(fmsg) == FTY_PROTO_ASSET) {
                    log_trace(ANSI_COLOR_CYAN "Receive PROTO_ASSET %s@%s on stream %s" ANSI_COLOR_RESET,
                        fty_proto_operation(fmsg), fty_proto_name(fmsg), address);
                    flexible_alert_handle_asset(self, fmsg, ruledir);
                }
                else if (fty_proto_id(fmsg) == FTY_PROTO_METRIC) {
                    log_trace(ANSI_COLOR_CYAN "Receive PROTO_METRIC %s@%s on stream %s" ANSI_COLOR_RESET,
                        fty_proto_type(fmsg), fty_proto_name(fmsg), address);

                    if (streq(address, FTY_PROTO_STREAM_METRICS) ||
                        streq(address, FTY_PROTO_STREAM_LICENSING_ANNOUNCEMENTS))
                    {
                        // messages from FTY_PROTO_STREAM_METRICS are regular metrics
                        // LICENSING.EXPIRE: bmsg publish licensing-limitation licensing.expire 7 days
                        flexible_alert_handle_metric(self, &fmsg, false);
                    }
                    else if (streq(address, FTY_PROTO_STREAM_METRICS_SENSOR)) {
                        // messages from FTY_PROTO_STREAM_METRICS_SENSORS are gpi sensors
                        if (is_gpi_metric(fmsg))
                            flexible_alert_handle_metric_sensor(self, &fmsg);
                    }
                    else {
                        log_debug("Message FTY_PROTO_METRIC, invalid address ('%s')", address);
                    }
                }
                fty_proto_destroy(&fmsg);
            }
            else if (streq(command, "MAILBOX DELIVER")) {
                // someone is addressing us directly
                // protocol frames cmd/param1/param2
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
                    // request: LIST/type/rule_class
                    // reply: LIST/type/rule_class/rule1/.../ruleN
                    // reply: ERROR/reason
                    log_info("%s %s %s", cmd, p1, p2);
                    reply = flexible_alert_list_rules(self, p1, p2);
                } else if (streq(cmd, COMMAND_LIST2)) { // LIST (version 2)
                    // request: <cmd>/jsonPayload
                    // reply: <cmd>/jsonPayload/rule1/.../ruleN
                    // reply: ERROR/reason
                    log_info("%s %s", cmd, p1);
                    reply = flexible_alert_list_rules2(self, p1);
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

    log_info("%s ended", actor_name);
}
