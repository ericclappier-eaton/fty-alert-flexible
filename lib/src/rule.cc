/*  =========================================================================
    rule - class representing one rule

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
    rule - class representing one rule
@discuss
@end
*/

#include "rule.h"
#include "vsjson.h"
#include <fty_log.h>
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

//  Structure of our class

static int string_comparefn(void* i1, void* i2)
{
    return strcmp(reinterpret_cast<char*>(i1), reinterpret_cast<char*>(i2));
}

//  --------------------------------------------------------------------------
//  Create a new rule

rule_t* rule_new(void)
{
    rule_t* self = reinterpret_cast<rule_t*>(zmalloc(sizeof(rule_t)));
    assert(self);
    memset(self, 0, sizeof(*self));

    //  Initialize class properties here
    self->metrics = zlist_new();
    zlist_autofree(self->metrics);
    zlist_comparefn(self->metrics, string_comparefn);
    self->assets = zlist_new();
    zlist_autofree(self->assets);
    zlist_comparefn(self->assets, string_comparefn);
    self->groups = zlist_new();
    zlist_autofree(self->groups);
    zlist_comparefn(self->groups, string_comparefn);
    self->models = zlist_new();
    zlist_autofree(self->models);
    zlist_comparefn(self->models, string_comparefn);
    self->types = zlist_new();
    zlist_autofree(self->types);
    zlist_comparefn(self->types, string_comparefn);
    self->result_actions = zhash_new();
    //  variables
    self->variables = zhashx_new();
    zhashx_set_duplicator(self->variables, reinterpret_cast<zhashx_duplicator_fn*>(strdup));
    zhashx_set_destructor(self->variables, reinterpret_cast<zhashx_destructor_fn*>(zstr_free));

    return self;
}

//  --------------------------------------------------------------------------
//  zhash_free_fn callback for result_actions list
static void free_action(void* data)
{
    zlist_t* list = reinterpret_cast<zlist_t*>(data);
    zlist_destroy(&list);
}

//  --------------------------------------------------------------------------
//  Add rule result action
void rule_add_result_action(rule_t* self, const char* result, const char* action)
{
    if (!self || !result)
        return;

    zlist_t* list = reinterpret_cast<zlist_t*>(zhash_lookup(self->result_actions, result));
    if (!list) {
        list = zlist_new();
        zlist_autofree(list);
        zhash_insert(self->result_actions, result, list);
        zhash_freefn(self->result_actions, result, free_action);
    }
    if (action)
        zlist_append(list, const_cast<char*>(action));
}

//  --------------------------------------------------------------------------
//  Rule loading callback

static int rule_json_callback(const char* locator, const char* value, void* data)
{
    if (!data)
        return 1;

    rule_t* self = reinterpret_cast<rule_t*>(data);

    // incomming json can be encapsulated with { "flexible": ... } envelope
    const char* mylocator = locator;
    if (strncmp(locator, "flexible/", 9) == 0)
        mylocator = &locator[9];

    if (streq(mylocator, "name")) {
        zstr_free(&self->name);
        self->name = vsjson_decode_string(value);
    } else if (streq(mylocator, "description")) {
        zstr_free(&self->description);
        self->description = vsjson_decode_string(value);
    } else if (streq(mylocator, "logical_asset")) {
        zstr_free(&self->logical_asset);
        self->logical_asset = vsjson_decode_string(value);
    } else if (strncmp(mylocator, "metrics/", 7) == 0) {
        char* metric = vsjson_decode_string(value);
        if (metric)
            zlist_append(self->metrics, metric);
        zstr_free(&metric);
    } else if (strncmp(mylocator, "assets/", 7) == 0) {
        char* asset = vsjson_decode_string(value);
        if (asset)
            zlist_append(self->assets, asset);
        zstr_free(&asset);
    } else if (strncmp(mylocator, "groups/", 7) == 0) {
        char* group = vsjson_decode_string(value);
        if (group)
            zlist_append(self->groups, group);
        zstr_free(&group);
    } else if (strncmp(mylocator, "models/", 7) == 0) {
        char* model = vsjson_decode_string(value);
        if (model && strlen(model) > 0)
            zlist_append(self->models, model);
        zstr_free(&model);
    } else if (strncmp(mylocator, "types/", 6) == 0) {
        char* type = vsjson_decode_string(value);
        if (type && strlen(type) > 0)
            zlist_append(self->types, type);
        zstr_free(&type);
    } else if (strncmp(mylocator, "results/", 8) == 0) {
        const char* end  = strrchr(mylocator, '/') + 1;
        const char* prev = end - strlen("action/");
        // OLD FORMAT:
        // results/high_critical/action/0
        if (*end >= '0' && *end <= '9' && strncmp(prev, "action", strlen("action")) == 0) {
            zstr_free(&self->parser.action);
            self->parser.action = vsjson_decode_string(value);
        }
        // NEW FORMAT:
        // results/high_critical/action/0/action
        // results/high_critical/action/0/asset for action == "GPO_INTERACTION"
        // results/high_critical/action/0/mode  ditto
        else if (streq(end, "action")) {
            zstr_free(&self->parser.action);
            self->parser.action = vsjson_decode_string(value);
        } else if (streq(end, "asset")) {
            zstr_free(&self->parser.act_asset);
            self->parser.act_asset = vsjson_decode_string(value);
        } else if (streq(end, "mode")) {
            zstr_free(&self->parser.act_mode);
            self->parser.act_mode = vsjson_decode_string(value);
        } else if (streq(end, "severity") || streq(end, "description")) {
            // action == AUTOMATION
            // automation members, supported but dropped
        } else
            return 0;
        // support empty action set
        bool is_empty  = false;
        bool is_simple = false;
        if (!self->parser.action) {
            log_debug("%s: no action configured", __func__);
            is_empty = true;
        } else {
            is_simple = streq(self->parser.action, "EMAIL") || streq(self->parser.action, "SMS") ||
                        streq(self->parser.action, "AUTOMATION");
            if (!is_simple && (!self->parser.act_asset || !self->parser.act_mode)) {
                log_debug("%s: action is not recognized, nor asset nor mode", __func__);
                return 0;
            }
        }
        // we are all set
        const char* start = mylocator + strlen("results/");
        const char* slash = strchr(start, '/');
        if (!slash) {
            log_error("malformed json: %s", mylocator);
            zstr_free(&self->parser.action);
            zstr_free(&self->parser.act_asset);
            zstr_free(&self->parser.act_mode);
            return 0;
        }
        char* key = reinterpret_cast<char*>(zmalloc(size_t(slash - start + 1)));
        memcpy(key, start, size_t(slash - start));
        log_debug("%s: key = %s", __func__, key);
        if (is_simple) {
            rule_add_result_action(self, key, self->parser.action);
        } else {
            if (!is_empty) {
                char* action =
                    zsys_sprintf("%s:%s:%s", self->parser.action, self->parser.act_asset, self->parser.act_mode);
                rule_add_result_action(self, key, action);
                zstr_free(&action);
            } else {
                rule_add_result_action(self, key, nullptr);
            }
        }
        zstr_free(&key);
        zstr_free(&self->parser.action);
        zstr_free(&self->parser.act_asset);
        zstr_free(&self->parser.act_mode);
    } else if (streq(mylocator, "evaluation")) {
        zstr_free(&self->evaluation);
        self->evaluation = vsjson_decode_string(value);
    } else if (strncmp(mylocator, "variables/", 10) == 0) {
        //  locator e.g. variables/low_critical
        char* slash = const_cast<char*>(strchr(mylocator, '/'));
        if (!slash)
            return 0;
        slash                = slash + 1;
        char* variable_value = vsjson_decode_string(value);
        if (!variable_value || strlen(variable_value) == 0) {
            zstr_free(&variable_value);
            return 0;
        }
        zhashx_insert(self->variables, slash, variable_value);
        zstr_free(&variable_value);
    }

    return 0;
}

//  --------------------------------------------------------------------------
//  Parse JSON into rule.

int rule_parse(rule_t* self, const char* json)
{
    int r = vsjson_parse(json, rule_json_callback, self, true);
    if (r != 0)
        log_error("vsjson_parse failed (r: %d)\njson:\n%s\n", r, json);
    return r;
}

//  --------------------------------------------------------------------------
//  Get rule name

const char* rule_name(rule_t* self)
{
    assert(self);
    return self->name;
}

//  --------------------------------------------------------------------------
//  Get the logical asset

const char* rule_logical_asset(rule_t* self)
{
    assert(self);
    return self->logical_asset;
}

//  --------------------------------------------------------------------------
//  Does rule contain this asset name?

bool rule_asset_exists(rule_t* self, const char* asset)
{
    assert(self);
    assert(asset);

    return zlist_exists(self->assets, const_cast<char*>(asset));
}

//  --------------------------------------------------------------------------
//  Does rule contain this group name?

bool rule_group_exists(rule_t* self, const char* group)
{
    assert(self);
    assert(group);

    return zlist_exists(self->groups, const_cast<char*>(group));
}


//  --------------------------------------------------------------------------
//  Does rule contain this metric?

bool rule_metric_exists(rule_t* self, const char* metric)
{
    assert(self);
    assert(metric);

    return zlist_exists(self->metrics, const_cast<char*>(metric));
}

//  --------------------------------------------------------------------------
//  Return the first metric. If there are no metrics, returns nullptr.

const char* rule_metric_first(rule_t* self)
{
    assert(self);
    return reinterpret_cast<const char*>(zlist_first(self->metrics));
}


//  --------------------------------------------------------------------------
//  Return the next metric. If there are no (more) metrics, returns nullptr.

const char* rule_metric_next(rule_t* self)
{
    assert(self);
    return reinterpret_cast<const char*>(zlist_next(self->metrics));
}


//  --------------------------------------------------------------------------
//  Does rule contain this model?

bool rule_model_exists(rule_t* self, const char* model)
{
    assert(self);
    assert(model);

    return zlist_exists(self->models, const_cast<char*>(model));
}


//  --------------------------------------------------------------------------
//  Does rule contain this type?

bool rule_type_exists(rule_t* self, const char* type)
{
    assert(self);
    assert(type);

    return zlist_exists(self->types, const_cast<char*>(type));
}

//  --------------------------------------------------------------------------
//  Get rule actions

zlist_t* rule_result_actions(rule_t* self, int result)
{
    zlist_t* list = nullptr;

    if (self) {
        const char* results;
        switch (result) {
            case -2:
                results = "low_critical";
                break;
            case -1:
                results = "low_warning";
                break;
            case 0:
                results = "ok";
                break;
            case 1:
                results = "high_warning";
                break;
            case 2:
                results = "high_critical";
                break;
            default:
                results = "";
                break;
        }
        list = reinterpret_cast<zlist_t*>(zhash_lookup(self->result_actions, results));
    }
    return list;
}

//  --------------------------------------------------------------------------
//  Get global variables
//  Caller is responsible for destroying the return value

zhashx_t* rule_global_variables(rule_t* self)
{
    assert(self);
    return zhashx_dup(self->variables);
}

//  --------------------------------------------------------------------------
//  Load json rule from file

int rule_load(rule_t* self, const char* path)
{
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        log_error("can't open file %s (%s)", path, strerror(errno));
        return -1;
    }

    struct stat rstat;
    if (fstat(fd, &rstat) != 0) {
        log_error("can't stat file %s", path);
    }

    size_t capacity = size_t(rstat.st_size + 1);
    char*  buffer   = reinterpret_cast<char*>(zmalloc(capacity + 1));
    assert(buffer);

    if (read(fd, buffer, capacity) == -1) {
        log_error("Error while reading rule %s", path);
    }
    close(fd);

    int result = rule_parse(self, buffer);
    free(buffer);
    return result;
}

//  --------------------------------------------------------------------------
// Update new_rule with configured actions of old_rule
void rule_merge(rule_t* old_rule, rule_t* new_rule)
{
    zhash_destroy(&new_rule->result_actions);
    // XXX: We invalidate the old rule here, because we know it's going to
    // be destroyed. The proper fix is to use zhashx and duplicate the hash.
    new_rule->result_actions = old_rule->result_actions;
    old_rule->result_actions = nullptr;
}

//  --------------------------------------------------------------------------
//  Save json rule to file

int rule_save(rule_t* self, const char* path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd == -1)
        return -1;

    char* json = rule_json(self);
    if (!json)
        return -2;
    if (write(fd, json, strlen(json)) == -1) {
        log_error("Error while writting rule %s", path);
        zstr_free(&json);
        return -3;
    }
    zstr_free(&json);
    close(fd);
    return 0;
}

// ZZZ return 1 if ok, else 0
int rule_compile(rule_t* self)
{
    if (!self)
        return 0;
    // destroy old context
    if (self->lua) {
        lua_close(self->lua);
        self->lua = nullptr;
    }
    // compile
#if LUA_VERSION_NUM > 501
    self->lua = luaL_newstate();
#else
    self->lua = lua_open();
#endif
    if (!self->lua)
        return 0;
    luaL_openlibs(self->lua); // get functions like print();
    if (luaL_dostring(self->lua, self->evaluation) != 0) {
        log_error("rule '%s' has an error", self->name);
        log_debug("ERROR, rule '%s' evaluation part\n%s", self->name, self->evaluation);
        lua_close(self->lua);
        self->lua = nullptr;
        return 0;
    }
    lua_getglobal(self->lua, "main");
    if (!lua_isfunction(self->lua, -1)) {
        log_error("main function not found in rule %s", self->name);
        lua_close(self->lua);
        self->lua = nullptr;
        return 0;
    }
    lua_pushnumber(self->lua, 0);
    lua_setglobal(self->lua, "OK");
    lua_pushnumber(self->lua, 1);
    lua_setglobal(self->lua, "WARNING");
    lua_pushnumber(self->lua, 1);
    lua_setglobal(self->lua, "HIGH_WARNING");
    lua_pushnumber(self->lua, 2);
    lua_setglobal(self->lua, "CRITICAL");
    lua_pushnumber(self->lua, 2);
    lua_setglobal(self->lua, "HIGH_CRITICAL");
    lua_pushnumber(self->lua, -1);
    lua_setglobal(self->lua, "LOW_WARNING");
    lua_pushnumber(self->lua, -2);
    lua_setglobal(self->lua, "LOW_CRITICAL");

    //  set global variables
    const char* item = reinterpret_cast<const char*>(zhashx_first(self->variables));
    while (item) {
        const char* key = reinterpret_cast<const char*>(zhashx_cursor(self->variables));
        lua_pushstring(self->lua, item);
        lua_setglobal(self->lua, key);
        item = reinterpret_cast<const char*>(zhashx_next(self->variables));
    }

    return 1;
}

//  --------------------------------------------------------------------------
//  Evaluate rule

void rule_evaluate(rule_t* self, zlist_t* params, const char* iname, const char* ename, int* result, char** message)
{
    if (result)
        *result = RULE_ERROR;
    if (message)
        *message = nullptr;

    if (!self || !params || !iname || !result || !message) {
        log_error("bad args");
        return;
    }

    log_trace("rule_evaluate %s", rule_name(self));

    if (!self->lua) {
        if (!rule_compile(self)) {
            log_error("rule_compile %s failed", rule_name(self));
            return;
        }
    }

    lua_pushstring(self->lua, ename ? ename : iname);
    lua_setglobal(self->lua, "NAME");
    lua_pushstring(self->lua, iname);
    lua_setglobal(self->lua, "INAME");
    lua_settop(self->lua, 0);
    lua_getglobal(self->lua, "main");

    char* value = reinterpret_cast<char*>(zlist_first(params));
    int   i     = 0;
    while (value) {
        log_trace("rule_evaluate: push param #%d: %s", i, value);
        lua_pushstring(self->lua, value);
        value = reinterpret_cast<char*>(zlist_next(params));
        i++;
    }

    int r = lua_pcall(self->lua, int(zlist_size(params)), 2, 0);

    if (r == 0) {
        // calculated
        if (lua_isnumber(self->lua, -1)) {
            *result         = int(lua_tointeger(self->lua, -1));
            const char* msg = lua_tostring(self->lua, -2);
            if (msg)
                *message = strdup(msg);
        } else if (lua_isnumber(self->lua, -2)) {
            *result         = int(lua_tointeger(self->lua, -2));
            const char* msg = lua_tostring(self->lua, -1);
            if (msg)
                *message = strdup(msg);
        } else {
            log_error("rule_evaluate: invalid content of self->lua.");
        }

        lua_pop(self->lua, 2);
    } else {
        log_error("rule_evaluate: lua_pcall %s failed (r: %d)", rule_name(self), r);
    }
}

//  --------------------------------------------------------------------------
//  Create json from rule

static char* s_string_append(char** string_p, size_t* capacity, const char* append)
{
    if (!string_p)
        return nullptr;
    if (!capacity)
        return nullptr;
    if (!append)
        return *string_p;

    char* string = *string_p;
    if (!string) {
        string    = reinterpret_cast<char*>(zmalloc(512));
        *capacity = 512;
    }

    size_t l1       = strlen(string);
    size_t l2       = strlen(append);
    size_t required = l1 + l2 + 1;
    if (*capacity < required) {
        size_t newcapacity = *capacity;
        while (newcapacity < required) {
            newcapacity += 512;
        }
        char* tmp = reinterpret_cast<char*>(realloc(string, newcapacity));
        if (!tmp) {
            free(string);
            *capacity = 0;
            return nullptr;
        }
        string    = tmp;
        *capacity = newcapacity;
    }
    strncat(string, append, *capacity);
    *string_p = string;
    return string;
}

static char* s_zlist_to_json_array(zlist_t* list)
{
    if (!list)
        return strdup("[]");
    char*  item     = reinterpret_cast<char*>(zlist_first(list));
    char*  json     = nullptr;
    size_t jsonsize = 0;
    s_string_append(&json, &jsonsize, "[");
    while (item) {
        char* encoded = vsjson_encode_string(item);
        s_string_append(&json, &jsonsize, encoded);
        s_string_append(&json, &jsonsize, ", ");
        zstr_free(&encoded);
        item = reinterpret_cast<char*>(zlist_next(list));
    }
    if (zlist_size(list)) {
        size_t x    = strlen(json);
        json[x - 2] = 0;
    }
    s_string_append(&json, &jsonsize, "]");
    return json;
}

static char* s_actions_to_json_array(zlist_t* actions)
{
    char*  item     = reinterpret_cast<char*>(zlist_first(actions));
    char*  json     = nullptr;
    size_t jsonsize = 0;
    s_string_append(&json, &jsonsize, "[");
    while (item) {
        s_string_append(&json, &jsonsize, "{\"action\": ");
        const char* p     = item;
        const char* colon = strchr(p, ':');
        if (!colon) {
            // recognized action?
            if (!streq(item, "EMAIL") && !streq(item, "SMS") && !streq(item, "AUTOMATION"))
                log_warning("Unrecognized action: %s", item);
            char* encoded = vsjson_encode_string(item);
            s_string_append(&json, &jsonsize, encoded);
            zstr_free(&encoded);
        } else {
            // GPO_INTERACTION
            char* encoded = nullptr;
            if (strncmp(item, "GPO_INTERACTION", size_t(colon - p)) != 0)
                log_warning("Unrecognized action: %.*s", colon - p, p);
            encoded = vsjson_encode_nstring(p, size_t(colon - p));
            s_string_append(&json, &jsonsize, encoded);
            zstr_free(&encoded);
            s_string_append(&json, &jsonsize, ", \"asset\": ");
            p = colon + 1;
            if (!(colon = strchr(p, ':'))) {
                log_warning("Missing mode field in \"%s\"", item);
                colon = p + strlen(p);
            }
            encoded = vsjson_encode_nstring(p, size_t(colon - p));
            s_string_append(&json, &jsonsize, encoded);
            zstr_free(&encoded);
            if (*colon == ':') {
                s_string_append(&json, &jsonsize, ", \"mode\": ");
                p       = colon + 1;
                encoded = vsjson_encode_string(p);
                s_string_append(&json, &jsonsize, encoded);
                zstr_free(&encoded);
            }
        }
        s_string_append(&json, &jsonsize, "}, ");
        item = reinterpret_cast<char*>(zlist_next(actions));
    }
    if (zlist_size(actions)) {
        size_t x    = strlen(json);
        json[x - 2] = 0;
    }
    s_string_append(&json, &jsonsize, "]");
    return json;
}

//  --------------------------------------------------------------------------
//  Convert rule back to json
//  Caller is responsible for destroying the return value

char* rule_json(rule_t* self)
{
    if (!self)
        return nullptr;

    char*  json     = nullptr;
    size_t jsonsize = 0;
    {
        // json start + name
        char* jname = vsjson_encode_string(self->name);
        s_string_append(&json, &jsonsize, "{\n\"name\":");
        s_string_append(&json, &jsonsize, jname);
        s_string_append(&json, &jsonsize, ",\n");
        zstr_free(&jname);
    }
    {
        char* desc = vsjson_encode_string(self->description ? self->description : "");
        s_string_append(&json, &jsonsize, "\"description\":");
        s_string_append(&json, &jsonsize, desc);
        s_string_append(&json, &jsonsize, ",\n");
        zstr_free(&desc);
    }
    {
        char* logical_asset = vsjson_encode_string(self->logical_asset ? self->logical_asset : "");
        s_string_append(&json, &jsonsize, "\"logical_asset\":");
        s_string_append(&json, &jsonsize, logical_asset);
        s_string_append(&json, &jsonsize, ",\n");
        zstr_free(&logical_asset);
    }
    {
        // metrics
        char* tmp = s_zlist_to_json_array(self->metrics);
        s_string_append(&json, &jsonsize, "\"metrics\":");
        s_string_append(&json, &jsonsize, tmp);
        s_string_append(&json, &jsonsize, ",\n");
        zstr_free(&tmp);
    }
    {
        // assets
        char* tmp = s_zlist_to_json_array(self->assets);
        s_string_append(&json, &jsonsize, "\"assets\":");
        s_string_append(&json, &jsonsize, tmp);
        s_string_append(&json, &jsonsize, ",\n");
        zstr_free(&tmp);
    }
    {
        // models
        char* tmp = s_zlist_to_json_array(self->models);
        s_string_append(&json, &jsonsize, "\"models\":");
        s_string_append(&json, &jsonsize, tmp);
        s_string_append(&json, &jsonsize, ",\n");
        zstr_free(&tmp);
    }
    {
        // groups
        char* tmp = s_zlist_to_json_array(self->groups);
        s_string_append(&json, &jsonsize, "\"groups\":");
        s_string_append(&json, &jsonsize, tmp);
        s_string_append(&json, &jsonsize, ",\n");
        zstr_free(&tmp);
    }
    {
        // results
        s_string_append(&json, &jsonsize, "\"results\": {\n");
        const void* result = zhash_first(self->result_actions);
        bool        first  = true;
        while (result) {
            if (first) {
                first = false;
            } else {
                s_string_append(&json, &jsonsize, ",\n");
            }
            char* key = vsjson_encode_string(zhash_cursor(self->result_actions));
            char* tmp = s_actions_to_json_array(const_cast<zlist_t*>(reinterpret_cast<const zlist_t*>(result)));
            s_string_append(&json, &jsonsize, key);
            s_string_append(&json, &jsonsize, ": {\"action\": ");
            s_string_append(&json, &jsonsize, tmp);
            s_string_append(&json, &jsonsize, "}");
            zstr_free(&tmp);
            zstr_free(&key);
            result = zhash_next(self->result_actions);
        }
        s_string_append(&json, &jsonsize, "},\n");
    }
    {
        // variables
        if (zhashx_size(self->variables)) {
            s_string_append(&json, &jsonsize, "\"variables\": {\n");
            char* item  = reinterpret_cast<char*>(zhashx_first(self->variables));
            bool  first = true;
            while (item) {
                if (first) {
                    first = false;
                } else {
                    s_string_append(&json, &jsonsize, ",\n");
                }
                char* key   = vsjson_encode_string(reinterpret_cast<const char*>(zhashx_cursor(self->variables)));
                char* value = vsjson_encode_string(item);
                s_string_append(&json, &jsonsize, key);
                s_string_append(&json, &jsonsize, ":");
                s_string_append(&json, &jsonsize, value);
                zstr_free(&key);
                zstr_free(&value);
                item = reinterpret_cast<char*>(zhashx_next(self->variables));
            }
            s_string_append(&json, &jsonsize, "},\n");
        }
    }
    {
        // json evaluation
        char* eval = vsjson_encode_string(self->evaluation);
        s_string_append(&json, &jsonsize, "\"evaluation\":");
        s_string_append(&json, &jsonsize, eval);
        s_string_append(&json, &jsonsize, "\n}\n");
        zstr_free(&eval);
    }
    return json;
}

//  --------------------------------------------------------------------------
//  Destroy the rule

void rule_destroy(rule_t** self_p)
{
    assert(self_p);
    if (*self_p) {
        rule_t* self = *self_p;
        //  Free class properties here
        zstr_free(&self->name);
        zstr_free(&self->description);
        zstr_free(&self->logical_asset);
        zstr_free(&self->evaluation);
        zstr_free(&self->parser.action);
        zstr_free(&self->parser.act_asset);
        zstr_free(&self->parser.act_mode);
        if (self->lua)
            lua_close(self->lua);
        zlist_destroy(&self->metrics);
        zlist_destroy(&self->assets);
        zlist_destroy(&self->groups);
        zlist_destroy(&self->models);
        zlist_destroy(&self->types);
        zhash_destroy(&self->result_actions);
        zhashx_destroy(&self->variables);
        //  Free object itself
        free(self);
        *self_p = nullptr;
    }
}
