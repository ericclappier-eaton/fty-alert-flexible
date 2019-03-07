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

#include "fty_alert_flexible_classes.h"

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

//  Structure of our class

struct _rule_t {
    char *name;
    char *description;
    char *logical_asset;
    zlist_t *metrics;
    zlist_t *assets;
    zlist_t *groups;
    zlist_t *models;
    zlist_t *types;
    zhash_t *result_actions;
    zhashx_t *variables;        //  lua context global variables
    char *evaluation;
    lua_State *lua;
    struct {
        char *action;
        char *act_asset;
        char *act_mode;
    } parser;                   // json parser state data
};


static
int string_comparefn (void *i1, void *i2)
{
    return strcmp ((char *)i1, (char *)i2);
}

//  --------------------------------------------------------------------------
//  Create a new rule

rule_t *
rule_new (void)
{
    rule_t *self = (rule_t *) zmalloc (sizeof (rule_t));
    assert (self);
    //  Initialize class properties here
    self -> metrics = zlist_new ();
    zlist_autofree (self -> metrics);
    zlist_comparefn (self -> metrics, string_comparefn);
    self -> assets = zlist_new ();
    zlist_autofree (self -> assets);
    zlist_comparefn (self -> assets, string_comparefn);
    self -> groups = zlist_new ();
    zlist_autofree (self -> groups);
    zlist_comparefn (self -> groups, string_comparefn);
    self -> models = zlist_new ();
    zlist_autofree (self -> models);
    zlist_comparefn (self -> models, string_comparefn);
    self -> types = zlist_new ();
    zlist_autofree (self -> types);
    zlist_comparefn (self -> types, string_comparefn);
    self -> result_actions = zhash_new ();
    //  variables
    self->variables = zhashx_new ();
    zhashx_set_duplicator (self->variables, (zhashx_duplicator_fn *) strdup);
    zhashx_set_destructor (self->variables, (zhashx_destructor_fn *) zstr_free);

    return self;
}

//  --------------------------------------------------------------------------
//  zhash_free_fn callback for result_actions
static void free_action(void *data)
{
    zlist_t *list = (zlist_t*)data;
    zlist_destroy(&list);
}

//  --------------------------------------------------------------------------
//  Add rule result action
void rule_add_result_action (rule_t *self, const char *result, const char *action)
{
    if (!self || !result) return;

    zlist_t *list = (zlist_t *) zhash_lookup (self->result_actions, result);
    if (!list) {
        list = zlist_new ();
        zlist_autofree (list);
        zhash_insert (self->result_actions, result, list);
        zhash_freefn (self->result_actions, result, free_action);
    }
    if (action)
        zlist_append (list, (char *)action);
}

//  --------------------------------------------------------------------------
//  Rule loading callback

static int
rule_json_callback (const char *locator, const char *value, void *data)
{
    if (!data) return 1;

    rule_t *self = (rule_t *) data;

    // incomming json can be encapsulated with { "flexible": ... } envelope
    const char *mylocator = locator;
    if (strncmp (locator, "flexible/",9) == 0) mylocator = &locator[9];

    if (streq (mylocator, "name")) {
        zstr_free (&self -> name);
        self -> name = vsjson_decode_string (value);
    }
    else if (streq (mylocator, "description")) {
        zstr_free (&self -> description);
        self -> description = vsjson_decode_string (value);
    }
    else if (streq (mylocator, "logical_asset")) {
        zstr_free (&self -> logical_asset);
        self -> logical_asset = vsjson_decode_string (value);
    }
    else if (strncmp (mylocator, "metrics/", 7) == 0) {
        char *metric = vsjson_decode_string (value);
        if (metric) zlist_append (self -> metrics, metric);
        zstr_free (&metric);
    }
    else if (strncmp (mylocator, "assets/", 7) == 0) {
        char *asset = vsjson_decode_string (value);
        if (asset) zlist_append (self -> assets, asset);
        zstr_free (&asset);
    }
    else if (strncmp (mylocator, "groups/", 7) == 0) {
        char *group = vsjson_decode_string (value);
        if (group) zlist_append (self -> groups, group);
        zstr_free (&group);
    }
    else if (strncmp (mylocator, "models/", 7) == 0) {
        char *model = vsjson_decode_string (value);
        if (model && strlen (model) > 0)
            zlist_append (self->models, model);
        zstr_free (&model);
    }
    else if (strncmp (mylocator, "types/", 6) == 0) {
        char *type = vsjson_decode_string (value);
        if (type && strlen (type) > 0)
            zlist_append (self->types, type);
        zstr_free (&type);
    }
    else if (strncmp (mylocator, "results/", 8) == 0) {
        const char *end = strrchr (mylocator, '/') + 1;
        const char *prev = end - strlen ("action/");
        // OLD FORMAT:
        // results/high_critical/action/0
        if (*end >= '0' && *end <= '9' && strncmp (prev, "action", strlen("action")) == 0)
            self->parser.action = vsjson_decode_string (value);
        // NEW FORMAT:
        // results/high_critical/action/0/action
        // results/high_critical/action/0/asset for action == "GPO_INTERACTION"
        // results/high_critical/action/0/mode  ditto
        else if (streq (end, "action"))
            self->parser.action = vsjson_decode_string (value);
        else if (streq (end, "asset"))
            self->parser.act_asset = vsjson_decode_string (value);
        else if (streq (end, "mode"))
            self->parser.act_mode = vsjson_decode_string (value);
        else
            return 0;
        // support empty action set
        bool is_empty = false;
        bool is_email = false;
        if (!self->parser.action) {
            log_debug("%s: no action configured", __func__);
            is_empty = true;
        }
        else {
            is_email = streq(self->parser.action, "EMAIL") ||
                            streq(self->parser.action, "SMS");
            if (!is_email && (!self->parser.act_asset || !self->parser.act_mode)) {
                log_debug("%s: action is not mail, nor asset nor mode", __func__);
                return 0;
            }
        }
        // we are all set
        const char *start = mylocator + strlen("results/");
        const char *slash = strchr(start, '/');
        if (!slash) {
            log_error ("malformed json: %s", mylocator);
            zstr_free (&self->parser.action);
            zstr_free (&self->parser.act_asset);
            zstr_free (&self->parser.act_mode);
            return 0;
        }
        char *key = (char *)zmalloc(slash - start + 1);
        memcpy(key, start, slash - start);
        log_debug("%s: key = %s", __func__, key);
        if (is_email) {
            rule_add_result_action (self, key, self->parser.action);
        } else {
            if (!is_empty) {
                char *action = zsys_sprintf("%s:%s:%s",
                        self->parser.action,
                        self->parser.act_asset,
                        self->parser.act_mode);
                rule_add_result_action (self, key, action);
                zstr_free (&action);
            }
            else
                rule_add_result_action (self, key, NULL);
        }
        zstr_free (&key);
        zstr_free (&self->parser.action);
        zstr_free (&self->parser.act_asset);
        zstr_free (&self->parser.act_mode);
    }
    else if (streq (mylocator, "evaluation")) {
        zstr_free (&self -> evaluation);
        self -> evaluation = vsjson_decode_string (value);
    }
    else
    if (strncmp (mylocator, "variables/", 10) == 0)
    {
        //  locator e.g. variables/low_critical
        char *slash = strchr (mylocator, '/');
        if (!slash)
            return 0;
        slash = slash + 1;
        char *variable_value = vsjson_decode_string (value);
        if (!variable_value || strlen (variable_value) == 0) {
            zstr_free (&variable_value);
            return 0;
        }
        zhashx_insert (self->variables, slash, variable_value);
        zstr_free (&variable_value);
    }

    return 0;
}

//  --------------------------------------------------------------------------
//  Parse JSON into rule.

int rule_parse (rule_t *self, const char *json)
{
    return vsjson_parse (json, rule_json_callback, self, true);
}

//  --------------------------------------------------------------------------
//  Get rule name

const char *
rule_name (rule_t *self)
{
    assert (self);
    return self->name;
}


//  --------------------------------------------------------------------------
//  Get the logical asset

const char *
rule_logical_asset (rule_t *self)
{
    assert (self);
    return self->logical_asset;
}

//  --------------------------------------------------------------------------
//  Does rule contain this asset name?

bool
rule_asset_exists (rule_t *self, const char *asset)
{
    assert (self);
    assert (asset);

    return zlist_exists (self->assets, (void *) asset);
}

//  --------------------------------------------------------------------------
//  Does rule contain this group name?

bool
rule_group_exists (rule_t *self, const char *group)
{
    assert (self);
    assert (group);

    return zlist_exists (self->groups, (void *) group);
}


//  --------------------------------------------------------------------------
//  Does rule contain this metric?

bool
rule_metric_exists (rule_t *self, const char *metric)
{
    assert (self);
    assert (metric);

    return zlist_exists (self->metrics, (void *) metric);
}

//  --------------------------------------------------------------------------
//  Return the first metric. If there are no metrics, returns NULL.

const char *
rule_metric_first (rule_t *self)
{
    assert (self);
    return (const char *) zlist_first (self->metrics);
}


//  --------------------------------------------------------------------------
//  Return the next metric. If there are no (more) metrics, returns NULL.

const char *
rule_metric_next (rule_t *self)
{
    assert (self);
    return (const char *) zlist_next (self->metrics);
}


//  --------------------------------------------------------------------------
//  Does rule contain this model?

bool
rule_model_exists (rule_t *self, const char *model)
{
    assert (self);
    assert (model);

    return zlist_exists (self->models, (void *) model);
}


//  --------------------------------------------------------------------------
//  Does rule contain this type?

bool
rule_type_exists (rule_t *self, const char *type)
{
    assert (self);
    assert (type);

    return zlist_exists (self->types, (void *) type);
}

//  --------------------------------------------------------------------------
//  Get rule actions

zlist_t *
rule_result_actions (rule_t *self, int result)
{
    zlist_t *list = NULL;

    if (self) {
        char *results;
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
        list = (zlist_t *) zhash_lookup (self->result_actions, results);
    }
    return list;
}

//  --------------------------------------------------------------------------
//  Get global variables
//  Caller is responsible for destroying the return value

zhashx_t *
rule_global_variables (rule_t *self)
{
    assert (self);
    return zhashx_dup (self->variables);

}


//  --------------------------------------------------------------------------
//  Load json rule from file

int rule_load (rule_t *self, const char *path)
{
    int fd = open (path, O_RDONLY);
    if (fd == -1) return -1;

    struct stat rstat;
    if (fstat (fd, &rstat) != 0) {
        log_error ("can't stat file %s", path);
    }

    int capacity = rstat.st_size + 1;
    char *buffer = (char *) zmalloc (capacity + 1);
    assert (buffer);

    if (read (fd, buffer, capacity) == -1) {
        log_error ("Error while reading rule %s", path);
    }
    close (fd);
    int result = rule_parse (self, buffer);
    free (buffer);
    return result;
}

//  --------------------------------------------------------------------------
// Update new_rule with configured actions of old_rule
void rule_merge (rule_t *old_rule, rule_t *new_rule)
{
    zhash_destroy (&new_rule->result_actions);
    // XXX: We invalidate the old rule here, because we know it's going to
    // be destroyed. The proper fix is to use zhashx and duplicate the hash.
    new_rule->result_actions = old_rule->result_actions;
    old_rule->result_actions = NULL;
}

//  --------------------------------------------------------------------------
//  Save json rule to file

int rule_save (rule_t *self, const char *path)
{
    int fd = open (path, O_WRONLY | O_CREAT | O_TRUNC,  S_IRUSR | S_IWUSR);
    if (fd == -1) return -1;

    char *json = rule_json (self);
    if (! json) return -2;
    if (write (fd, json, strlen(json)) == -1) {
        log_error ("Error while writting rule %s", path);
        zstr_free (&json);
        return -3;
    }
    zstr_free (&json);
    close (fd);
    return 0;
}

static int rule_compile (rule_t *self)
{
    if (!self) return 0;
    // destroy old context
    if (self -> lua) {
        lua_close (self->lua);
        self->lua = NULL;
    }
    // compile
#if LUA_VERSION_NUM > 501
    self -> lua = luaL_newstate();
#else
    self -> lua = lua_open();
#endif
    if (!self->lua) return 0;
    luaL_openlibs(self -> lua); // get functions like print();
    if (luaL_dostring (self -> lua, self -> evaluation) != 0) {
        log_error ("rule %s has an error", self -> name);
        lua_close (self -> lua);
        self -> lua = NULL;
        return 0;
    }
    lua_getglobal (self -> lua, "main");
    if (!lua_isfunction (self -> lua, -1)) {
        log_error ("main function not found in rule %s", self -> name);
        lua_close (self->lua);
        self -> lua = NULL;
        return 0;
    }
    lua_pushnumber(self -> lua, 0);
    lua_setglobal(self -> lua, "OK");
    lua_pushnumber(self -> lua, 1);
    lua_setglobal(self -> lua, "WARNING");
    lua_pushnumber(self -> lua, 1);
    lua_setglobal(self -> lua, "HIGH_WARNING");
    lua_pushnumber(self -> lua, 2);
    lua_setglobal(self -> lua, "CRITICAL");
    lua_pushnumber(self -> lua, 2);
    lua_setglobal(self -> lua, "HIGH_CRITICAL");
    lua_pushnumber(self -> lua, -1);
    lua_setglobal(self -> lua, "LOW_WARNING");
    lua_pushnumber(self -> lua, -2);
    lua_setglobal(self -> lua, "LOW_CRITICAL");

    //  set global variables
    const char *item = (const char *) zhashx_first (self->variables);
    while (item) {
        const char *key = (const char *) zhashx_cursor (self->variables);
        lua_pushstring (self->lua, item);
        lua_setglobal (self->lua, key);
        item = (const char *) zhashx_next (self->variables);
    }

    return 1;
}


//  --------------------------------------------------------------------------
//  Evaluate rule

void
rule_evaluate (rule_t *self, zlist_t *params, const char *iname, const char *ename, int *result, char **message)
{
    if (!self || !params || !iname || !result || !message) return;

    *result = RULE_ERROR;
    *message = NULL;
    if (!self -> lua) {
        if (! rule_compile (self)) return;
    }
    lua_pushstring(self -> lua, ename ? ename : iname);
    lua_setglobal(self -> lua, "NAME");
    lua_pushstring(self -> lua, iname);
    lua_setglobal(self -> lua, "INAME");
    lua_settop (self->lua, 0);
    lua_getglobal (self->lua, "main");
    char *value = (char *) zlist_first (params);
    while (value) {
        lua_pushstring (self -> lua, value);
        value = (char *) zlist_next (params);
    }
    if (lua_pcall(self -> lua, zlist_size (params), 2, 0) == 0) {
        // calculated
        if (lua_isnumber (self -> lua, -1)) {
            *result = lua_tointeger(self -> lua, -1);
            const char *msg = lua_tostring (self->lua, -2);
            if (msg) *message = strdup (msg);
        }
        else if (lua_isnumber (self -> lua, -2)) {
            *result = lua_tointeger(self -> lua, -2);
            const char *msg = lua_tostring (self->lua, -1);
            if (msg) *message = strdup (msg);
        }
        else
            log_debug ("rule_evaluate: invalid content of self->lua.");
        lua_pop (self->lua, 2);
    }
}

//  --------------------------------------------------------------------------
//  Create json from rule

static char * s_string_append (char **string_p, size_t *capacity, const char *append)
{
    if (! string_p) return NULL;
    if (! append) return *string_p;

    char *string = *string_p;
    if (!string) {
        string = (char *) zmalloc (512);
        *capacity = 512;
    }
    size_t l1 = strlen (string);
    size_t l2 = strlen (append);
    size_t required = l1+l2+1;
    if (*capacity < required) {
        size_t newcapacity = *capacity;
        while (newcapacity < required) {
            newcapacity += 512;
        }
        char *tmp = (char *) realloc (string, newcapacity);
        if (!tmp) {
            free (string);
            *capacity = 0;
            return NULL;
        }
        string = tmp;
        *capacity = newcapacity;
    }
    strncat (string, append, *capacity);
    *string_p = string;
    return string;
}

static char * s_zlist_to_json_array (zlist_t* list)
{
    if (!list) return strdup("[]");
    char *item = (char *) zlist_first (list);
    char *json = NULL;
    size_t jsonsize = 0;
    s_string_append (&json, &jsonsize, "[");
    while (item) {
        char *encoded = vsjson_encode_string (item);
        s_string_append (&json, &jsonsize, encoded);
        s_string_append (&json, &jsonsize, ", ");
        zstr_free (&encoded);
        item = (char *) zlist_next (list);
    }
    if (zlist_size (list)) {
        size_t x = strlen (json);
        json [x-2] = 0;
    }
    s_string_append (&json, &jsonsize, "]");
    return json;
}

static char * s_actions_to_json_array (zlist_t *actions)
{
    char *item = (char *) zlist_first (actions);
    char *json = NULL;
    size_t jsonsize = 0;
    s_string_append (&json, &jsonsize, "[");
    while (item) {
        s_string_append (&json, &jsonsize, "{\"action\": ");
        const char *p = item;
        const char *colon = strchr (p, ':');
        if (!colon) {
            // EMAIL or SMS
            if (!streq(item, "EMAIL") && !streq(item, "SMS"))
                log_warning ("Unrecognized action: %s", item);
            char *encoded = vsjson_encode_string(item);
            s_string_append (&json, &jsonsize, encoded);
            zstr_free (&encoded);
        } else {
            // GPO_INTERACTION
            char *encoded = NULL;
            if (strncmp (item, "GPO_INTERACTION", colon - p) != 0)
                log_warning ("Unrecognized action: %.*s", colon - p, p);
            encoded = vsjson_encode_nstring(p, colon - p);
            s_string_append (&json, &jsonsize, encoded);
            zstr_free (&encoded);
            s_string_append (&json, &jsonsize, ", \"asset\": ");
            p = colon + 1;
            if (!(colon = strchr (p, ':'))) {
                log_warning ("Missing mode field in \"%s\"", item);
                colon = p + strlen(p);
            }
            encoded = vsjson_encode_nstring(p, colon - p);
            s_string_append (&json, &jsonsize, encoded);
            zstr_free (&encoded);
            if (*colon == ':') {
                s_string_append (&json, &jsonsize, ", \"mode\": ");
                p = colon + 1;
                encoded = vsjson_encode_string(p);
                s_string_append (&json, &jsonsize, encoded);
                zstr_free (&encoded);
            }
        }
        s_string_append (&json, &jsonsize, "}, ");
        item = (char *) zlist_next (actions);
    }
    if (zlist_size (actions)) {
        size_t x = strlen (json);
        json [x-2] = 0;
    }
    s_string_append (&json, &jsonsize, "]");
    return json;
}

//  --------------------------------------------------------------------------
//  Convert rule back to json
//  Caller is responsible for destroying the return value

char *
rule_json (rule_t *self)
{
    if (!self) return NULL;

    char *json = NULL;
    size_t jsonsize = 0;
    {
        //json start + name
        char *jname = vsjson_encode_string (self->name);
        s_string_append (&json, &jsonsize, "{\n\"name\":");
        s_string_append (&json, &jsonsize, jname);
        s_string_append (&json, &jsonsize, ",\n");
        zstr_free (&jname);
    }
    {
        char *desc = vsjson_encode_string (self->description ? self->description : "");
        s_string_append (&json, &jsonsize, "\"description\":");
        s_string_append (&json, &jsonsize, desc);
        s_string_append (&json, &jsonsize, ",\n");
        zstr_free (&desc);
    }
    {
        char *logical_asset = vsjson_encode_string (self->logical_asset ? self->logical_asset : "");
        s_string_append (&json, &jsonsize, "\"logical_asset\":");
        s_string_append (&json, &jsonsize, logical_asset);
        s_string_append (&json, &jsonsize, ",\n");
        zstr_free (&logical_asset);
    }
    {
        //metrics
        char *tmp = s_zlist_to_json_array (self->metrics);
        s_string_append (&json, &jsonsize, "\"metrics\":");
        s_string_append (&json, &jsonsize, tmp);
        s_string_append (&json, &jsonsize, ",\n");
        zstr_free (&tmp);
    }
    {
        //assets
        char *tmp = s_zlist_to_json_array (self->assets);
        s_string_append (&json, &jsonsize, "\"assets\":");
        s_string_append (&json, &jsonsize, tmp);
        s_string_append (&json, &jsonsize, ",\n");
        zstr_free (&tmp);
    }
    {
        //models
        char *tmp = s_zlist_to_json_array (self->models);
        s_string_append (&json, &jsonsize, "\"models\":");
        s_string_append (&json, &jsonsize, tmp);
        s_string_append (&json, &jsonsize, ",\n");
        zstr_free (&tmp);
    }
    {
        //groups
        char *tmp = s_zlist_to_json_array (self->groups);
        s_string_append (&json, &jsonsize, "\"groups\":");
        s_string_append (&json, &jsonsize, tmp);
        s_string_append (&json, &jsonsize, ",\n");
        zstr_free (&tmp);
    }
    {
        //results
        s_string_append (&json, &jsonsize, "\"results\": {\n");
        const void *result = zhash_first (self->result_actions);
        bool first = true;
        while (result) {
            if (first) {
                first = false;
            } else {
                s_string_append (&json, &jsonsize, ",\n");
            }
            char *key = vsjson_encode_string (zhash_cursor (self->result_actions));
            char *tmp = s_actions_to_json_array ((zlist_t *)result);
            s_string_append (&json, &jsonsize, key);
            s_string_append (&json, &jsonsize, ": {\"action\": ");
            s_string_append (&json, &jsonsize, tmp);
            s_string_append (&json, &jsonsize, "}");
            zstr_free (&tmp);
            zstr_free (&key);
            result = zhash_next (self->result_actions);
        }
        s_string_append (&json, &jsonsize, "},\n");
    }
    {
        //variables
        if (zhashx_size (self->variables)) {
            s_string_append (&json, &jsonsize, "\"variables\": {\n");
            char *item = (char *)zhashx_first (self->variables);
            bool first = true;
            while (item) {
                if (first) {
                    first = false;
                } else {
                    s_string_append (&json, &jsonsize, ",\n");
                }
                char *key = vsjson_encode_string((char *)zhashx_cursor (self->variables));
                char *value = vsjson_encode_string (item);
                s_string_append (&json, &jsonsize, key);
                s_string_append (&json, &jsonsize, ":");
                s_string_append (&json, &jsonsize, value);
                zstr_free (&key);
                zstr_free (&value);
                item = (char *) zhashx_next (self->variables);
            }
            s_string_append (&json, &jsonsize, "},\n");
        }
    }
    {
        //json evaluation
        char *eval = vsjson_encode_string (self->evaluation);
        s_string_append (&json, &jsonsize, "\"evaluation\":");
        s_string_append (&json, &jsonsize, eval);
        s_string_append (&json, &jsonsize, "\n}\n");
        zstr_free (&eval);
    }
    return json;
}

//  --------------------------------------------------------------------------
//  Destroy the rule

void
rule_destroy (rule_t **self_p)
{
    assert (self_p);
    if (*self_p) {
        rule_t *self = *self_p;
        //  Free class properties here
        zstr_free (&self->name);
        zstr_free (&self->description);
        zstr_free (&self->logical_asset);
        zstr_free (&self->evaluation);
        if (self->lua) lua_close (self->lua);
        zlist_destroy (&self->metrics);
        zlist_destroy (&self->assets);
        zlist_destroy (&self->groups);
        zlist_destroy (&self->models);
        zlist_destroy (&self->types);
        zhash_destroy (&self->result_actions);
        zhashx_destroy (&self->variables);
        //  Free object itself
        free (self);
        *self_p = NULL;
    }
}

//  --------------------------------------------------------------------------
//  Self test of this class

void
vsjson_test (bool verbose)
{
    printf (" * vsjson: skip\n");
}

void json_rule_test(const char *dir, const char *basename)
{
    rule_t *self = rule_new ();
    assert (self);
    char *rule_file = zsys_sprintf ("%s/rules/%s.rule", dir, basename);
    char *json_file = zsys_sprintf ("%s/rules/%s.json", dir, basename);
    assert (rule_file && json_file);
    rule_load (self, rule_file);
    zstr_free (&rule_file);
    FILE *f;
    char *stock_json;
    assert (f = fopen (json_file, "r"));
    assert (stock_json = (char *)calloc (1, 4096));
    assert (fread (stock_json, 1, 4096, f));
    fclose (f);
    zstr_free (&json_file);
    // test rule to json
    char *json = rule_json (self);
    // XXX: This is fragile, as we require the json to be bit-identical.
    // If you get an error here, manually review the actual difference.
    // In particular, the hash order is not stable
    if (!streq (json, stock_json)) {
        fprintf (stderr, "Generated json is different\nEXPECTED:\n%sGOT:\n%s",
                stock_json, json);
        abort ();
    }
    zstr_free (&stock_json);
    rule_t *rule = rule_new ();
    rule_parse (rule, json);
    char *json2 = rule_json (rule);
    assert (streq (rule_name(rule), rule_name (self)));
    if (!streq (json, json2)) {
        fprintf (stderr, "Generated json differs after second pass\nEXPECTED:\n%sGOT:\n%s",
                json, json2);
        abort ();
    }
    rule_destroy (&rule);
    zstr_free (&json);
    zstr_free (&json2);
    rule_destroy (&self);
}

void
rule_test (bool verbose)
{
    printf (" * rule: \n");

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
    char *rule_file = NULL;

    //  @selftest
    //  Simple create/destroy test
    {
        printf ("      Simple create/destroy test ... ");
        rule_t *self = rule_new ();
        assert (self);
        rule_destroy (&self);
        assert (self == NULL);
        printf ("      OK\n");
    }

    //  Load test #1
    {
        printf ("      Load test #1 ... ");
        rule_t *self = rule_new ();
        assert (self);
        rule_file = zsys_sprintf ("%s/rules/%s", SELFTEST_DIR_RO, "load.rule");
        assert (rule_file);
        rule_load (self, rule_file);
        zstr_free (&rule_file);
        rule_destroy (&self);
        assert (self == NULL);
        printf ("      OK\n");
    }

    //  Load test #2 - tests 'variables' section
    {
        printf ("      Load test #2 - 'variables' section ... ");
        rule_t *self = rule_new ();
        assert (self);
        rule_file = zsys_sprintf ("%s/rules/%s", SELFTEST_DIR_RO, "threshold.rule");
        assert (rule_file);
        rule_load (self, rule_file);
        zstr_free (&rule_file);

        //  prepare expected 'variables' hash
        zhashx_t *expected = zhashx_new ();
        assert (expected);
        zhashx_set_duplicator (self->variables, (zhashx_duplicator_fn *) strdup);
        zhashx_set_destructor (self->variables, (zhashx_destructor_fn *) zstr_free);

        zhashx_insert (expected, "high_critical", (void *) "60");
        zhashx_insert (expected, "high_warning", (void *) "40");
        zhashx_insert (expected, "low_warning", (void *) "15");
        zhashx_insert (expected, "low_critical", (void *) "5");

        //  compare it against loaded 'variables'
        const char *item = (const char *) zhashx_first (self->variables);
        while (item) {
            const char *key = (const char *) zhashx_cursor (self->variables);
            const char *expected_value = (const char *) zhashx_lookup (expected, key);
            assert (expected_value);
            assert (streq (item, expected_value));
            zhashx_delete (expected, key);
            item = (const char *) zhashx_next (self->variables);
        }
        assert (zhashx_size (expected) == 0);
        zhashx_destroy (&expected);
        rule_destroy (&self);
        assert (self == NULL);
        printf ("      OK\n");
    }

    printf ("      Load test #3 - json construction test ... ");
    json_rule_test (SELFTEST_DIR_RO, "test");
    printf ("      OK\n");

    printf ("      Load test #4 - old json format ... ");
    json_rule_test (SELFTEST_DIR_RO, "old");
    printf ("      OK\n");
    //  @end
    printf ("OK\n");
}
