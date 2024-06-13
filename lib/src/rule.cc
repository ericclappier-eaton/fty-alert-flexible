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
#include <fty_log.h>
#include <cxxtools/serializationinfo.h>
#include "fty_common_json.h"
#include <string>
#include <map>

struct _rule_t
{
    char*      name;
    char*      description;
    char*      logical_asset;
    zlist_t*   metrics;
    zlist_t*   assets;
    zlist_t*   groups;
    zlist_t*   models;
    zlist_t*   types;
    zhash_t*   result_actions;
    zhashx_t*  variables; /// lua context global variables
    char*      evaluation;
    lua_State* lua;
};

static int strcmp_fn(void* i1, void* i2)
{
    return strcmp(reinterpret_cast<char*>(i1), reinterpret_cast<char*>(i2));
}

//  --------------------------------------------------------------------------
//  Create a new rule

rule_t* rule_new()
{
    rule_t* self = reinterpret_cast<rule_t*>(zmalloc(sizeof(rule_t)));
    if (!self) {
        return NULL;
    }
    memset(self, 0, sizeof(*self));

    //  Initialize class properties here
    self->metrics = zlist_new();
    zlist_autofree(self->metrics);
    zlist_comparefn(self->metrics, strcmp_fn);

    self->assets = zlist_new();
    zlist_autofree(self->assets);
    zlist_comparefn(self->assets, strcmp_fn);

    self->groups = zlist_new();
    zlist_autofree(self->groups);
    zlist_comparefn(self->groups, strcmp_fn);

    self->models = zlist_new();
    zlist_autofree(self->models);
    zlist_comparefn(self->models, strcmp_fn);

    self->types = zlist_new();
    zlist_autofree(self->types);
    zlist_comparefn(self->types, strcmp_fn);

    self->result_actions = zhash_new();

    //  variables
    self->variables = zhashx_new();
    zhashx_set_duplicator(self->variables, reinterpret_cast<zhashx_duplicator_fn*>(strdup));
    zhashx_set_destructor(self->variables, reinterpret_cast<zhashx_destructor_fn*>(zstr_free));

    return self;
}

//  --------------------------------------------------------------------------
//  zhash_freefn callback for result_actions list
static void zlist_freefn(void* p)
{
    if (p) {
        zlist_t* list = reinterpret_cast<zlist_t*>(p);
        zlist_destroy(&list);
    }
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
        zhash_freefn(self->result_actions, result, zlist_freefn);
    }
    if (action) {
        zlist_append(list, const_cast<char*>(action));
    }
}

//  Parse rule from JSON.
//  Returns 0 if ok, else failed
int rule_parse(rule_t* self, const char* json)
{
    if (!self) {
        log_error("self is NULL");
        return 2;
    }

    try {
        cxxtools::SerializationInfo si;
        JSON::readFromString(json, si);

        auto pf = si.findMember("flexible");
        if (!pf || pf->isNull()) {
            //log_debug("No flexible object defined");
            pf = &si; // parse the whole block
        }

        if (auto p = pf->findMember("name"); p && !p->isNull()) {
            std::string aux;
            *p >>= aux;
            zstr_free(&self->name);
            self->name = strdup(aux.c_str());
        }

        if (auto p = pf->findMember("description"); p && !p->isNull()) {
            std::string aux;
            *p >>= aux;
            zstr_free(&self->description);
            self->description = strdup(aux.c_str());
        }

        if (auto p = pf->findMember("logical_asset"); p && !p->isNull()) {
            std::string aux;
            *p >>= aux;
            zstr_free(&self->logical_asset);
            self->logical_asset = strdup(aux.c_str());
        }

        if (auto p = pf->findMember("metrics"); p && !p->isNull()) {
            if (p->category() != cxxtools::SerializationInfo::Category::Array) {
                throw std::runtime_error("'metrics' not an array");
            }
            std::vector<std::string> metrics;
            *p >>= metrics;
            for (const auto& it : metrics) {
                zlist_append(self->metrics, const_cast<char*>(it.c_str()));
            }
        }

        if (auto p = pf->findMember("assets"); p && !p->isNull()) {
            if (p->category() != cxxtools::SerializationInfo::Category::Array) {
                throw std::runtime_error("'assets' not an array");
            }
            std::vector<std::string> assets;
            *p >>= assets;
            for (const auto& it : assets) {
                zlist_append(self->assets, const_cast<char*>(it.c_str()));
            }
        }

        if (auto p = pf->findMember("groups"); p && !p->isNull()) {
            if (p->category() != cxxtools::SerializationInfo::Category::Array) {
                throw std::runtime_error("'groups' not an array");
            }
            std::vector<std::string> groups;
            *p >>= groups;
            for (const auto& it : groups) {
                zlist_append(self->groups, const_cast<char*>(it.c_str()));
            }
        }

        if (auto p = pf->findMember("models"); p && !p->isNull()) {
            if (p->category() != cxxtools::SerializationInfo::Category::Array) {
                throw std::runtime_error("'models' not an array");
            }
            std::vector<std::string> models;
            *p >>= models;
            for (const auto& it : models) {
                zlist_append(self->models, const_cast<char*>(it.c_str()));
            }
        }

        if (auto p = pf->findMember("types"); p && !p->isNull()) {
            if (p->category() != cxxtools::SerializationInfo::Category::Array) {
                throw std::runtime_error("'types' not an array");
            }
            std::vector<std::string> types;
            *p >>= types;
            for (const auto& it : types) {
                zlist_append(self->types, const_cast<char*>(it.c_str()));
            }
        }

        /**
        "results": {
          "high_warning": {"action": []},
          "low_critical": {"action": [{"action": "SMS"}, {"action": "GPO_INTERACTION", "asset": "gpo-42", "mode": "close"}]},
          "high_critical": {"action": [{"action": "EMAIL"}]}
        }
        **/

        if (auto p = pf->findMember("results"); p && !p->isNull()) {
            if (p->category() != cxxtools::SerializationInfo::Category::Object) {
                throw std::runtime_error("'results' not an object");
            }

            for (const auto& action : *p) { // loop on 'results' properties
                if (action.category() != cxxtools::SerializationInfo::Object) {
                    throw std::runtime_error("'results' property not an object");
                }
                std::string name = action.name();

                auto a = action.findMember("action");
                if (!a || a->isNull()) {
                    throw std::runtime_error("'action' not found (results/"+ name + ")");
                }
                if (a->category() != cxxtools::SerializationInfo::Category::Array) {
                    throw std::runtime_error("'action' not an array (results/"+ name + ")");
                }

                // create action list **empty**
                rule_add_result_action(self, name.c_str(), NULL);

                // loop on action array
                for (const auto& it : *a) {
                    std::string type;
                    if (it.category() == cxxtools::SerializationInfo::Category::Value) {
                        it >>= type; // old style ["EMAIL", "SMS"]
                    }
                    else { // new style [{"action": "EMAIL"}, {"action": "SMS"}]
                        it.getMember("action") >>= type; // "EMAIL", "SMS", ...
                        if (type == "GPO_INTERACTION") {
                            std::string asset, mode;
                            it.getMember("asset") >>= asset; // gpo-42
                            it.getMember("mode") >>= mode; // open
                            type += ":" + asset + ":" + mode;
                        }
                    }

                    rule_add_result_action(self, name.c_str(), type.c_str());
                }
            }
        }

        if (auto p = pf->findMember("evaluation"); p && !p->isNull()) {
            std::string aux;
            *p >>= aux;
            zstr_free(&self->evaluation);
            self->evaluation = strdup(aux.c_str());
        }

        if (auto p = pf->findMember("variables"); p && !p->isNull()) {
            for (const auto& variable : *p) { // loop on 'variables' properties
                std::string name, value;
                name = variable.name();
                variable >>= value;

                zhashx_insert(self->variables, name.c_str(), const_cast<char*>(value.c_str()));
            }
        }

        return 0; // ok
    }
    catch(const std::exception& e) {
        log_debug("JSON parse failed, json:\n%s", json);
        log_error("JSON parse exception reached: %s", e.what());
    }
    return 1; // failed
}

// Serialize rule to JSON
// Caller must free the returned string
char* rule_serialize(rule_t* self)
{
    if (!self) {
        return nullptr;
    }

    try {
        cxxtools::SerializationInfo si;

        //log_debug("== %s", "name, description, logical_asset");
        si.addMember("name") <<= self->name ? self->name : "";
        si.addMember("description") <<= self->description ? self->description : "";
        si.addMember("logical_asset") <<= self->logical_asset ? self->logical_asset : "";

        struct {
            std::string name;
            zlist_t* list;
        } lists[] = {
            { "metrics", self->metrics },
            { "assets", self->assets },
            { "models", self->models },
            { "groups", self->groups },
        };
        for (const auto& it : lists) {
            //log_debug("== %s", it.name.c_str());

            si.addMember(it.name).setCategory(cxxtools::SerializationInfo::Category::Array);
            auto p = si.findMember(it.name);

            char* item = reinterpret_cast<char*>(zlist_first(it.list));
            while (item) {
                p->addMember("") <<= item;
                item = reinterpret_cast<char*>(zlist_next(it.list));
            }
        }

        // results
        //log_debug("== %s", "results");
        {
            /**
            "results": {
              "high_warning": {"action": []},
              "low_critical": {"action": [{"action": "SMS"}, {"action": "GPO_INTERACTION", "asset": "gpo-42", "mode": "close"}]},
              "high_critical": {"action": [{"action": "EMAIL"}]}
            }
            **/
            si.addMember("results");
            auto re = si.findMember("results");

            void* result = zhash_first(self->result_actions);
            while (result) {
                const char* actionName = zhash_cursor(self->result_actions);

                re->addMember(actionName);
                auto p = re->findMember(actionName);
                p->addMember("action").setCategory(cxxtools::SerializationInfo::Category::Array);
                auto act = p->findMember("action");

                zlist_t* actions = reinterpret_cast<zlist_t*>(result);
                char* type = reinterpret_cast<char*>(zlist_first(actions));
                while (type) {
                    //log_debug("== results/%s/%s", actionName, type);

                    cxxtools::SerializationInfo item;

                    if (strchr(type, ':') == NULL) {
                        item.addMember("action") <<= type; // <action>
                    }
                    else { // GPO_INTERACTION
                        char* aux = strdup(type); // <action>:<asset>:<mode>
                        char *p0 = aux, *p1 = NULL;
                        p1 = strchr(p0, ':'); if (p1) { *p1 = 0; item.addMember("action") <<= p0; p0 = p1 + 1; }
                        p1 = strchr(p0, ':'); if (p1) { *p1 = 0; item.addMember("asset")  <<= p0; p0 = p1 + 1; }
                        item.addMember("mode") <<= p0;
                        zstr_free(&aux);
                    }

                    act->addMember("") <<= item;

                    type = reinterpret_cast<char*>(zlist_next(actions));
                }

                result = zhash_next(self->result_actions);
            }
        }

        // variables
        if (zhashx_size(self->variables) != 0) {
            //log_debug("== %s", "variables");
            si.addMember("variables");
            auto variables = si.findMember("variables");

            std::map<std::string, std::string> ordered_vars;
            char* value = reinterpret_cast<char*>(zhashx_first(self->variables));
            while (value) {
                const char* key = reinterpret_cast<const char*>(zhashx_cursor(self->variables));
                ordered_vars[key] = value ? value : "";
                value = reinterpret_cast<char*>(zhashx_next(self->variables));
            }

            for (const auto& var : ordered_vars) {
                //log_debug("== %s %s/%s", "variables", var.first.c_str(), var.second.c_str());
                variables->addMember(var.first) <<= var.second;
            }
        }

        //log_debug("== %s", "evaluation");
        si.addMember("evaluation") <<= self->evaluation ? self->evaluation : "";

        std::string json = JSON::writeToString(si, false);
        return strdup(json.c_str());
    }
    catch (const std::exception& e) {
        log_error("JSON serialize exception reached: %s", e.what());
    }

    return nullptr;
}

//  --------------------------------------------------------------------------
//  Get rule name

const char* rule_name(rule_t* self)
{
    return self ? self->name : NULL;
}

const char* rule_asset(rule_t* self)
{
    // asset from name
    const char* p = (self && self->name) ? strchr(self->name, '@') : NULL;
    return p ? (p + 1) : NULL;
}

//  --------------------------------------------------------------------------
//  Get the logical asset

const char* rule_logical_asset(rule_t* self)
{
    return self ? self->logical_asset : NULL;
}

//  --------------------------------------------------------------------------
//  Does rule contain this asset name?

bool rule_asset_exists(rule_t* self, const char* asset)
{
    return self && asset && zlist_exists(self->assets, const_cast<char*>(asset));
}

//  --------------------------------------------------------------------------
//  Does rule contain this group name?

bool rule_group_exists(rule_t* self, const char* group)
{
    return self && group && zlist_exists(self->groups, const_cast<char*>(group));
}


//  --------------------------------------------------------------------------
//  Does rule contain this metric?

bool rule_metric_exists(rule_t* self, const char* metric)
{
    return self && metric && zlist_exists(self->metrics, const_cast<char*>(metric));
}

//  --------------------------------------------------------------------------
//  Return the first metric. If there are no metrics, returns nullptr.

const char* rule_metric_first(rule_t* self)
{
    return reinterpret_cast<const char*>(self ? zlist_first(self->metrics) : NULL);
}

//  --------------------------------------------------------------------------
//  Return the next metric. If there are no (more) metrics, returns nullptr.

const char* rule_metric_next(rule_t* self)
{
    return reinterpret_cast<const char*>(self ? zlist_next(self->metrics) : NULL);
}

//  --------------------------------------------------------------------------
//  Does rule contain this model?

bool rule_model_exists(rule_t* self, const char* model)
{
    return self && model && zlist_exists(self->models, const_cast<char*>(model));
}


//  --------------------------------------------------------------------------
//  Does rule contain this type?

bool rule_type_exists(rule_t* self, const char* type)
{
    return self && type && zlist_exists(self->types, const_cast<char*>(type));
}

//  --------------------------------------------------------------------------
//  Get rule actions

zlist_t* rule_result_actions(rule_t* self, int result)
{
    zlist_t* list = nullptr;

    if (self) {
        const char* results = "";
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
            default:;
        }
        list = reinterpret_cast<zlist_t*>(zhash_lookup(self->result_actions, results));
    }
    return list;
}

//  --------------------------------------------------------------------------
//  Get rule variables (globals)
//  Caller is responsible for destroying the return value

zhashx_t* rule_variables(rule_t* self)
{
    return self ? zhashx_dup(self->variables) : NULL;
}

//  --------------------------------------------------------------------------
//  Load json rule from file
//  Returns 0 if ok
int rule_load(rule_t* self, const char* path)
{
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        log_error("can't open file %s (%s)", path, strerror(errno));
        return -1;
    }

    struct stat rstat;
    memset(&rstat, 0, sizeof(rstat));
    if (fstat(fd, &rstat) != 0) {
        log_error("can't stat file %s (%s)", path, strerror(errno));
        close(fd);
        return -1;
    }

    size_t capacity = size_t(rstat.st_size + 1);
    char* buffer = reinterpret_cast<char*>(zmalloc(capacity + 1));
    if (!buffer) {
        log_error("memory allocation failed");
        close(fd);
        return -1;
    }
    memset(buffer, 0, capacity + 1);

    ssize_t r = read(fd, buffer, capacity);
    close(fd);
    if (r == -1) {
        log_error("Error while reading rule %s", path);
        free(buffer);
        return -1;
    }

    buffer[capacity] = 0;
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
//  Returns 0 if ok
int rule_save(rule_t* self, const char* path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        log_error("open %s failed (%s)", path, strerror(errno));
        return -1;
    }
    char* json = rule_serialize(self);
    if (!json) {
        log_error("rule_serialize() failed");
        close(fd);
        return -2;
    }
    ssize_t r = write(fd, json, strlen(json));
    zstr_free(&json);
    close(fd);
    if (r == -1) {
        log_error("Error while writing rule %s", path);
        return -3;
    }
    return 0;
}

// ZZZ return 1 if ok, else 0
int rule_compile(rule_t* self)
{
    if (!self) {
        return 0;
    }

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

    return 1; // ok
}

//  --------------------------------------------------------------------------
//  Evaluate rule

void rule_evaluate(rule_t* self, zlist_t* params, const char* iname, const char* ename, int* result, char** message)
{
    if (result) {
        *result = RULE_ERROR;
    }
    if (message) {
        *message = nullptr;
    }

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
    int i = 0;
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
            *result = int(lua_tointeger(self->lua, -1));
            const char* msg = lua_tostring(self->lua, -2);
            if (msg) {
                *message = strdup(msg);
            }
        }
        else if (lua_isnumber(self->lua, -2)) {
            *result = int(lua_tointeger(self->lua, -2));
            const char* msg = lua_tostring(self->lua, -1);
            if (msg) {
                *message = strdup(msg);
            }
        }
        else {
            log_error("rule_evaluate: invalid content of self->lua.");
        }

        lua_pop(self->lua, 2);
    }
    else {
        log_error("rule_evaluate: lua_pcall %s failed (r: %d)", rule_name(self), r);
    }
}

//  --------------------------------------------------------------------------
//  Destroy the rule

void rule_destroy(rule_t** self_p)
{
    if (self_p && (*self_p)) {
        rule_t* self = *self_p;

        zstr_free(&self->name);
        zstr_free(&self->description);
        zstr_free(&self->logical_asset);
        zstr_free(&self->evaluation);
        if (self->lua) {
            lua_close(self->lua);
        }
        zlist_destroy(&self->metrics);
        zlist_destroy(&self->assets);
        zlist_destroy(&self->groups);
        zlist_destroy(&self->models);
        zlist_destroy(&self->types);
        zhash_destroy(&self->result_actions);
        zhashx_destroy(&self->variables);

        free(self);
        *self_p = nullptr;
    }
}
