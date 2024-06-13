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

#pragma once

#include <czmq.h>
#include <lua.hpp>

#define RULE_ERROR 255

/// opacified structure
typedef struct _rule_t rule_t;

/// Create a new rule
rule_t* rule_new(void);

/// Destroy the rule
void rule_destroy(rule_t** self_p);

/// Parse rule from json string
int rule_parse(rule_t* self, const char* json);

/// Serialize rule to json
/// Caller must free the returned string
char* rule_serialize(rule_t* self);

/// Get rule name
const char* rule_name(rule_t* self);

/// Get rule asset from rule name
const char* rule_asset(rule_t* self);

/// Get the logical asset
const char* rule_logical_asset(rule_t* self);

/// Does rule contain this asset name?
bool rule_asset_exists(rule_t* self, const char* asset);

/// Does rule contain this group name?
bool rule_group_exists(rule_t* self, const char* group);

/// Does rule contain this metric?
bool rule_metric_exists(rule_t* self, const char* metric);

/// Return the first metric. If there are no metrics, returns NULL.
const char* rule_metric_first(rule_t* self);

/// Return the next metric. If there are no (more) metrics, returns NULL.
const char* rule_metric_next(rule_t* self);

/// Does rule contain this model?
bool rule_model_exists(rule_t* self, const char* model);

/// Does rule contain this type?
bool rule_type_exists(rule_t* self, const char* type);

/// Get rule actions
zlist_t* rule_result_actions(rule_t* self, int result);

/// Get rule variables (globals)
/// Caller is responsible for destroying the return value
zhashx_t* rule_variables(rule_t* self);

/// Load json rule from file
int rule_load(rule_t* self, const char* path);

/// Update new_rule with configured actions of old_rule
void rule_merge(rule_t* old_rule, rule_t* new_rule);

/// Save json rule to file
int rule_save(rule_t* self, const char* path);

/// Evaluate rule
void rule_evaluate(rule_t* self, zlist_t* params, const char* iname, const char* ename, int* result, char** message);

/// ZZZ Returns 1 if ok
int rule_compile(rule_t* self);

