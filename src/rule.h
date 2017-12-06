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

#ifndef RULE_H_INCLUDED
#define RULE_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#define RULE_ERROR 255

//  Opaque class structures to allow forward references
#ifndef RULE_T_DEFINED
typedef struct _rule_t rule_t;
#define RULE_T_DEFINED
#endif

//  @interface
//  Create a new rule
FTY_ALERT_FLEXIBLE_PRIVATE rule_t *
    rule_new (void);

//  Destroy the rule
FTY_ALERT_FLEXIBLE_PRIVATE void
    rule_destroy (rule_t **self_p);

//  Self test of this class
FTY_ALERT_FLEXIBLE_PRIVATE void
    rule_test (bool verbose);

//  Self test of this class
FTY_ALERT_FLEXIBLE_PRIVATE void
    vsjson_test (bool verbose);

//  Parse json rule from string
FTY_ALERT_FLEXIBLE_PRIVATE int
    rule_parse (rule_t *self, const char *json);

//  Get rule name
FTY_ALERT_FLEXIBLE_PRIVATE const char *
    rule_name (rule_t *self);

//  Does rule contain this asset name?
FTY_ALERT_FLEXIBLE_PRIVATE bool
    rule_asset_exists (rule_t *self, const char *asset);

//  Does rule contain this group name?
FTY_ALERT_FLEXIBLE_PRIVATE bool
    rule_group_exists (rule_t *self, const char *group);

//  Does rule contain this metric?
FTY_ALERT_FLEXIBLE_PRIVATE bool
    rule_metric_exists (rule_t *self, const char *metric);

//  Return the first metric. If there are no metrics, returns NULL.
FTY_ALERT_FLEXIBLE_PRIVATE const char *
    rule_metric_first (rule_t *self);

//  Return the next metric. If there are no (more) metrics, returns NULL.
FTY_ALERT_FLEXIBLE_PRIVATE const char *
    rule_metric_next (rule_t *self);

//  Does rule contain this model?
FTY_ALERT_FLEXIBLE_PRIVATE bool
    rule_model_exists (rule_t *self, const char *model);

//  Does rule contain this type?
FTY_ALERT_FLEXIBLE_PRIVATE bool
    rule_type_exists (rule_t *self, const char *type);

//  Get rule actions
FTY_ALERT_FLEXIBLE_PRIVATE zlist_t *
    rule_result_actions (rule_t *self, int result);

//  Get global variables
//  Caller is responsible for destroying the return value
FTY_ALERT_FLEXIBLE_PRIVATE zhashx_t *
    rule_global_variables (rule_t *self);

//  Load json rule from file
FTY_ALERT_FLEXIBLE_PRIVATE int
    rule_load (rule_t *self, const char *path);

//  Save json rule to file
FTY_ALERT_FLEXIBLE_PRIVATE int
    rule_save (rule_t *self, const char *path);

//  Convert rule back to json
//  Caller is responsible for destroying the return value
FTY_ALERT_FLEXIBLE_PRIVATE char *
    rule_json (rule_t *self);

//  Evaluate rule
FTY_ALERT_FLEXIBLE_PRIVATE void
rule_evaluate (rule_t *self, zlist_t *params, const char *iname, const char *ename, int *result, char **message);

//  @end

#ifdef __cplusplus
}
#endif

#endif
