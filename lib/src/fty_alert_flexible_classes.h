/*  =========================================================================
    fty_alert_flexible_classes - private header file

    Copyright (C) 2016 - 2017 Tomas Halman
    Copyright (C) 2017 - 2020 Eaton

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

#ifndef FTY_ALERT_FLEXIBLE_CLASSES_H_INCLUDED
#define FTY_ALERT_FLEXIBLE_CLASSES_H_INCLUDED

//  External dependencies
#include <lua.h>
#include <czmq.h>
#include <malamute.h>
#include <fty_log.h>
#include <fty_common.h>
#include <ftyproto.h>
#include <cxxtools/allocator.h>
#include <fty_shm.h>

#if 0

//  Opaque class structures to allow forward references
#ifndef RULE_T_DEFINED
typedef struct _rule_t rule_t;
#define RULE_T_DEFINED
#endif
#ifndef VSJSON_T_DEFINED
typedef struct _vsjson_t vsjson_t;
#define VSJSON_T_DEFINED
#endif
#ifndef METRICS_T_DEFINED
typedef struct _metrics_t metrics_t;
#define METRICS_T_DEFINED
#endif

#endif //0

#if defined (__WINDOWS__)
#   if defined FTY_ALERT_FLEXIBLE_STATIC
#       define FTY_ALERT_FLEXIBLE_EXPORT
#   elif defined FTY_ALERT_FLEXIBLE_INTERNAL_BUILD
#       if defined DLL_EXPORT
#           define FTY_ALERT_FLEXIBLE_EXPORT __declspec(dllexport)
#       else
#           define FTY_ALERT_FLEXIBLE_EXPORT
#       endif
#   elif defined FTY_ALERT_FLEXIBLE_EXPORTS
#       define FTY_ALERT_FLEXIBLE_EXPORT __declspec(dllexport)
#   else
#       define FTY_ALERT_FLEXIBLE_EXPORT __declspec(dllimport)
#   endif
#   define FTY_ALERT_FLEXIBLE_PRIVATE
#elif defined (__CYGWIN__)
#   define FTY_ALERT_FLEXIBLE_EXPORT
#   define FTY_ALERT_FLEXIBLE_PRIVATE
#else
#   if (defined __GNUC__ && __GNUC__ >= 4) || defined __INTEL_COMPILER
#       define FTY_ALERT_FLEXIBLE_PRIVATE __attribute__ ((visibility ("hidden")))
#       define FTY_ALERT_FLEXIBLE_EXPORT __attribute__ ((visibility ("default")))
#   else
#       define FTY_ALERT_FLEXIBLE_PRIVATE
#       define FTY_ALERT_FLEXIBLE_EXPORT
#   endif
#endif

//  Internal API
#include "fty_alert_flexible_audit_log.h"
#include "vsjson.h"
#include "rule.h"
#include "flexible_alert.h"


#if 0

//  *** To avoid double-definitions, only define if building without draft ***
#ifndef FTY_ALERT_FLEXIBLE_BUILD_DRAFT_API

//  *** Draft method, defined for internal use only ***
//  Self test of this class.
FTY_ALERT_FLEXIBLE_PRIVATE void
    rule_test (bool verbose);

//  *** Draft method, defined for internal use only ***
//  Self test of this class.
FTY_ALERT_FLEXIBLE_PRIVATE void
    vsjson_test (bool verbose);

//  *** Draft method, defined for internal use only ***
//  Self test of this class.
FTY_ALERT_FLEXIBLE_PRIVATE void
    metrics_test (bool verbose);

//  Self test for private classes
FTY_ALERT_FLEXIBLE_PRIVATE void
    fty_alert_flexible_private_selftest (bool verbose, const char *subtest);

#endif // FTY_ALERT_FLEXIBLE_BUILD_DRAFT_API
#endif //0

#endif
