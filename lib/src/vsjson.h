/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <tomas@halman.net> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Tomas Halman
 * ----------------------------------------------------------------------------
 * this source can be found at https://github.com/thalman/vsjson
 */

#ifndef __VSJSON_H
#define __VSJSON_H

#ifdef __cplusplus
extern "C" {
#endif

typedef int (vsjson_callback_t)(const char *locator, const char *value, void *data);

FTY_ALERT_FLEXIBLE_PRIVATE int
    vsjson_parse (const char *json, vsjson_callback_t *func, void *data, bool callWhenEmpty);

FTY_ALERT_FLEXIBLE_PRIVATE char*
    vsjson_decode_string (const char *string);

FTY_ALERT_FLEXIBLE_PRIVATE char*
    vsjson_encode_string (const char *string);

FTY_ALERT_FLEXIBLE_PRIVATE char*
    vsjson_encode_nstring (const char *string, size_t len);

#ifdef __cplusplus
}
#endif

#endif // __VSJSON_H
