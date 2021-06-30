/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <tomas@halman.net> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Tomas Halman
 * ----------------------------------------------------------------------------
 * this source can be found at https://github.com/thalman/vsjson
 */

#pragma once
#include <czmq.h>

typedef int(vsjson_callback_t)(const char* locator, const char* value, void* data);

int vsjson_parse(const char* json, vsjson_callback_t* func, void* data, bool callWhenEmpty);

char* vsjson_decode_string(const char* string);

char* vsjson_encode_string(const char* string);

char* vsjson_encode_nstring(const char* string, size_t len);
