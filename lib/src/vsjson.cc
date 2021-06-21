/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <tomas@halman.net> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Tomas Halman
 * ----------------------------------------------------------------------------
 * this source can be found at https://github.com/thalman/vsjson
 */

#include "vsjson.h"
#include <assert.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VSJSON_SEPARATOR '/'

struct _vsjson_t
{
    int         state;
    const char* cursor;
    char*       text;
    char*       token;
    int         tokensize;
};

typedef struct _vsjson_t vsjson_t;

static vsjson_t* vsjson_new(const char* json)
{
    if (!json)
        return nullptr;
    vsjson_t* self = reinterpret_cast<vsjson_t*>(malloc(sizeof(vsjson_t)));
    if (!self)
        return nullptr;

    memset(self, 0, sizeof(vsjson_t));
    self->text = strdup(json);
    return self;
}

static const char* _vsjson_set_token(vsjson_t* self, const char* ptr, size_t len)
{
    if (!ptr || !self)
        return nullptr;

    if (!len)
        len = strlen(ptr);
    if (self->tokensize > int(len + 1)) {
        // fits in
        strncpy(self->token, ptr, len);
        self->token[len] = 0;
        return self->token;
    }
    if (self->token) {
        free(self->token);
        self->token     = nullptr;
        self->tokensize = 0;
    }
    self->token = reinterpret_cast<char*>(malloc(len + 1));
    if (!self->token)
        return nullptr;
    strncpy(self->token, ptr, len);
    self->token[len] = 0;
    self->tokensize  = int(len + 1);
    return self->token;
}

[[maybe_unused]] static const char* _vsjson_seek_to_next_token(vsjson_t* self)
{
    if (!self)
        return nullptr;

    while (true) {
        if (self->cursor == nullptr)
            return nullptr;
        if (!isspace(self->cursor[0]))
            return self->cursor;
        self->cursor++;
    }
}

static const char* _vsjson_find_next_token(vsjson_t* self, const char* start)
{
    if (!self)
        return nullptr;

    const char* p = start;
    if (!start)
        p = self->text;
    while (true) {
        if (*p == 0)
            return nullptr;
        if (!isspace(*p))
            return p;
        p++;
    }
}

static const char* _vsjson_find_string_end(vsjson_t* self, const char* start)
{
    if (!self || !start)
        return nullptr;

    const char* p = start;
    if (*p != '"')
        return nullptr;
    ++p;
    while (true) {
        switch (*p) {
            case 0:
                return nullptr;
            case '\\':
                ++p;
                if (*p == 0)
                    return nullptr;
                break;
            case '"':
                return ++p;
        }
        ++p;
    }
}

static const char* _vsjson_find_number_end(vsjson_t* self, const char* start)
{
    if (!self || !start)
        return nullptr;

    const char* p = start;
    if (!(isdigit(*p) || *p == '-' || *p == '+'))
        return nullptr;
    ++p;
    while (true) {
        if (*p == 0)
            return nullptr;
        if (isdigit(*p) || *p == '.' || *p == 'e' || *p == 'E' || *p == '-' || *p == '+') {
            ++p;
        } else {
            return p;
        }
    }
}

static const char* _vsjson_find_keyword_end(vsjson_t* self, const char* start)
{
    if (!self || !start)
        return nullptr;

    const char* p = start;
    if (!isalpha(*p))
        return nullptr;
    ++p;
    while (true) {
        if (*p == 0)
            return p;
        if (isalpha(*p)) {
            ++p;
        } else {
            return p;
        }
    }
}

static const char* _vsjson_find_token_end(vsjson_t* self, const char* start)
{
    if (!self || !start)
        return nullptr;

    const char* p = start;
    if (strchr("{}[]:,", *p)) {
        return ++p;
    }
    if (*p == '"') {
        return _vsjson_find_string_end(self, p);
    }
    if (strchr("+-0123456789", *p)) {
        return _vsjson_find_number_end(self, p);
    }
    if (isalpha(*p)) {
        return _vsjson_find_keyword_end(self, p);
    }
    return nullptr;
}

static int vsjson_is_token_valid(vsjson_t* self)
{
    if (!self || !self->token)
        return 0;
    if (strchr("{}[]:,", self->token[0]) && (self->token[1] == 0)) {
        return 1;
    }
    if (strchr("+-0123456789", self->token[0])) {
        // TODO: validate json number?
        return 1;
    }
    switch (self->token[0]) {
        case '"':
            if (self->token[strlen(self->token) - 1] == '"' && strlen(self->token) >= 2) {
                return 1;
            }
            return 0;
        case 't':
            if (strcmp(self->token, "true") == 0)
                return 1;
            return 0;
        case 'f':
            if (strcmp(self->token, "false") == 0)
                return 1;
            return 0;
        case 'n':
            if (strcmp(self->token, "nullptr") == 0)
                return 1;
            return 0;
    }
    return 0;
}

static const char* vsjson_first_token(vsjson_t* self)
{
    if (!self)
        return nullptr;
    self->cursor = _vsjson_find_next_token(self, nullptr);
    if (!self->cursor)
        return nullptr;
    const char* p = _vsjson_find_token_end(self, self->cursor);
    if (p) {
        _vsjson_set_token(self, self->cursor, size_t(p - self->cursor));
        self->cursor = p;
        return self->token;
    }
    return nullptr;
}

static const char* vsjson_next_token(vsjson_t* self)
{
    if (!self)
        return nullptr;
    self->cursor = _vsjson_find_next_token(self, self->cursor);
    if (!self->cursor)
        return nullptr;
    const char* p = _vsjson_find_token_end(self, self->cursor);
    if (p) {
        _vsjson_set_token(self, self->cursor, size_t(p - self->cursor));
        self->cursor = p;
        return self->token;
    }
    return nullptr;
}

static void vsjson_destroy(vsjson_t** self_p)
{
    if (!self_p)
        return;
    if (!*self_p)
        return;
    vsjson_t* self = *self_p;
    if (self->text)
        free(self->text);
    if (self->token)
        free(self->token);
    free(self);
    *self_p = nullptr;
}

static int _vsjson_walk_array(
    vsjson_t* self, const char* prefix, vsjson_callback_t* func, void* data, bool callWhenEmpty);

static int _vsjson_walk_object(
    vsjson_t* self, const char* prefix, vsjson_callback_t* func, void* data, bool callWhenEmpty)
{
    int    result     = 0;
    int    itemscount = 0;
    char*  locator    = nullptr;
    char*  key        = nullptr;
    size_t s;

    const char* token = vsjson_next_token(self);
    while (token) {
        // token should be key or }
        switch (token[0]) {
            case '}':
                if (itemscount == 0 && callWhenEmpty) {
                    result = func(&prefix[1], nullptr, data);
                }
                goto cleanup;
            case '"':
                key = vsjson_decode_string(token);
                ++itemscount;
                token = vsjson_next_token(self);
                if (strcmp(token, ":") != 0) {
                    result = -1;
                    goto cleanup;
                }
                token = vsjson_next_token(self);
                if (!token) {
                    result = -1;
                    goto cleanup;
                }
                s       = strlen(prefix) + strlen(key) + 2;
                locator = reinterpret_cast<char*>(malloc(s));
                if (!locator) {
                    result = -2;
                    goto cleanup;
                }
                snprintf(locator, s, "%s%c%s", prefix, VSJSON_SEPARATOR, key);
                switch (token[0]) {
                    case '{':
                        result = _vsjson_walk_object(self, locator, func, data, callWhenEmpty);
                        if (result != 0)
                            goto cleanup;
                        break;
                    case '[':
                        result = _vsjson_walk_array(self, locator, func, data, callWhenEmpty);
                        if (result != 0)
                            goto cleanup;
                        break;
                    case ':':
                    case ',':
                    case '}':
                    case ']':
                        result = -1;
                        goto cleanup;
                    default:
                        // this is the value
                        if (vsjson_is_token_valid(self)) {
                            result = func(&locator[1], token, data);
                        } else {
                            result = -3;
                        }
                        if (result != 0)
                            goto cleanup;
                        break;
                }
                free(locator);
                locator = nullptr;
                free(key);
                key = nullptr;
                break;
            default:
                // this is wrong
                result = -1;
                goto cleanup;
        }
        token = vsjson_next_token(self);
        // now the token can be only '}' or ','
        if (!token) {
            result = -1;
            goto cleanup;
        }
        switch (token[0]) {
            case ',':
                token = vsjson_next_token(self);
                break;
            case '}':
                break;
            default:
                result = -1;
                goto cleanup;
        }
    }
cleanup:
    if (locator)
        free(locator);
    if (key)
        free(key);
    return result;
}

static int _vsjson_walk_array(
    vsjson_t* self, const char* prefix, vsjson_callback_t* func, void* data, bool callWhenEmpty)
{
    int   index   = 0;
    int   result  = 0;
    char* locator = nullptr;

    const char* token = vsjson_next_token(self);
    while (token) {
        size_t s = strlen(prefix) + 1 + sizeof(index) * 3 + 1;
        locator  = reinterpret_cast<char*>(malloc(s));
        if (!locator) {
            result = -2;
            goto cleanup;
        }
        snprintf(locator, s, "%s%c%i", prefix, VSJSON_SEPARATOR, index);
        // token should be value or ]
        switch (token[0]) {
            case ']':
                if (index == 0 && callWhenEmpty) {
                    result = func(&prefix[1], nullptr, data);
                }
                goto cleanup;
            case ':':
            case ',':
            case '}':
                result = -1;
                goto cleanup;
            case '{':
                result = _vsjson_walk_object(self, locator, func, data, callWhenEmpty);
                ++index;
                if (result != 0)
                    goto cleanup;
                break;
            case '[':
                result = _vsjson_walk_array(self, locator, func, data, callWhenEmpty);
                ++index;
                if (result != 0)
                    goto cleanup;
                break;
            default:
                if (vsjson_is_token_valid(self)) {
                    result = func(&locator[1], token, data);
                    ++index;
                } else {
                    result = -3;
                }
                if (result != 0)
                    goto cleanup;
                break;
        }
        free(locator);
        locator = nullptr;

        token = vsjson_next_token(self);
        // now the token can be only ']' or ','
        if (!token) {
            result = -1;
            goto cleanup;
        }
        switch (token[0]) {
            case ',':
                token = vsjson_next_token(self);
                break;
            case ']':
                break;
            default:
                result = -1;
                goto cleanup;
        }
    }
cleanup:
    if (locator)
        free(locator);
    return result;
}

static int vsjson_walk_trough(vsjson_t* self, vsjson_callback_t* func, void* data, bool callWhenEmpty)
{
    if (!self || !func)
        return -1;

    int result = 0;

    const char* token = vsjson_first_token(self);
    if (token) {
        switch (token[0]) {
            case '{':
                result = _vsjson_walk_object(self, "", func, data, callWhenEmpty);
                break;
            case '[':
                result = _vsjson_walk_array(self, "", func, data, callWhenEmpty);
                break;
            default:
                // this is simple json containing just string, number ...
                if (vsjson_is_token_valid(self)) {
                    result = func("", token, data);
                } else {
                    result = -1;
                }
                break;
        }
    }
    if (result == 0) {
        token = vsjson_next_token(self);
        if (token)
            result = -1;
    }
    return result;
}

char* vsjson_decode_string(const char* string)
{
    if (!string)
        return nullptr;

    char* decoded = reinterpret_cast<char*>(malloc(strlen(string)));
    if (!decoded)
        return nullptr;

    memset(decoded, 0, strlen(string));
    const char* src = string;
    char*       dst = decoded;

    if (string[0] != '"' || string[strlen(string) - 1] != '"') {
        // no quotes, this is not json string
        free(decoded);
        return nullptr;
    }
    ++src;
    while (*src) {
        switch (*src) {
            case '\\':
                ++src;
                switch (*src) {
                    case '\\':
                    case '/':
                    case '"':
                        *dst = *src;
                        ++dst;
                        break;
                    case 'b':
                        *dst = '\b';
                        ++dst;
                        break;
                    case 'f':
                        *dst = '\f';
                        ++dst;
                        break;
                    case 'n':
                        *dst = '\n';
                        ++dst;
                        break;
                    case 'r':
                        *dst = '\r';
                        ++dst;
                        break;
                    case 't':
                        *dst = '\t';
                        ++dst;
                        break;
                        // TODO \uXXXX
                }
                break;
            default:
                *dst = *src;
                ++dst;
        }
        ++src;
    }
    --dst;
    *dst = 0;
    return decoded;
}


char* vsjson_encode_string(const char* string)
{
    if (!string)
        return nullptr;
    return vsjson_encode_nstring(string, strlen(string));
}

char* vsjson_encode_nstring(const char* string, size_t len)
{
    if (!string)
        return nullptr;

    size_t      capacity = len + 15;
    int         index    = 1;
    const char* p        = string;

    char* encoded = reinterpret_cast<char*>(malloc(capacity));
    if (!encoded)
        return nullptr;
    memset(encoded, 0, capacity);
    encoded[0] = '"';
    while (*p && p - string < int(len)) {
        switch (*p) {
            case '"':
            case '\\':
            case '/':
                encoded[index++] = '\\';
                encoded[index++] = *p;
                break;
            case '\b':
                encoded[index++] = '\\';
                encoded[index++] = 'b';
                break;
            case '\f':
                encoded[index++] = '\\';
                encoded[index++] = 'f';
                break;
            case '\n':
                encoded[index++] = '\\';
                encoded[index++] = 'n';
                break;
            case '\r':
                encoded[index++] = '\\';
                encoded[index++] = 'r';
                break;
            case '\t':
                encoded[index++] = '\\';
                encoded[index++] = 't';
                break;
            default:
                encoded[index++] = *p;
                break;
                // TODO \uXXXX
        }
        p++;
        if (capacity - size_t(index) < 10) {
            size_t add = len - size_t(p - string) + 15;
            char*  ne  = reinterpret_cast<char*>(realloc(encoded, capacity + add));
            if (ne) {
                encoded = ne;
                memset(&encoded[capacity], 0, add);
                capacity += add;
            } else {
                free(encoded);
                return nullptr;
            }
        }
    }
    encoded[index] = '"';
    return encoded;
}

int vsjson_parse(const char* json, vsjson_callback_t* func, void* data, bool callWhenEmpty)
{
    if (!json || !func)
        return -1;
    vsjson_t* v = vsjson_new(json);
    int       r = vsjson_walk_trough(v, func, data, callWhenEmpty);
    vsjson_destroy(&v);
    return r;
}
