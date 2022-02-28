/*  =========================================================================
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

#include "asset_info.h"
#include <fty_log.h>
#include <czmq.h>

// zlist_t compare locations items (char*)
// required by zlist_first() usage
static int locations_cmp_fn(void *item1, void *item2)
{
    char* s1 = static_cast<char*>(item1);
    char* s2 = static_cast<char*>(item2);
    return strcmp(s1, s2);
}

struct _asset_info_t
{
    zlist_t* locations;
};

asset_info_t* asset_info_new(fty_proto_t* asset)
{
    if (!(asset && (fty_proto_id(asset) == FTY_PROTO_ASSET))) {
        log_error("invalid asset proto");
        return NULL;
    }

    asset_info_t* self = static_cast<asset_info_t*>(zmalloc(sizeof(*self)));
    if (!self) {
        log_error("zmalloc failed");
        return NULL;
    }
    memset(self, 0, sizeof(*self));

    // asset locations, inspect aux attributes 'parent_name.X' (X in [1..4]])
    self->locations = zlist_new(); // list of iname (strings)
    zlist_autofree(self->locations);
    zlist_comparefn(self->locations, locations_cmp_fn);
    for (int i = 1; i <= 4; i++) {
        char auxName[32];
        snprintf(auxName, sizeof(auxName), "parent_name.%d", i);
        const char* parentiName = fty_proto_aux_string(asset, auxName, NULL);
        if (parentiName) {
            zlist_append(self->locations, const_cast<char*>(parentiName));
        }
    }

    return self; // ok
}

void asset_info_destroy(asset_info_t** self_p)
{
    if (!(self_p && (*self_p)))
        return;

    asset_info_t* self = *self_p;
    zlist_destroy(&self->locations);
    memset(self, 0, sizeof(*self));
    free(self);
    *self_p = NULL;
}

int asset_info_isInLocations(asset_info_t* self, const char* asset)
{
    return (self && self->locations) ? zlist_exists(self->locations, const_cast<char*>(asset)) : 0;
}

std::string asset_info_dumpLocations(asset_info_t* self)
{
    std::string aux;
    if (self) {
        for (void* item = zlist_first(self->locations); item; item = zlist_next(self->locations))
        {
            char* iname = static_cast<char*>(item);
            aux += (aux.empty() ? "" : ", ") + std::string(iname);
        }
    }
    return aux;
}
