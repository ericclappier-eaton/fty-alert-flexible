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

#pragma once
#include <fty_proto.h>
#include <string>

/// opacified structure
typedef struct _asset_info_t asset_info_t;

/// create a new asset_info_t* object from ASSET fty_proto_t* object
/// returns a valid object if success, else NULL
/// returned object must be destroyed by caller
asset_info_t* asset_info_new(fty_proto_t* asset);

/// destroy an asset_info_t* object
/// self_p nullified
void asset_info_destroy(asset_info_t** self_p);

/// says if the given ASSET is described in self locations
/// returns 1 if yes, else 0
int asset_info_isInLocations(asset_info_t* self, const char* asset);

/// DBG, dump asset locations
std::string asset_info_dumpLocations(asset_info_t* self);
