/*  =========================================================================
    flexible_alert - Main class for evaluating alerts

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
#include <malamute.h>

struct flexible_alert_t
{
    zhash_t*      rules;
    zhash_t*      assets;
    zhash_t*      metrics;
    zhash_t*      enames;
    mlm_client_t* mlm;
};

// Flexible alert actor
void flexible_alert_actor(zsock_t* pipe, void* args);

flexible_alert_t* flexible_alert_new(void);
void flexible_alert_destroy(flexible_alert_t** self_p);
