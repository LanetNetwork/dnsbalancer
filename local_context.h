/* vim: set tabstop=4:softtabstop=4:shiftwidth=4:noexpandtab */

/*
 * dnsbalancer - daemon to balance UDP DNS requests over DNS servers
 * Initially created under patronage of Lanet Network
 * Programmed by Oleksandr Natalenko <oleksandr@natalenko.name>, 2015-2017
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#ifndef __LOCAL_CONTEXT_H__
#define __LOCAL_CONTEXT_H__

#include "types.h"

struct db_local_context* db_local_context_load(const char* _config_file, struct db_global_context* _g_ctx) __attribute__((nonnull(1, 2)));
void db_local_context_unload(struct db_local_context* _l_ctx) __attribute__((nonnull(1)));

#endif /* __LOCAL_CONTEXT_H__ */

