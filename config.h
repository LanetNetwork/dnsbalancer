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

#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <ini_config.h>

typedef struct collection_item db_config_t;

db_config_t* db_config_open(const char* _filepath) __attribute__((nonnull(1)));
void db_config_close(db_config_t* _config) __attribute__((nonnull(1)));
uint64_t db_config_get_u64(db_config_t* _config, const char* _section, const char* _key, uint64_t _default) __attribute__((nonnull(1, 2, 3)));
int db_config_get_int(db_config_t* _config, const char* _section, const char* _key, int _default) __attribute__((nonnull(1, 2, 3)));
unsigned db_config_get_uint(db_config_t* _config, const char* _section, const char* _key, unsigned _default) __attribute__((nonnull(1, 2, 3)));
const char* db_config_get_cstr(db_config_t* _config, const char* _section, const char* _key) __attribute__((nonnull(1, 2)));
char** db_config_get_keys(db_config_t* _config, const char* _section, int* _size) __attribute__((nonnull(1, 2, 3)));
void db_config_free_keys(char** _keys) __attribute__((nonnull(1)));

#endif /* __CONFIG_H__ */

