/* vim: set tabstop=4:softtabstop=4:shiftwidth=4:noexpandtab */

/*
 * dnsbalancer - daemon to balance UDP DNS requests over DNS servers
 * Copyright (C) 2015 Lanet Network
 * Programmed by Oleksandr Natalenko <o.natalenko@lanet.ua>
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

#ifndef __GLOBAL_CONTEXT_H__
#define __GLOBAL_CONTEXT_H__

#include <dnsbalancer.h>

struct db_global_context
{
	db_request_list_t db_requests;
	pfpthq_pool_t* gc_pool;
	pthread_t gc_id;
	uint64_t db_gc_interval;
};

db_global_context_t* db_global_context_load(const char* _config_file) __attribute__((nonnull(1)));
void db_global_context_unload(db_global_context_t* _g_ctx) __attribute__((nonnull(1)));

#endif /* __GLOBAL_CONTEXT_H__ */

