/* vim: set tabstop=4:softtabstop=4:shiftwidth=4:noexpandtab */

/*
 * dnsbalancer - daemon to balance UDP DNS requests over DNS servers
 * Copyright (C) 2015-2016 Lanet Network
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

#ifndef __LOCAL_CONTEXT_H__
#define __LOCAL_CONTEXT_H__

#include "dnsbalancer.h"

struct db_local_context
{
	db_frontend_t** frontends;
	size_t frontends_count;
	pfpthq_pool_t* watchdog_pool;
	pthread_t watchdog_id;
	uint64_t db_watchdog_interval;
	unsigned short int stats_enabled;
	sa_family_t stats_layer3_family;
	pfcq_net_address_t stats_address;
};

db_local_context_t* db_local_context_load(const char* _config_file, db_global_context_t* _g_ctx) __attribute__((nonnull(1, 2)));
void db_local_context_unload(db_local_context_t* _l_ctx) __attribute__((nonnull(1)));

#endif /* __LOCAL_CONTEXT_H__ */

