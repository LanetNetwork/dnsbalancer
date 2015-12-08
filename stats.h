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

#ifndef __STATS_H__
#define __STATS_H__

#include <dnsbalancer.h>

#define DB_LATENCY_FIRST	7
#define DB_LATENCY_LAST		23
#define DB_LATENCY_BUCKETS	(DB_LATENCY_LAST - DB_LATENCY_FIRST + 1)

typedef struct db_latency_stats
{
	// 2^7...2^23,MAX us, 18 cells
	uint64_t lats[DB_LATENCY_BUCKETS + 1];
	pthread_spinlock_t lats_lock[DB_LATENCY_BUCKETS + 1];
} db_latency_stats_t;

void db_stats_frontend_in(db_frontend_t* _frontend, uint64_t _delta_bytes) __attribute__((nonnull(1)));
void db_stats_frontend_in_invalid(db_frontend_t* _frontend, uint64_t _delta_bytes) __attribute__((nonnull(1)));
void db_stats_frontend_out(db_frontend_t* _frontend, uint64_t _delta_bytes, ldns_pkt_rcode _rcode) __attribute__((nonnull(1)));
void db_stats_forwarder_in(db_forwarder_t* _forwarder, uint64_t _delta_bytes) __attribute__((nonnull(1)));
void db_stats_forwarder_out(db_forwarder_t* _forwarder, uint64_t _delta_bytes, ldns_pkt_rcode _rcode) __attribute__((nonnull(1)));
void db_stats_latency_update(struct timespec _ctime);
void db_stats_init(db_local_context_t* _ctx) __attribute__((nonnull(1)));
void db_stats_done(void);

#endif /* __STATS_H__ */

