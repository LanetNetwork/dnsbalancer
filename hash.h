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

#ifndef __HASH_H__
#define __HASH_H__

#include <dnsbalancer.h>
#include <ldns/ldns.h>

typedef struct db_hash
{
	char* uniq;
	uint64_t crc;
} db_hash_t;

db_hash_t db_make_hash(ldns_pkt* _packet, ldns_rr* _rr, int _forwarder_socket) __attribute__((nonnull(1, 2)));
void db_free_hash(db_hash_t* _hash) __attribute__((nonnull(1)));
unsigned short int db_compare_hashes(db_hash_t* _hash1, db_hash_t* _hash2) __attribute__((nonnull(1, 2)));

#endif /* __HASH_H__ */

