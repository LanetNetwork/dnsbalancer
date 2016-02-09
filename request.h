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

#ifndef __REQUEST_H__
#define __REQUEST_H__

#include <ldns/ldns.h>
#include <limits.h>
#include <pfcq.h>
#include <sys/queue.h>

typedef struct db_request_data
{
	ldns_rr_type rr_type;
	ldns_rr_class rr_class;
	char fqdn[HOST_NAME_MAX];
	int forwarder_socket;
	uint64_t hash;
} db_request_data_t;

struct db_request
{
	TAILQ_ENTRY(db_request) tailq;
	uint16_t original_id;
	db_request_data_t data;
	pfcq_net_address_t client_address;
	struct timespec ctime;
	size_t forwarder_index;
};

TAILQ_HEAD(db_requests, db_request);

typedef struct db_request_bucket
{
	struct db_requests requests;
	size_t requests_count;
	pthread_mutex_t requests_lock;
} db_request_bucket_t;

typedef struct db_request_list
{
	db_request_bucket_t list[UINT16_MAX + 1];
	uint16_t list_index;
	pthread_spinlock_t list_index_lock;
	uint64_t ttl;
} db_request_list_t;

db_request_data_t db_make_request_data(ldns_pkt* _packet, int _forwarder_socket) __attribute__((nonnull(1)));
int db_compare_request_data(db_request_data_t _data1, db_request_data_t _data2);
struct db_request* db_make_request(ldns_pkt* _packet, db_request_data_t _data, pfcq_net_address_t _address, size_t _forwarder_index) __attribute__((nonnull(1)));
uint16_t db_insert_request(db_request_list_t* _list, struct db_request* _request) __attribute__((nonnull(1, 2)));
struct db_request* db_eject_request(db_request_list_t* _list, uint16_t _index, db_request_data_t _data) __attribute__((nonnull(1)));
void db_remove_request_unsafe(db_request_list_t* _list, uint16_t _index, struct db_request* _request) __attribute__((nonnull(1, 3)));

#endif /* __REQUEST_H__ */

