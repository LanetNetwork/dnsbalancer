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

#include "types.h"

#include "contrib/pfcq/pfcq.h"

struct db_request_data db_make_request_data(ldns_pkt* _packet, int _forwarder_socket) __attribute__((nonnull(1)));
int db_compare_request_data(struct db_request_data _data1, struct db_request_data _data2);
struct db_request* db_make_request(ldns_pkt* _packet, struct db_request_data _data, pfcq_net_address_t _address, size_t _forwarder_index) __attribute__((nonnull(1)));
uint16_t db_insert_request(struct db_request_list* _list, struct db_request* _request) __attribute__((nonnull(1, 2)));
struct db_request* db_eject_request(struct db_request_list* _list, uint16_t _index, struct db_request_data _data) __attribute__((nonnull(1)));
void db_remove_request_unsafe(struct db_request_list* _list, uint16_t _index, struct db_request* _request) __attribute__((nonnull(1, 3)));

#endif /* __REQUEST_H__ */

