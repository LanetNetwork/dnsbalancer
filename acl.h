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

#ifndef __ACL_H__
#define __ACL_H__

#include "types.h"

void db_acl_free_item(struct db_acl_item* _item) __attribute__((nonnull(1)));
void db_acl_free_list_item(struct db_list_item* _item) __attribute__((nonnull(1)));
enum db_acl_action db_check_query_acl(sa_family_t _layer3, pfcq_net_address_t* _address, struct db_request_data* _request_data, struct db_acl* _acl,
	void** _acl_data, size_t* _acl_data_length) __attribute__((nonnull(2, 3, 4, 5, 6)));

#endif /* __ACL_H__ */

