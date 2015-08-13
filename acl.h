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

#ifndef __ACL_H__
#define __ACL_H__

#include <errno.h>
#include <hash.h>
#include <netinet/in.h>
#include <pfcq.h>
#include <regex.h>
#include <sys/queue.h>
#include <sys/socket.h>

typedef enum db_acl_action
{
	DB_ACL_ACTION_ALLOW,
	DB_ACL_ACTION_DENY
} db_acl_action_t;

struct db_acl_item
{
	TAILQ_ENTRY(db_acl_item) tailq;
	char* s_layer3;
	char* s_address;
	char* s_netmask;
	char* s_regex;
	char* s_action;
	sa_family_t layer3;
	int __padding1:32;
	pfcq_in_address_t address;
	pfcq_in_address_t netmask;
	regex_t regex;
	db_acl_action_t action;
	pthread_spinlock_t hits_lock;
	uint64_t hits;
};

TAILQ_HEAD(db_acl, db_acl_item);

db_acl_action_t db_check_query_acl(sa_family_t _layer3, pfcq_net_address_t* _address, db_prehash_t* _prehash, struct db_acl* _acl) __attribute__((nonnull(2, 3, 4)));

#endif /* __ACL_H__ */

