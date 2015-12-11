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
#include <pfcq.h>
#include <regex.h>
#include <request.h>
#include <sys/queue.h>

typedef enum db_acl_source
{
	DB_ACL_SOURCE_LOCAL,
	DB_ACL_SOURCE_MYSQL
} db_acl_source_t;

typedef enum db_acl_matcher
{
	DB_ACL_MATCHER_STRICT,
	DB_ACL_MATCHER_SUBDOMAIN,
	DB_ACL_MATCHER_REGEX
} db_acl_matcher_t;

typedef enum db_acl_action
{
	DB_ACL_ACTION_ALLOW,
	DB_ACL_ACTION_DENY,
	DB_ACL_ACTION_NXDOMAIN,
	DB_ACL_ACTION_SET_A
} db_acl_action_t;

typedef union db_acl_action_parameters
{
	pfcq_in_address_t set_a_address;
} db_acl_action_parameters_t;

struct db_list_item
{
	TAILQ_ENTRY(db_list_item) tailq;
	char* s_name;
	char* s_value;
	size_t s_value_length;
	uint64_t s_value_hash;
	unsigned short int regex_compiled;
	regex_t regex;
};

TAILQ_HEAD(db_list, db_list_item);

struct db_acl_item
{
	TAILQ_ENTRY(db_acl_item) tailq;
	char* s_layer3;
	char* s_address;
	char* s_netmask;
	char* s_matcher;
	char* s_list;
	char* s_action;
	char* s_action_parameters;
	sa_family_t layer3;
	pfcq_in_address_t address;
	pfcq_in_address_t netmask;
	db_acl_matcher_t matcher;
	struct db_list list;
	db_acl_action_t action;
	db_acl_action_parameters_t action_parameters;
	pthread_spinlock_t hits_lock;
	uint64_t hits;
};

TAILQ_HEAD(db_acl, db_acl_item);

void db_acl_free_item(struct db_acl_item* _item) __attribute__((nonnull(1)));
void db_acl_free_list_item(struct db_list_item* _item) __attribute__((nonnull(1)));
db_acl_action_t db_check_query_acl(sa_family_t _layer3, pfcq_net_address_t* _address, db_request_data_t* _request_data, struct db_acl* _acl,
	void** _acl_data, size_t* _acl_data_length) __attribute__((nonnull(2, 3, 4, 5, 6)));

#endif /* __ACL_H__ */

