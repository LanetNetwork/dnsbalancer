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

#ifndef __TYPES_H__
#define __TYPES_H__

#include <ldns/ldns.h>
#include <microhttpd.h>
#include <pthread.h>
#include <regex.h>
#include <stdint.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include "defines.h"

#include "contrib/pfcq/pfcq.h"
#include "contrib/pfpthq/pfpthq.h"

enum db_backend_mode
{
	DB_BE_MODE_RR,
	DB_BE_MODE_RANDOM,
	DB_BE_MODE_LEAST_PKTS,
	DB_BE_MODE_LEAST_TRAFFIC,
	DB_BE_MODE_HASH_L3_L4,
	DB_BE_MODE_HASH_L3,
	DB_BE_MODE_HASH_L4
};

enum db_acl_source
{
	DB_ACL_SOURCE_LOCAL,
	DB_ACL_SOURCE_MYSQL
};

enum db_acl_matcher
{
	DB_ACL_MATCHER_STRICT,
	DB_ACL_MATCHER_SUBDOMAIN,
	DB_ACL_MATCHER_REGEX
};

enum db_acl_rr_type
{
	DB_ACL_RR_TYPE_ALL,
	DB_ACL_RR_TYPE_ANY
};

enum db_acl_action
{
	DB_ACL_ACTION_ALLOW,
	DB_ACL_ACTION_DENY,
	DB_ACL_ACTION_NXDOMAIN,
	DB_ACL_ACTION_SET_A
};

struct db_forwarder_stats
{
	uint64_t in_pkts;
	uint64_t out_pkts;
	uint64_t in_bytes;
	uint64_t out_bytes;
	uint64_t out_noerror;
	uint64_t out_servfail;
	uint64_t out_nxdomain;
	uint64_t out_refused;
	uint64_t out_other;
	pthread_spinlock_t in_lock;
	pthread_spinlock_t out_lock;
};

struct db_forwarder
{
	char* name;
	sa_family_t layer3;
	unsigned short int alive;
	unsigned short int fails;
	pfcq_net_address_t address;
	size_t check_attempts;
	uint64_t check_timeout;
	char* check_query;
	struct db_forwarder_stats stats;
	uint64_t weight;
};

struct db_backend
{
	enum db_backend_mode mode;
	pthread_spinlock_t queries_lock;
	struct db_forwarder** forwarders;
	size_t forwarders_count;
	uint64_t queries;
	uint64_t total_weight;
};

struct db_frontend_stats
{
	uint64_t in_pkts;
	uint64_t out_pkts;
	uint64_t in_pkts_invalid;
	uint64_t in_bytes;
	uint64_t out_bytes;
	uint64_t out_noerror;
	uint64_t out_servfail;
	uint64_t out_nxdomain;
	uint64_t out_refused;
	uint64_t out_other;
	uint64_t in_bytes_invalid;
	pthread_spinlock_t in_lock;
	pthread_spinlock_t out_lock;
	pthread_spinlock_t in_invalid_lock;
};

struct db_set_a
{
	unsigned long address4;
	uint32_t ttl;
};

union db_acl_action_parameters
{
	struct db_set_a set_a;
};

struct db_list_item
{
	TAILQ_ENTRY(db_list_item) tailq;
	char* s_name;
	enum db_acl_rr_type rr_type;
	char* s_fqdn;
	size_t s_fqdn_length;
	uint64_t s_fqdn_hash;
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
	enum db_acl_matcher matcher;
	struct db_list list;
	enum db_acl_action action;
	union db_acl_action_parameters action_parameters;
	pthread_spinlock_t hits_lock;
	uint64_t hits;
};

TAILQ_HEAD(db_acl, db_acl_item);

struct db_request_data
{
	ldns_rr_type rr_type;
	ldns_rr_class rr_class;
	char fqdn[HOST_NAME_MAX];
	int forwarder_socket;
	uint64_t hash;
};

struct db_request
{
	TAILQ_ENTRY(db_request) tailq;
	uint16_t original_id;
	struct db_request_data data;
	pfcq_net_address_t client_address;
	struct timespec ctime;
	size_t forwarder_index;
};

TAILQ_HEAD(db_requests, db_request);

struct db_request_bucket
{
	struct db_requests requests;
	size_t requests_count;
	pthread_mutex_t requests_lock;
};

struct db_request_list
{
	struct db_request_bucket list[UINT16_MAX + 1];
	uint16_t list_index;
	pthread_spinlock_t list_index_lock;
	uint64_t ttl;
};

struct db_frontend
{
	char* name;
	pfcq_net_address_t address;
	size_t dns_max_packet_length;
	pfpthq_pool_t* workers_pool;
	struct db_worker** workers;
	int workers_count;
	enum db_acl_source acl_source;
	sa_family_t layer3;
	struct db_global_context* g_ctx;
	struct db_local_context* l_ctx;
	struct db_backend backend;
	struct db_frontend_stats stats;
	struct db_acl acl;
};

struct db_global_context
{
	struct db_request_list db_requests;
	pfpthq_pool_t* gc_pool;
	pthread_t gc_id;
	uint64_t db_gc_interval;
	int gc_eventfd;
};

struct db_latency_stats
{
	uint64_t lats[DB_LATENCY_BUCKETS];
	pthread_spinlock_t lats_lock[DB_LATENCY_BUCKETS];
};

struct db_local_context
{
	struct db_frontend** frontends;
	size_t frontends_count;
	pfpthq_pool_t* watchdog_pool;
	pthread_t watchdog_id;
	uint64_t db_watchdog_interval;
	unsigned short int stats_enabled;
	sa_family_t stats_layer3_family;
	pfcq_net_address_t stats_address;
	struct MHD_Daemon* mhd_daemon;
	struct db_latency_stats db_lats;
};

struct db_worker
{
	struct db_frontend* frontend;
	pthread_t id;
	int eventfd;
};

#endif /* __TYPES_H__ */

