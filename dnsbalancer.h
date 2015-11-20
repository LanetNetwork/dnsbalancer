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

#ifndef __DNSBALANCER_H__
#define __DNSBALANCER_H__

#include <acl.h>
#include <errno.h>
#include <pfcq.h>
#include <pfpthq.h>
#include <sys/queue.h>

#if !defined(SO_REUSEPORT)
#error "SO_REUSEPORT is undeclared (pre-3.9 Linux kernel?)"
#endif /* !defined(SO_REUSEPORT) */

#define APP_NAME							"dnsbalancer"
#define APP_VERSION							"0.0.1"
#define APP_YEAR							"2015"
#define APP_HOLDER							"Lanet Network"
#define APP_PROGRAMMER						"Oleksandr Natalenko"
#define APP_EMAIL							"o.natalenko@lanet.ua"

#define DB_CONFIG_REQUEST_TTL_KEY			"general:request_ttl"
#define DB_CONFIG_GC_INTERVAL_KEY			"general:gc_interval"
#define DB_CONFIG_WATCHDOG_INTERVAL_KEY		"general:watchdog_interval"
#define DB_CONFIG_STATS_ENABLED_KEY			"stats:enabled"
#define DB_CONFIG_STATS_LAYER3_KEY			"stats:layer3"
#define DB_CONFIG_STATS_PORT_KEY			"stats:port"
#define DB_CONFIG_STATS_BIND_KEY			"stats:bind"
#define DB_CONFIG_RLIMIT_KEY				"general:rlimit"
#define DB_CONFIG_FRONTENDS_KEY				"general:frontends"
#define DB_CONFIG_IPV4						"ipv4"
#define DB_CONFIG_IPV6						"ipv6"
#define DB_CONFIG_RR						"rr"
#define DB_CONFIG_RANDOM					"random"
#define DB_CONFIG_LEAST_PKTS				"least_pkts"
#define DB_CONFIG_LEAST_TRAFFIC				"least_traffic"
#define DB_CONFIG_HASH_L3_L4				"hash_l3+l4"
#define DB_CONFIG_HASH_L3					"hash_l3"
#define DB_CONFIG_HASH_L4					"hash_l4"
#define DB_CONFIG_LIST_SEPARATOR			","
#define DB_CONFIG_PARAMETERS_SEPARATOR		"/"
#define DB_CONFIG_ACL_MATCHER_STRICT		"strict"
#define DB_CONFIG_ACL_MATCHER_SUBDOMAIN		"subdomain"
#define DB_CONFIG_ACL_MATCHER_REGEX			"regex"
#define DB_CONFIG_ACL_ACTION_ALLOW			"allow"
#define DB_CONFIG_ACL_ACTION_DENY			"deny"
#define DB_CONFIG_ACL_ACTION_NXDOMAIN		"nxdomain"
#define DB_CONFIG_ACL_ACTION_SET_A			"set_a"
#define DB_CONFIG_ACL_SOURCE_LOCAL			"local"
#define DB_CONFIG_ACL_SOURCE_MYSQL			"mysql"
#define DB_DEFAULT_RLIMIT					32768
#define DB_DEFAULT_REQUEST_TTL				10000
#define DB_DEFAULT_GC_INTERVAL				1000
#define DB_DEFAULT_WATCHDOG_INTERVAL		1000
#define DB_DEFAULT_STATS_PORT				8083
#define DB_DEFAULT_DNS_PORT					53
#define DB_DEFAULT_DNS_PACKET_SIZE			4096
#define DB_DEFAULT_FORWARDER_CHECK_ATTEMPTS	3
#define DB_DEFAULT_FORWARDER_CHECK_TIMEOUT	500
#define DB_DEFAULT_WEIGHT					1
#define DB_1_SEC_NS							(1000LL * 1000 * 1000)
#define DB_1_MIN_S							(60LL)
#define DB_5_MINS_S							(5 * DB_1_MIN_S)
#define DB_15_MINS_S						(15 * DB_1_MIN_S)
#define DB_1_MIN_NS							(DB_1_MIN_S * DB_1_SEC_NS)
#define DB_5_MINS_NS						(5 * DB_1_MIN_NS)
#define DB_15_MINS_NS						(15 * DB_1_MIN_NS)
#define DB_LOADAVG_ITEM_TTL					DB_15_MINS_NS

typedef enum db_backend_mode
{
	DB_BE_MODE_RR,
	DB_BE_MODE_RANDOM,
	DB_BE_MODE_LEAST_PKTS,
	DB_BE_MODE_LEAST_TRAFFIC,
	DB_BE_MODE_HASH_L3_L4,
	DB_BE_MODE_HASH_L3,
	DB_BE_MODE_HASH_L4
} db_backend_mode_t;

typedef struct db_forwarder_stats
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
} db_forwarder_stats_t;

typedef struct db_forwarder
{
	char* name;
	sa_family_t layer3;
	int __padding1:32;
	pfcq_net_address_t address;
	unsigned short int alive;
	unsigned short int fails;
	int __padding2;
	size_t check_attempts;
	uint64_t check_timeout;
	char* check_query;
	db_forwarder_stats_t stats;
	uint64_t weight;
} db_forwarder_t;

typedef struct db_backend
{
	db_backend_mode_t mode;
	pthread_spinlock_t queries_lock;
	db_forwarder_t** forwarders;
	size_t forwarders_count;
	uint64_t queries;
	uint64_t total_weight;
} db_backend_t;

typedef struct db_frontend_stats
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
	int __padding1;
} db_frontend_stats_t;

typedef struct db_local_context db_local_context_t;
typedef struct db_global_context db_global_context_t;

typedef struct db_frontend
{
	char* name;
	pfcq_net_address_t address;
	size_t dns_max_packet_length;
	pfpthq_pool_t* workers_pool;
	pthread_t* workers_id;
	int workers;
	db_acl_source_t acl_source;
	sa_family_t layer3;
	int __padding1:32;
	db_global_context_t* g_ctx;
	db_backend_t backend;
	db_frontend_stats_t stats;
	struct db_acl acl;
} db_frontend_t;

struct db_local_context
{
	db_frontend_t** frontends;
	size_t frontends_count;
	pfpthq_pool_t* watchdog_pool;
	pthread_t watchdog_id;
	uint64_t db_watchdog_interval;
	unsigned short int stats_enabled;
	sa_family_t stats_layer3_family;
	int __padding1;
	pfcq_net_address_t stats_address;
};

struct db_global_context
{
	db_request_list_t db_requests;
	pfpthq_pool_t* gc_pool;
	pthread_t gc_id;
	uint64_t db_gc_interval;
};

#endif /* __DNSBALANCER_H__ */

