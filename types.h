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

#include <ldns/ldns.h>
#include <netinet/in.h>
#include <pthread.h>
#include <regex.h>
#include <sys/queue.h>

#include "pfcq.h"
#include "sys.h"

enum ds_pkt_type
{
	DS_PKT_UNK = 0,
	DS_PKT_REQ,
	DS_PKT_REP,
};

enum ds_tsk_type
{
	DS_TSK_UNK = 0,
	DS_TSK_REG,
	DS_TSK_WDT,
};

enum ds_fwd_mode
{
	DS_FWD_UNK = 0,
	DS_FWD_RR,
	DS_FWD_STICKY,
};

enum ds_acl_type
{
	DS_ACL_UNK = 0,
	DS_ACL_LOCAL,
	DS_ACL_MYSQL,
};

enum ds_acl_req_fqdn_matcher
{
	DS_MATCHER_UNK = 0,
	DS_MATCHER_STRICT,
	DS_MATCHER_SUBDOMAINS,
	DS_MATCHER_REGEX,
};

enum ds_acl_act_kind
{
	DS_ACTION_UNK = 0,
	DS_ACTION_ACCEPT,
	DS_ACTION_DROP,
	DS_ACTION_NXDOMAIN,
	DS_ACTION_SET_A,
	// TODO: more to come?
};

struct ds_wrk_tsk
{
	TAILQ_ENTRY(ds_wrk_tsk) tailq;

	char* buf;							// ]
	ssize_t buf_size;					// | raw
	bool redirected;					// ]

	uint16_t subst_id;					// ]
	char fqdn[HOST_NAME_MAX];			// |
	ldns_rr_type rr_type;				// | key
	ldns_rr_class rr_class;				// |
	struct ds_fwd_sk* fwd_sk;			// ]

	struct pfcq_net_addr addr;			// ]
	uint16_t orig_id;					// |
	struct ds_fe_sk* orig_fe_sk;		// |
	struct pfcq_net_addr orig_fe_addr;	// | value
	struct ds_fe_fwd* fe_fwd;			// |
	struct pfcq_counter epoch;			// |
	enum ds_tsk_type type;				// ]
};

TAILQ_HEAD(ds_wrk_tsk_list, ds_wrk_tsk);

struct ds_acl
{
	char* name;
	enum ds_acl_type type;
	// TODO: struct/union for additional options
	// like MySQL DB connection etc
	struct ds_acl_subnet* subnets;
	size_t n_subnets;
	struct ds_acl_req* reqs;
	size_t n_reqs;
	struct ds_acl_act* acts;
	size_t n_acts;
};

struct ds_acl_subnet_item
{
	char* name;
	struct pfcq_net_addr addr;
	struct pfcq_net_addr mask;
};

struct ds_acl_subnet
{
	char* name;
	size_t nitems;
	struct ds_acl_subnet_item* items;
};

struct ds_acl_req_item
{
	char* name;
	ldns_rr_class rr_class;
	ldns_rr_type rr_type;
	enum ds_acl_req_fqdn_matcher matcher;
	char* expr;
	regex_t regex;
};

struct ds_acl_req
{
	char* name;
	size_t nitems;
	struct ds_acl_req_item* items;
};

struct ds_acl_act_item
{
	char* name;
	enum ds_acl_act_kind act;
	// TODO: union for action parms
};

struct ds_acl_act
{
	char* name;
	size_t nitems;
	struct ds_acl_act_item* items;
};

struct ds_fe
{
	char* name;
	struct pfcq_net_addr addr;
	int dscp;
	enum ds_fwd_mode fwd_mode;
	struct ds_fe_fwd* fe_fwds;
	size_t nfefwds;
	struct pfcq_counter c_fwd;
};

struct ds_fwd
{
	char* name;							// ] meta

	struct pfcq_net_addr addr;			// ]
	int reg_dscp;						// | net
	int wdt_dscp;						// ]

	struct pfcq_counter c_q_id;			// ] DNS query ID

	char* wdt_query;					// ]
	struct pfcq_counter wdt_pending;	// | watchdog
	size_t wdt_tries;					// |
	bool alive;							// ]
};

struct ds_fe_sk
{
	int sk;
	struct ds_fe* fe;
};

struct ds_fwd_sk
{
	int sk;
	struct ds_fwd* fwd;
};

struct ds_fe_fwd
{
	struct ds_fwd* fwd;
};

struct ds_wrk_ctx
{
	struct ds_ctx* ctx;					// ]
	size_t index;						// | meta
	pthread_t id;						// ]

	int ready;

	struct rb_table* tracking;
	struct rb_table* fe_sk_set;
	struct rb_table* fwd_sk_set;
	struct rb_table* fwd_wdt_sk_set;
	int poll_timeo;
	int wrk_fd;

	int ev_prep_fd;
	int ev_fwd_fd;
	int ev_rep_fd;
	int ev_wdt_rep_fd;
	int ev_gc_fd;
	int ev_exit_fd;
	struct ds_wrk_tsk_list prep_queue;
	struct ds_wrk_tsk_list fwd_queue;
	struct ds_wrk_tsk_list rep_queue;
	pthread_spinlock_t rep_queue_lock;
	struct ds_wrk_tsk_list wdt_rep_queue;
	pthread_spinlock_t wdt_rep_queue_lock;
};

struct ds_ctx
{
	bool redirect;
	struct pfcq_counter c_redirect_wrk;
	struct ds_ctx* ctx_next;
	size_t max_pkt_size;
	struct ds_fe* fes;
	size_t nfes;
	struct ds_fwd* fwds;
	size_t nfwds;
	size_t nacls;
	size_t n_acl_subnets;
	struct ds_acl_subnet* acl_subnets;
	size_t n_acl_reqs;
	struct ds_acl_req* acl_reqs;
	size_t n_acl_acts;
	struct ds_acl_act* acl_acts;
	int wdt_fd;
	int tk_fd;
	uint64_t req_ttl;
	uint64_t gc_intvl;
	struct ds_wrk_ctx** wrks;
	size_t nwrks;
	int poll_timeo;
	struct pfcq_counter epoch;
	uint64_t epoch_size;
	struct pfcq_counter in_flight;
};

typedef int (*ds_loop_handler_fn_t)(struct epoll_event, struct ds_wrk_ctx*);

