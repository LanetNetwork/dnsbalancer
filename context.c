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

#include <sys/eventfd.h>
#include <sys/timerfd.h>

#include "ini.h"
#include "pfcq.h"
#include "rb.h"
#include "utils.h"
#include "worker.h"

#include "context.h"

struct ds_ctx* ds_ctx_load(const char* _config_file)
{
	int nsections = -1;
	char** sections = NULL;
	struct ds_ctx* ret = NULL;
	ds_cfg_t* cfg = NULL;

	ret = pfcq_alloc(sizeof(struct ds_ctx));

	cfg = ds_cfg_open("dnsbalancer", _config_file);

	sections = ds_cfg_get_sections(cfg, &nsections);

	// enumerate sections
	for (size_t i = 0; i < (size_t)nsections; i++)
	{
		const char* stype = ds_cfg_try_get_cstr(cfg, sections[i], DS_CFG_KEY_TYPE);
		if (!stype)
			continue;

		if (pfcq_strlcmp(stype, DS_CFG_TYPE_FE) == 0)
			ret->nfes++;
		else if (pfcq_strlcmp(stype, DS_CFG_TYPE_FWD) == 0)
			ret->nfwds++;
		else if (pfcq_strlcmp(stype, DS_CFG_TYPE_ACL) == 0)
			ret->nacls++;
		else if (pfcq_strlcmp(stype, DS_CFG_TYPE_SUBNET) == 0)
			ret->n_acl_subnets++;
		else if (pfcq_strlcmp(stype, DS_CFG_TYPE_REQ) == 0)
			ret->n_acl_reqs++;
		else if (pfcq_strlcmp(stype, DS_CFG_TYPE_ACT) == 0)
			ret->n_acl_acts++;
		else
		{
			inform("Section type: %s\n", stype);
			stop("Unknown section type");
		}
	}

	// subnets
	ret->acl_subnets = pfcq_alloc(ret->n_acl_subnets * sizeof(struct ds_acl_subnet));
	for (size_t i = 0, c_s = 0; i < (size_t)nsections; i++)
	{
		const char* stype = ds_cfg_try_get_cstr(cfg, sections[i], DS_CFG_KEY_TYPE);
		if (!stype || pfcq_strlcmp(stype, DS_CFG_TYPE_SUBNET) != 0)
			continue;

		// name
		ret->acl_subnets[c_s].name = pfcq_strdup(sections[i]);

		char** keys = ds_cfg_get_keys(cfg, sections[i], (int*)&ret->acl_subnets[c_s].nitems);
		if (!--ret->acl_subnets[c_s].nitems) // minus "type"
		{
			inform("Section: %s\n", sections[i]);
			stop("Section is empty");
		}

		ret->acl_subnets[c_s].items = pfcq_alloc(ret->acl_subnets[c_s].nitems * sizeof(struct ds_acl_subnet_item));

		for (size_t j = 0, c_i = 0; j < ret->acl_subnets[c_s].nitems + 1; j++)
		{
			size_t nparts = 0;
			char** parts = NULL;
			const char* cur = NULL;

			if (pfcq_strlcmp(keys[j], DS_CFG_KEY_TYPE) == 0)
				continue;

			cur = ds_cfg_get_cstr(cfg, sections[i], keys[j]);
			parts = pfcq_split_string(cur, DS_CFG_PARTS_DELIM, &nparts);
			if (unlikely(nparts != 2))
			{
				inform("Address: %s\n", cur);
				stop("Incorrect address specified");
			}

			ret->acl_subnets[c_s].items[c_i].name = pfcq_strdup(keys[j]);
			ds_inet_pton(parts[0], 0, &ret->acl_subnets[c_s].items[c_i].addr);
			ds_inet_vlsmton(&ret->acl_subnets[c_s].items[c_i].addr,
							parts[1], &ret->acl_subnets[c_s].items[c_i].mask);

			pfcq_free_split_string(parts, nparts);

			c_i++;
		}
		ds_cfg_free_keys(keys);

		verbose("[subnet: %s] loaded\n", ret->acl_subnets[c_s].name);

		c_s++;
	}

	// requests
	ret->acl_reqs = pfcq_alloc(ret->n_acl_reqs * sizeof(struct ds_acl_req));
	for (size_t i = 0, c_s = 0; i < (size_t)nsections; i++)
	{
		const char* stype = ds_cfg_try_get_cstr(cfg, sections[i], DS_CFG_KEY_TYPE);
		if (!stype || pfcq_strlcmp(stype, DS_CFG_TYPE_REQ) != 0)
			continue;

		// name
		ret->acl_reqs[c_s].name = pfcq_strdup(sections[i]);

		char** keys = ds_cfg_get_keys(cfg, sections[i], (int*)&ret->acl_reqs[c_s].nitems);
		if (!--ret->acl_reqs[c_s].nitems) // minus "type"
		{
			inform("Section: %s\n", sections[i]);
			stop("Section is empty");
		}

		ret->acl_reqs[c_s].items = pfcq_alloc(ret->acl_reqs[c_s].nitems * sizeof(struct ds_acl_req_item));

		for (size_t j = 0, c_i = 0; j < ret->acl_reqs[c_s].nitems + 1; j++)
		{
			size_t nparts = 0;
			char** parts = NULL;
			const char* cur = NULL;

			if (pfcq_strlcmp(keys[j], DS_CFG_KEY_TYPE) == 0)
				continue;

			cur = ds_cfg_get_cstr(cfg, sections[i], keys[j]);
			parts = pfcq_split_string(cur, DS_CFG_PARTS_DELIM, &nparts);
			if (unlikely(nparts != 4))
			{
				inform("Request: %s\n", cur);
				stop("Incorrect request specified");
			}

			ret->acl_reqs[c_s].items[c_i].name = pfcq_strdup(keys[j]);
			// LDNS_RR_CLASS_FIRST (0) for "*"
			ret->acl_reqs[c_s].items[c_i].rr_class = ldns_get_rr_class_by_name(parts[0]);
			// LDNS_RR_TYPE_FIRST (0) for "*"
			ret->acl_reqs[c_s].items[c_i].rr_type = ldns_get_rr_type_by_name(parts[1]);
			if (pfcq_strlcmp(parts[2], DS_CFG_MATCHER_STRICT) == 0)
				ret->acl_reqs[c_s].items[c_i].matcher = DS_MATCHER_STRICT;
			else if (pfcq_strlcmp(parts[2], DS_CFG_MATCHER_SUBDOMAINS) == 0)
				ret->acl_reqs[c_s].items[c_i].matcher = DS_MATCHER_SUBDOMAINS;
			else if (pfcq_strlcmp(parts[2], DS_CFG_MATCHER_REGEX) == 0)
				ret->acl_reqs[c_s].items[c_i].matcher = DS_MATCHER_REGEX;
			else
			{
				inform("Matcher: %s\n", parts[2]);
				stop("Incorrect matcher specified");
			}
			ret->acl_reqs[c_s].items[c_i].expr = pfcq_strdup(parts[3]);
			ds_regcomp(&ret->acl_reqs[c_s].items[c_i].regex, ret->acl_reqs[c_s].items[c_i].expr);

			pfcq_free_split_string(parts, nparts);

			c_i++;
		}
		ds_cfg_free_keys(keys);

		verbose("[request: %s] loaded\n", ret->acl_reqs[c_s].name);

		c_s++;
	}

	// actions
	ret->acl_acts = pfcq_alloc(ret->n_acl_acts * sizeof(struct ds_acl_act));
	for (size_t i = 0, c_s = 0; i < (size_t)nsections; i++)
	{
		const char* stype = ds_cfg_try_get_cstr(cfg, sections[i], DS_CFG_KEY_TYPE);
		if (!stype || pfcq_strlcmp(stype, DS_CFG_TYPE_ACT) != 0)
			continue;

		// name
		ret->acl_acts[c_s].name = pfcq_strdup(sections[i]);

		char** keys = ds_cfg_get_keys(cfg, sections[i], (int*)&ret->acl_acts[c_s].nitems);
		if (!--ret->acl_acts[c_s].nitems) // minus "type"
		{
			inform("Section: %s\n", sections[i]);
			stop("Section is empty");
		}

		ret->acl_acts[c_s].items = pfcq_alloc(ret->acl_acts[c_s].nitems * sizeof(struct ds_acl_act_item));

		for (size_t j = 0, c_i = 0; j < ret->acl_acts[c_s].nitems + 1; j++)
		{
			size_t nparts = 0;
			char** parts = NULL;
			const char* cur = NULL;

			if (pfcq_strlcmp(keys[j], DS_CFG_KEY_TYPE) == 0)
				continue;

			cur = ds_cfg_get_cstr(cfg, sections[i], keys[j]);
			parts = pfcq_split_string(cur, DS_CFG_PARTS_DELIM, &nparts);
			if (unlikely(nparts != 2))
			{
				inform("Action: %s\n", cur);
				stop("Incorrect action specified");
			}

			ret->acl_acts[c_s].items[c_i].name = pfcq_strdup(keys[j]);
			if (pfcq_strlcmp(parts[0], DS_CFG_ACL_ACT_ACCEPT) == 0)
				ret->acl_acts[c_s].items[c_i].act = DS_ACTION_ACCEPT;
			else if (pfcq_strlcmp(parts[0], DS_CFG_ACL_ACT_DROP) == 0)
				ret->acl_acts[c_s].items[c_i].act = DS_ACTION_DROP;
			else if (pfcq_strlcmp(parts[0], DS_CFG_ACL_ACT_NXDOMAIN) == 0)
				ret->acl_acts[c_s].items[c_i].act = DS_ACTION_NXDOMAIN;
			// TODO: also obtain parms for SET_A from parts[1]
			else if (pfcq_strlcmp(parts[0], DS_CFG_ACL_ACT_SET_A) == 0)
				ret->acl_acts[c_s].items[c_i].act = DS_ACTION_SET_A;
			else
			{
				inform("Action: %s\n", parts[0]);
				stop("Incorrect action specified");
			}

			pfcq_free_split_string(parts, nparts);

			c_i++;
		}
		ds_cfg_free_keys(keys);

		verbose("[action: %s] loaded\n", ret->acl_acts[c_s].name);

		c_s++;
	}

	pfcq_counter_init(&ret->epoch);
	ret->tk_fd = ds_timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	ret->epoch_size =
		ds_cfg_get_u64(cfg, DS_CFG_SECTION_GENERAL,
					   DS_CFG_KEY_TK_INTVL, DS_CFG_DEFAULT_TK_INTVL) * 1000000ULL;
	ds_timerfd_settime(ret->tk_fd, ret->epoch_size);

	// forwarders
	ret->fwds = pfcq_alloc(ret->nfwds * sizeof(struct ds_fwd));
	for (size_t i = 0, c_f = 0; i < (size_t)nsections; i++)
	{
		size_t nparts = 0;
		char** parts = NULL;
		const char* cur = NULL;
		const char* stype = ds_cfg_try_get_cstr(cfg, sections[i], DS_CFG_KEY_TYPE);
		if (!stype || pfcq_strlcmp(stype, DS_CFG_TYPE_FWD) != 0)
			continue;

		// init
		pfcq_counter_init(&ret->fwds[c_f].c_q_id);
		pfcq_counter_set(&ret->fwds[c_f].c_q_id, 1);
		pfcq_counter_init(&ret->fwds[c_f].wdt_pending);

		// name
		ret->fwds[c_f].name = pfcq_strdup(sections[i]);

		// address
		cur = ds_cfg_get_cstr(cfg, sections[i], DS_CFG_KEY_ADDR);
		parts = pfcq_split_string(cur, DS_CFG_PARTS_DELIM, &nparts);
		if (unlikely(nparts != 2))
		{
			inform("Address: %s\n", cur);
			stop("Incorrect address specified");
		}
		ds_inet_pton(parts[0], (in_port_t)pfcq_strtoul(parts[1], 10), &ret->fwds[c_f].addr);
		pfcq_free_split_string(parts, nparts);

		// regular DSCP
		cur = ds_cfg_get_cstr(cfg, sections[i], DS_CFG_KEY_REG_DSCP);
		ret->fwds[c_f].reg_dscp = pfcq_strtoul(cur, 16);

		// watchdog DSCP
		cur = ds_cfg_get_cstr(cfg, sections[i], DS_CFG_KEY_WDT_DSCP);
		ret->fwds[c_f].wdt_dscp = pfcq_strtoul(cur, 16);

		// watchdog query
		cur = ds_cfg_get_cstr(cfg, sections[i], DS_CFG_KEY_WDT_QUERY);
		ret->fwds[c_f].wdt_query = pfcq_strdup(cur);

		// watchdog tries
		ret->fwds[c_f].wdt_tries = ds_cfg_get_uint(cfg, sections[i], DS_CFG_KEY_WDT_TRIES, DS_CFG_DEFAULT_WDT_TRIES);

		// forwarder is alive by default
		ret->fwds[c_f].alive = true;

		verbose("[fwd: %s] loaded\n", ret->fwds[c_f].name);

		c_f++;
	}

	ret->wdt_fd = ds_timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	ds_timerfd_settime(ret->wdt_fd,
		ds_cfg_get_u64(cfg, DS_CFG_SECTION_GENERAL,
					   DS_CFG_KEY_WDT_INTVL, DS_CFG_DEFAULT_WDT_INTVL) * 1000000ULL);

	ret->fes = pfcq_alloc(ret->nfes * sizeof(struct ds_fe));
	for (size_t i = 0, c_f = 0; i < (size_t)nsections; i++)
	{
		size_t nparts = 0;
		char** parts = NULL;
		const char* cur = NULL;
		const char* stype = ds_cfg_try_get_cstr(cfg, sections[i], DS_CFG_KEY_TYPE);
		if (!stype || pfcq_strlcmp(stype, DS_CFG_TYPE_FE) != 0)
			continue;

		// init
		pfcq_counter_init(&ret->fes[c_f].c_fwd);

		// name
		ret->fes[c_f].name = pfcq_strdup(sections[i]);

		// address
		cur = ds_cfg_get_cstr(cfg, sections[i], DS_CFG_KEY_ADDR);
		parts = pfcq_split_string(cur, DS_CFG_PARTS_DELIM, &nparts);
		if (unlikely(nparts != 2))
		{
			inform("Address: %s\n", cur);
			stop("Incorrect address specified");
		}
		ds_inet_pton(parts[0], (in_port_t)pfcq_strtoul(parts[1], 10), &ret->fes[c_f].addr);
		pfcq_free_split_string(parts, nparts);

		// DSCP
		cur = ds_cfg_get_cstr(cfg, sections[i], DS_CFG_KEY_REG_DSCP);
		ret->fes[c_f].dscp = pfcq_strtoul(cur, 16);

		// forwarding mode
		cur = ds_cfg_get_cstr(cfg, sections[i], DS_CFG_KEY_FWD_MODE);
		if (pfcq_strlcmp(cur, DS_CFG_FWD_MODE_RR) == 0)
			ret->fes[c_f].fwd_mode = DS_FWD_RR;
		else if (pfcq_strlcmp(cur, DS_CFG_FWD_MODE_STICKY) == 0)
			ret->fes[c_f].fwd_mode = DS_FWD_STICKY;
		else
		{
			inform("Unknown forwarding mode: %s\n", cur);
			stop("Stopping.");
		}

		// forwarders
		cur = ds_cfg_get_cstr(cfg, sections[i], DS_CFG_KEY_FWDS);
		parts = pfcq_split_string(cur, DS_CFG_LIST_DELIM, &nparts);
		ret->fes[c_f].nfefwds = nparts;
		ret->fes[c_f].fe_fwds = pfcq_alloc(ret->fes[c_f].nfefwds * sizeof(struct ds_fe_fwd*));
		for (size_t j = 0; j < ret->fes[c_f].nfefwds; j++)
		{
			for (size_t k = 0; k < ret->nfwds; k++)
			{
				if (strncmp(parts[j], ret->fwds[k].name, strlen(parts[j])) != 0)
					continue;

				ret->fes[c_f].fe_fwds[j].fwd = &ret->fwds[k];
				break;
			}

			if (!ret->fes[c_f].fe_fwds[j].fwd)
			{
				inform("%s\n", "Unable to assign forwarder. Consider checking config file.");
				stop("Stopping.");
			}
		}

		pfcq_free_split_string(parts, nparts);

		verbose("[fe: %s] loaded\n", ret->fes[c_f].name);

		c_f++;
	}

	ds_cfg_free_sections(sections);

	ret->max_pkt_size =
		ds_cfg_get_uint(cfg, DS_CFG_SECTION_GENERAL,
						DS_CFG_KEY_MAX_PKT_SIZE, DS_CFG_DEFAULT_MAX_PKT_SIZE);
	if (unlikely(ret->max_pkt_size > LDNS_MAX_PACKETLEN))
	{
		inform(DS_CFG_KEY_MAX_PKT_SIZE "=%zu exceeds max allowed packet size (%d)\n", ret->max_pkt_size, LDNS_MAX_PACKETLEN);
		stop("Stopping.");
	}

	pfcq_counter_init(&ret->in_flight);

	ret->poll_timeo =
		ds_cfg_get_uint(cfg, DS_CFG_SECTION_GENERAL,
						DS_CFG_KEY_POLL_TIMEO, DS_CFG_DEFAULT_POLL_TIMEO);

	ret->req_ttl = ds_cfg_get_u64(cfg, DS_CFG_SECTION_GENERAL,
								  DS_CFG_KEY_REQ_TTL, DS_CFG_DEFAULT_REQ_TTL) * 1000000ULL;
	ret->gc_intvl = ds_cfg_get_u64(cfg, DS_CFG_SECTION_GENERAL,
								   DS_CFG_KEY_GC_INTVL,
								   DS_CFG_DEFAULT_GC_INTVL) * 1000000ULL;

	pfcq_counter_init(&ret->c_redirect_wrk);

	ret->nwrks = pfcq_hint_cpus(ds_cfg_get_int(cfg, DS_CFG_SECTION_GENERAL, DS_CFG_KEY_WRKS, DS_CFG_DEFAULT_WRKS));
	ret->wrks = pfcq_alloc(ret->nwrks * sizeof(struct ds_wrk_ctx*));
	for (size_t i = 0; i < ret->nwrks; i++)
	{
		ret->wrks[i] = pfcq_alloc(sizeof(struct ds_wrk_ctx));

		ret->wrks[i]->ctx = ret;
		ret->wrks[i]->index = i;
		ret->wrks[i]->ready = ds_eventfd(0, 0);

		pthread_create(&ret->wrks[i]->id, NULL, ds_wrk, (void*)ret->wrks[i]);
		ds_consume_u64(ret->wrks[i]->ready);
		ds_close(ret->wrks[i]->ready);
		verbose("[ctx: %p, wrk: %zu/%#lx] started\n", (void*)ret, ret->wrks[i]->index, ret->wrks[i]->id);
	}

	ds_cfg_close(cfg);

	return ret;
}

void ds_ctx_unload(struct ds_ctx* _ctx)
{
	for (size_t i = 0; i < _ctx->nwrks; i++)
		ds_produce_u64(_ctx->wrks[i]->ev_exit_fd);

	pfcq_counter_reset(&_ctx->c_redirect_wrk);

	for (size_t i = 0; i < _ctx->nwrks; i++)
	{
		pthread_join(_ctx->wrks[i]->id, NULL);
		verbose("[ctx: %p, wrk: %zu/%#lx] exited\n", (void*)_ctx, _ctx->wrks[i]->index, _ctx->wrks[i]->id);
		pfcq_free(_ctx->wrks[i]);
	}
	pfcq_free(_ctx->wrks);

	ds_close(_ctx->wdt_fd);

	pfcq_counter_reset(&_ctx->in_flight);

	for (size_t i = 0; i < _ctx->nfes; i++)
	{
		pfcq_free(_ctx->fes[i].name);
		pfcq_free(_ctx->fes[i].fe_fwds);
		pfcq_counter_reset(&_ctx->fes[i].c_fwd);
	}
	pfcq_free(_ctx->fes);

	for (size_t i = 0; i < _ctx->nfwds; i++)
	{
		pfcq_free(_ctx->fwds[i].wdt_query);
		pfcq_free(_ctx->fwds[i].name);
		pfcq_counter_reset(&_ctx->fwds[i].c_q_id);
		pfcq_counter_reset(&_ctx->fwds[i].wdt_pending);
	}
	pfcq_free(_ctx->fwds);

	ds_close(_ctx->tk_fd);
	pfcq_counter_reset(&_ctx->epoch);

	for (size_t i = 0; i < _ctx->n_acl_subnets; i++)
	{
		for (size_t j = 0; j < _ctx->acl_subnets[i].nitems; j++)
		{
			pfcq_free(_ctx->acl_subnets[i].items[j].name);
		}
		pfcq_free(_ctx->acl_subnets[i].items);
		pfcq_free(_ctx->acl_subnets[i].name);
	}
	pfcq_free(_ctx->acl_subnets);

	for (size_t i = 0; i < _ctx->n_acl_reqs; i++)
	{
		for (size_t j = 0; j < _ctx->acl_reqs[i].nitems; j++)
		{
			pfcq_free(_ctx->acl_reqs[i].items[j].name);
			pfcq_free(_ctx->acl_reqs[i].items[j].expr);
			regfree(&_ctx->acl_reqs[i].items[j].regex);
		}
		pfcq_free(_ctx->acl_reqs[i].items);
		pfcq_free(_ctx->acl_reqs[i].name);
	}
	pfcq_free(_ctx->acl_reqs);

	for (size_t i = 0; i < _ctx->n_acl_acts; i++)
	{
		for (size_t j = 0; j < _ctx->acl_acts[i].nitems; j++)
		{
			pfcq_free(_ctx->acl_acts[i].items[j].name);
		}
		pfcq_free(_ctx->acl_acts[i].items);
		pfcq_free(_ctx->acl_acts[i].name);
	}
	pfcq_free(_ctx->acl_acts);

	pfcq_free(_ctx);
}

