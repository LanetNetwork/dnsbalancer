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
		else if (pfcq_strlcmp(stype, DS_CFG_TYPE_ACT) == 0)
			ret->nacts++;
		else
		{
			inform("Section type: %s\n", stype);
			stop("Unknown section type");
		}
	}

	pfcq_counter_init(&ret->epoch);
	ret->tk_fd = ds_timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	ret->epoch_size =
		ds_cfg_get_u64(cfg, DS_CFG_SECTION_GENERAL,
					   DS_CFG_KEY_TK_INTVL, DS_CFG_DEFAULT_TK_INTVL) * 1000000ULL;
	ds_timerfd_settime(ret->tk_fd, ret->epoch_size);

	// forwarders
	ret->fwds = pfcq_alloc(ret->nfwds * sizeof(struct ds_fwd));
	for (size_t i = 0, c_x = 0; i < (size_t)nsections; i++)
	{
		size_t nparts = 0;
		char** parts = NULL;
		const char* cur = NULL;
		const char* stype = ds_cfg_try_get_cstr(cfg, sections[i], DS_CFG_KEY_TYPE);
		if (!stype || pfcq_strlcmp(stype, DS_CFG_TYPE_FWD) != 0)
			continue;

		// init
		pfcq_counter_init(&ret->fwds[c_x].c_q_id);
		pfcq_counter_set(&ret->fwds[c_x].c_q_id, 1);
		pfcq_counter_init(&ret->fwds[c_x].wdt_pending);

		// name
		ret->fwds[c_x].name = pfcq_strdup(sections[i]);

		// address
		cur = ds_cfg_get_cstr(cfg, sections[i], DS_CFG_KEY_ADDR);
		parts = pfcq_split_string(cur, DS_CFG_PARTS_DELIM, &nparts);
		if (unlikely(nparts != 2))
		{
			inform("Address: %s\n", cur);
			stop("Incorrect address specified");
		}
		ds_inet_pton(parts[0], (in_port_t)pfcq_strtoul(parts[1], 10), &ret->fwds[c_x].addr);
		pfcq_free_split_string(parts, nparts);

		// regular DSCP
		cur = ds_cfg_get_cstr(cfg, sections[i], DS_CFG_KEY_REG_DSCP);
		ret->fwds[c_x].reg_dscp = pfcq_strtoul(cur, 16);

		// watchdog DSCP
		cur = ds_cfg_get_cstr(cfg, sections[i], DS_CFG_KEY_WDT_DSCP);
		ret->fwds[c_x].wdt_dscp = pfcq_strtoul(cur, 16);

		// watchdog query
		cur = ds_cfg_get_cstr(cfg, sections[i], DS_CFG_KEY_WDT_QUERY);
		ret->fwds[c_x].wdt_query = pfcq_strdup(cur);

		// watchdog tries
		ret->fwds[c_x].wdt_tries = ds_cfg_get_uint(cfg, sections[i], DS_CFG_KEY_WDT_TRIES, DS_CFG_DEFAULT_WDT_TRIES);

		// forwarder is alive by default
		ret->fwds[c_x].alive = true;

		verbose("[fwd: %s] loaded\n", ret->fwds[c_x].name);

		c_x++;
	}

	// actions
	ret->acts = pfcq_alloc(ret->nacts * sizeof(struct ds_act));
	for (size_t i = 0, c_x = 0; i < (size_t)nsections; i++)
	{
		const char* stype = ds_cfg_try_get_cstr(cfg, sections[i], DS_CFG_KEY_TYPE);
		if (!stype || pfcq_strlcmp(stype, DS_CFG_TYPE_ACT) != 0)
			continue;

		// name
		ret->acts[c_x].name = pfcq_strdup(sections[i]);

		char** keys = ds_cfg_get_keys(cfg, sections[i], (int*)&ret->acts[c_x].nact_items);
		if (!--ret->acts[c_x].nact_items) // minus "type"
		{
			inform("Section: %s\n", sections[i]);
			stop("Section is empty");
		}

		ret->acts[c_x].act_items = pfcq_alloc(ret->acts[c_x].nact_items * sizeof(struct ds_act_item));

		for (size_t j = 0, c_y = 0; j < ret->acts[c_x].nact_items + 1; j++)
		{
			size_t nparts = 0;
			char** parts = NULL;
			const char* cur = NULL;
			size_t naddr_parts = 0;
			char** addr_parts = NULL;
			size_t nact_parts = 0;
			char** act_parts = NULL;

			if (pfcq_strlcmp(keys[j], DS_CFG_KEY_TYPE) == 0)
				continue;

			cur = ds_cfg_get_cstr(cfg, sections[i], keys[j]);
			parts = pfcq_split_string(cur, DS_CFG_LIST_DELIM, &nparts);
			if (unlikely(nparts != 5))
			{
				inform("Action: %s\n", cur);
				stop("Incorrect action specified");
			}

			ret->acts[c_x].act_items[c_y].name = pfcq_strdup(keys[j]);

			// address/mask
			addr_parts = pfcq_split_string(parts[0], DS_CFG_PARTS_DELIM, &naddr_parts);
			if (unlikely(naddr_parts != 2))
			{
				inform("Address: %s\n", parts[0]);
				stop("Incorrect address specified");
			}
			ds_inet_pton(addr_parts[0], 0, &ret->acts[c_x].act_items[c_y].addr);
			ds_inet_vlsmton(&ret->acts[c_x].act_items[c_y].addr,
							addr_parts[1], &ret->acts[c_x].act_items[c_y].mask);
			pfcq_free_split_string(addr_parts, naddr_parts);

			// LDNS_RR_CLASS_FIRST (0) for "*"
			ret->acts[c_x].act_items[c_y].rr_class = ldns_get_rr_class_by_name(parts[1]);
			// LDNS_RR_TYPE_FIRST (0) for "*"
			ret->acts[c_x].act_items[c_y].rr_type = ldns_get_rr_type_by_name(parts[2]);
			ret->acts[c_x].act_items[c_y].expr = pfcq_strdup(parts[3]);
			ds_regcomp(&ret->acts[c_x].act_items[c_y].regex, ret->acts[c_x].act_items[c_y].expr);

			act_parts = pfcq_split_string(parts[4], DS_CFG_PARTS_DELIM, &nact_parts);
			if (pfcq_strlcmp(act_parts[0], DS_CFG_ACT_BALANCE) == 0)
			{
				size_t nfwd_parts = 0;
				char** fwd_parts = NULL;

				ret->acts[c_x].act_items[c_y].act_type = DS_ACT_BALANCE;

				if (pfcq_strlcmp(act_parts[1], DS_CFG_ACT_BALANCE_RR) == 0)
				{
					ret->acts[c_x].act_items[c_y].act_balance_type = DS_ACT_BALANCE_RR;
				} else if (pfcq_strlcmp(act_parts[1], DS_CFG_ACT_BALANCE_STICKY) == 0)
				{
					ret->acts[c_x].act_items[c_y].act_balance_type = DS_ACT_BALANCE_STICKY;
				} else
				{
					inform("Balancing type: %s\n", act_parts[1]);
					stop("Unknown balancing type specified");
				}
				fwd_parts = pfcq_split_string(act_parts[2], DS_CFG_SUBLIST_DELIM, &nfwd_parts);
				ret->acts[c_x].act_items[c_y].act_balance_nfwds = nfwd_parts;
				ret->acts[c_x].act_items[c_y].act_balance_fwds =
					pfcq_alloc(ret->acts[c_x].act_items[c_y].act_balance_nfwds *
					sizeof(struct ds_fwd*));
				for (size_t k = 0, c_z = 0; k < ret->acts[c_x].act_items[c_y].act_balance_nfwds; k++)
					for (size_t t = 0; t < ret->acts[c_x].act_items[c_y].act_balance_nfwds; t++)
						if (strncmp(ret->fwds[k].name, fwd_parts[t], strlen(fwd_parts[t])) == 0)
						{
							ret->acts[c_x].act_items[c_y].act_balance_fwds[c_z] = &ret->fwds[k];
							c_z++;
						}
				pfcq_free_split_string(fwd_parts, nfwd_parts);
				pfcq_counter_init(&ret->acts[c_x].act_items[c_y].c_fwd);
			} else
			{
				inform("Action: %s\n", act_parts[0]);
				stop("Unknown action specified");
			}
			pfcq_free_split_string(act_parts, nact_parts);

			pfcq_free_split_string(parts, nparts);

			c_y++;
		}
		ds_cfg_free_keys(keys);

		verbose("[act: %s] loaded\n", ret->acts[c_x].name);

		c_x++;
	}

	ret->wdt_fd = ds_timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	ds_timerfd_settime(ret->wdt_fd,
		ds_cfg_get_u64(cfg, DS_CFG_SECTION_GENERAL,
					   DS_CFG_KEY_WDT_INTVL, DS_CFG_DEFAULT_WDT_INTVL) * 1000000ULL);

	ret->fes = pfcq_alloc(ret->nfes * sizeof(struct ds_fe));
	for (size_t i = 0, c_x = 0; i < (size_t)nsections; i++)
	{
		size_t nparts = 0;
		char** parts = NULL;
		const char* cur = NULL;
		const char* stype = ds_cfg_try_get_cstr(cfg, sections[i], DS_CFG_KEY_TYPE);
		if (!stype || pfcq_strlcmp(stype, DS_CFG_TYPE_FE) != 0)
			continue;

		// name
		ret->fes[c_x].name = pfcq_strdup(sections[i]);

		// address
		cur = ds_cfg_get_cstr(cfg, sections[i], DS_CFG_KEY_ADDR);
		parts = pfcq_split_string(cur, DS_CFG_PARTS_DELIM, &nparts);
		if (unlikely(nparts != 2))
		{
			inform("Address: %s\n", cur);
			stop("Incorrect address specified");
		}
		ds_inet_pton(parts[0], (in_port_t)pfcq_strtoul(parts[1], 10), &ret->fes[c_x].addr);
		pfcq_free_split_string(parts, nparts);

		// DSCP
		cur = ds_cfg_get_cstr(cfg, sections[i], DS_CFG_KEY_REG_DSCP);
		ret->fes[c_x].dscp = pfcq_strtoul(cur, 16);

		// actions
		cur = ds_cfg_get_cstr(cfg, sections[i], DS_CFG_KEY_ACTS);
		parts = pfcq_split_string(cur, DS_CFG_LIST_DELIM, &nparts);
		ret->fes[c_x].nacts = nparts;
		ret->fes[c_x].acts = pfcq_alloc(ret->fes[c_x].nacts * sizeof(struct ds_act));
		for (size_t j = 0, c_y = 0; j < ret->nacts; j++)
			for (size_t k = 0; k < ret->fes[c_x].nacts; k++)
				if (strncmp(ret->acts[j].name, parts[k], strlen(parts[k])) == 0)
				{
					ret->fes[c_x].acts[c_y] = ret->acts[j];
					c_y++;
				}
		pfcq_free_split_string(parts, nparts);

		verbose("[fe: %s] loaded\n", ret->fes[c_x].name);

		c_x++;
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
		pfcq_free(_ctx->fes[i].acts);
	}
	pfcq_free(_ctx->fes);

	for (size_t i = 0; i < _ctx->nacts; i++)
	{
		for (size_t j = 0; j < _ctx->acts[i].nact_items; j++)
		{
			pfcq_free(_ctx->acts[i].act_items[j].name);
			pfcq_free(_ctx->acts[i].act_items[j].expr);
			regfree(&_ctx->acts[i].act_items[j].regex);
			pfcq_free(_ctx->acts[i].act_items[j].act_balance_fwds);
		}
		pfcq_free(_ctx->acts[i].act_items);
		pfcq_free(_ctx->acts[i].name);
	}
	pfcq_free(_ctx->acts);

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

	pfcq_free(_ctx);
}

