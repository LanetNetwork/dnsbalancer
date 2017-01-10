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

#include <signal.h>
#include <sys/eventfd.h>

#ifndef MODE_DEBUG
#include <sys/resource.h>
#endif

#include "acl_local.h"
#include "config.h"
#include "watchdog.h"
#include "worker.h"

#include "local_context.h"

struct db_local_context* db_local_context_load(const char* _config_file, struct db_global_context* _g_ctx)
{
	struct db_local_context* ret = NULL;
	struct collection_item* config = NULL;
#ifndef MODE_DEBUG
	rlim_t limit;
	struct rlimit limits;
#endif

	config = db_config_open(_config_file);

	ret = pfcq_alloc(sizeof(struct db_local_context));

	ret->global_context = _g_ctx;

	ret->db_watchdog_interval = db_config_get_u64(config, DB_CONFIG_GENERAL_SECTION, DB_CONFIG_WATCHDOG_INTERVAL_KEY, DB_DEFAULT_WATCHDOG_INTERVAL);

	ret->stats_enabled = (unsigned short int)db_config_get_uint(config, DB_CONFIG_STATS_SECTION, DB_CONFIG_STATS_ENABLED_KEY, 0);

	if (ret->stats_enabled)
	{
		const char* stats_layer3 = db_config_get_cstr(config, DB_CONFIG_STATS_SECTION, DB_CONFIG_STATS_LAYER3_KEY);
		if (unlikely(!stats_layer3))
			stop("No stats L3 protocol specified in config file");
		if (strcmp(stats_layer3, DB_CONFIG_IPV4) == 0)
			ret->stats_layer3_family = PF_INET;
		else if (strcmp(stats_layer3, DB_CONFIG_IPV6) == 0)
			ret->stats_layer3_family = PF_INET6;
		else
			stop("Unknown stats L3 protocol specified in config file");

		unsigned short int stats_port = (unsigned short int)db_config_get_uint(config, DB_CONFIG_STATS_SECTION, DB_CONFIG_STATS_PORT_KEY, DB_DEFAULT_STATS_PORT);

		const char* stats_bind = db_config_get_cstr(config, DB_CONFIG_STATS_SECTION, DB_CONFIG_STATS_BIND_KEY);
		if (unlikely(!stats_bind))
			stop("No stats bind address specified in config file");
		int inet_pton_stats_bind_res = -1;
		switch (ret->stats_layer3_family)
		{
			case PF_INET:
				ret->stats_address.address4.sin_family = AF_INET;
				inet_pton_stats_bind_res = inet_pton(AF_INET, stats_bind, &ret->stats_address.address4.sin_addr);
				ret->stats_address.address4.sin_port = htons(stats_port);
				break;
			case PF_INET6:
				ret->stats_address.address6.sin6_family = AF_INET6;
				inet_pton_stats_bind_res = inet_pton(AF_INET6, stats_bind, &ret->stats_address.address6.sin6_addr);
				ret->stats_address.address6.sin6_port = htons(stats_port);
				break;
			default:
				panic("socket domain");
				break;
		}
		if (unlikely(inet_pton_stats_bind_res != 1))
			panic("inet_pton");
	}

#ifndef MODE_DEBUG
	limit = (rlim_t)db_config_get_uint(config, DB_CONFIG_GENERAL_SECTION, DB_CONFIG_RLIMIT_KEY, DB_DEFAULT_RLIMIT);

	limits.rlim_cur = limit;
	limits.rlim_max = limit;

	if (unlikely(setrlimit(RLIMIT_NOFILE, &limits) == -1))
	{
		fail("setrlimit");
		stop("Unable to set limits.");
	}
#endif

	const char* frontends_str = db_config_get_cstr(config, DB_CONFIG_GENERAL_SECTION, DB_CONFIG_FRONTENDS_KEY);
	if (unlikely(!frontends_str))
		stop("No frontends configured in config file");
	char* frontends_str_iterator = pfcq_strdup(frontends_str);
	char* frontends_str_iterator_p = frontends_str_iterator;
	char* frontend = NULL;
	while (likely(frontend = strsep(&frontends_str_iterator, DB_CONFIG_LIST_SEPARATOR)))
	{
		if (unlikely(!ret->frontends))
			ret->frontends = pfcq_alloc(sizeof(struct db_frontend*));
		else
			ret->frontends = pfcq_realloc(ret->frontends, (ret->frontends_count + 1) * sizeof(struct db_frontend*));
		ret->frontends[ret->frontends_count] = pfcq_alloc(sizeof(struct db_frontend));
		ret->frontends[ret->frontends_count]->g_ctx = _g_ctx;
		ret->frontends[ret->frontends_count]->l_ctx = ret;

		ret->frontends[ret->frontends_count]->name = pfcq_strdup(frontend);
		ret->frontends[ret->frontends_count]->workers_count = pfcq_hint_cpus(db_config_get_int(config, frontend, DB_CONFIG_FE_WORKERS_KEY, -1));
		ret->frontends[ret->frontends_count]->workers_pool = pfpthq_init(frontend, ret->frontends[ret->frontends_count]->workers_count);
		ret->frontends[ret->frontends_count]->workers = pfcq_alloc(ret->frontends[ret->frontends_count]->workers_count * sizeof(struct db_worker*));
		ret->frontends[ret->frontends_count]->dns_max_packet_length = db_config_get_int(config, frontend, DB_CONFIG_FE_DNS_MPL_KEY, DB_DEFAULT_DNS_PACKET_SIZE);

		const char* frontend_layer3 = db_config_get_cstr(config, frontend, DB_CONFIG_FE_L3_KEY);
		if (unlikely(!frontend_layer3))
		{
			inform("Frontend: %s\n", frontend);
			stop("No frontend L3 protocol specified in config file");
		}
		if (strcmp(frontend_layer3, DB_CONFIG_IPV4) == 0)
			ret->frontends[ret->frontends_count]->layer3 = PF_INET;
		else if (strcmp(frontend_layer3, DB_CONFIG_IPV6) == 0)
			ret->frontends[ret->frontends_count]->layer3 = PF_INET6;
		else
		{
			inform("Frontend: %s\n", frontend);
			stop("Unknown frontend L3 protocol specified in config file");
		}

		unsigned short int frontend_port = (unsigned short int)db_config_get_int(config, frontend, DB_CONFIG_FE_PORT_KEY, DB_DEFAULT_DNS_PORT);
		const char* frontend_bind = db_config_get_cstr(config, frontend, DB_CONFIG_FE_BIND_KEY);
		if (unlikely(!frontend_bind))
		{
			inform("Frontend: %s\n", frontend);
			stop("No bind address specified in config file");
		}
		int inet_pton_bind_res = -1;
		switch (ret->frontends[ret->frontends_count]->layer3)
		{
			case PF_INET:
				ret->frontends[ret->frontends_count]->address.address4.sin_family = AF_INET;
				inet_pton_bind_res = inet_pton(AF_INET, frontend_bind, &ret->frontends[ret->frontends_count]->address.address4.sin_addr);
				ret->frontends[ret->frontends_count]->address.address4.sin_port = htons(frontend_port);
				break;
			case PF_INET6:
				ret->frontends[ret->frontends_count]->address.address6.sin6_family = AF_INET6;
				inet_pton_bind_res = inet_pton(AF_INET6, frontend_bind, &ret->frontends[ret->frontends_count]->address.address6.sin6_addr);
				ret->frontends[ret->frontends_count]->address.address6.sin6_port = htons(frontend_port);
				break;
			default:
				panic("socket domain");
				break;
		}
		if (unlikely(inet_pton_bind_res != 1))
			panic("inet_pton");

		const char* frontend_backend = db_config_get_cstr(config, frontend, DB_CONFIG_FE_BE_KEY);
		if (unlikely(!frontend_backend))
		{
			inform("Frontend: %s\n", frontend);
			stop("No backend specified in config file");
		}

		const char* backend_mode = db_config_get_cstr(config, frontend_backend, DB_CONFIG_BE_MODE_KEY);
		if (unlikely(!backend_mode))
		{
			inform("Backend: %s\n", frontend_backend);
			stop("No backend mode specified in config file");
		}
		if (likely(strcmp(backend_mode, DB_CONFIG_RR) == 0))
			ret->frontends[ret->frontends_count]->backend.mode = DB_BE_MODE_RR;
		else if (likely(strcmp(backend_mode, DB_CONFIG_RANDOM) == 0))
			ret->frontends[ret->frontends_count]->backend.mode = DB_BE_MODE_RANDOM;
		else if (likely(strcmp(backend_mode, DB_CONFIG_LEAST_PKTS) == 0))
			ret->frontends[ret->frontends_count]->backend.mode = DB_BE_MODE_LEAST_PKTS;
		else if (likely(strcmp(backend_mode, DB_CONFIG_LEAST_TRAFFIC) == 0))
			ret->frontends[ret->frontends_count]->backend.mode = DB_BE_MODE_LEAST_TRAFFIC;
		else if (likely(strcmp(backend_mode, DB_CONFIG_HASH_L3_L4) == 0))
			ret->frontends[ret->frontends_count]->backend.mode = DB_BE_MODE_HASH_L3_L4;
		else if (likely(strcmp(backend_mode, DB_CONFIG_HASH_L3) == 0))
			ret->frontends[ret->frontends_count]->backend.mode = DB_BE_MODE_HASH_L3;
		else if (likely(strcmp(backend_mode, DB_CONFIG_HASH_L4) == 0))
			ret->frontends[ret->frontends_count]->backend.mode = DB_BE_MODE_HASH_L4;
		else
		{
			inform("Backend: %s\n", frontend_backend);
			stop("Unknown backend mode specified in config file");
		}

		const char* backend_forwarders = db_config_get_cstr(config, frontend_backend, DB_CONFIG_BE_FORWARDERS_KEY);
		if (unlikely(!backend_forwarders))
		{
			inform("Backend: %s\n", frontend_backend);
			stop("No forwarders specified in config file");
		}
		char* backend_forwarders_iterator = pfcq_strdup(backend_forwarders);
		char* backend_forwarders_iterator_p = backend_forwarders_iterator;
		char* forwarder = NULL;
		while (likely(forwarder = strsep(&backend_forwarders_iterator, DB_CONFIG_LIST_SEPARATOR)))
		{
			if (unlikely(!ret->frontends[ret->frontends_count]->backend.forwarders))
				ret->frontends[ret->frontends_count]->backend.forwarders = pfcq_alloc(sizeof(struct db_forwarder*));
			else
				ret->frontends[ret->frontends_count]->backend.forwarders =
					pfcq_realloc(ret->frontends[ret->frontends_count]->backend.forwarders,
						(ret->frontends[ret->frontends_count]->backend.forwarders_count + 1) * sizeof(struct db_forwarder*));
			ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count] = pfcq_alloc(sizeof(struct db_frontend));

			const char* forwarder_host = db_config_get_cstr(config, forwarder, DB_CONFIG_FW_HOST_KEY);
			if (unlikely(!forwarder_host))
			{
				inform("Forwarder: %s\n", forwarder);
				stop("No forwarder host specified in config file");
			}

			const char* forwarder_layer3 = db_config_get_cstr(config, forwarder, DB_CONFIG_FW_L3_KEY);
			if (unlikely(!forwarder_layer3))
			{
				inform("Forwarder: %s\n", forwarder);
				stop("No forwarder L3 protocol specified in config file");
			}
			if (strcmp(forwarder_layer3, DB_CONFIG_IPV4) == 0)
				ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->layer3 = PF_INET;
			else if (strcmp(forwarder_layer3, DB_CONFIG_IPV6) == 0)
				ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->layer3 = PF_INET6;
			else
			{
				inform("Forwarder: %s\n", forwarder);
				stop("Unknown forwarder L3 protocol specified in config file");
			}

			unsigned short int forwarder_port = (unsigned short int)db_config_get_uint(config, forwarder, DB_CONFIG_FW_PORT_KEY, DB_DEFAULT_DNS_PORT);
			int inet_pton_res = -1;
			switch (ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->layer3)
			{
				case PF_INET:
					ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->address.address4.sin_family = AF_INET;
					ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->address.address4.sin_port = htons(forwarder_port);
					inet_pton_res = inet_pton(ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->layer3,
							forwarder_host, &(ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->address.address4.sin_addr));
					break;
				case PF_INET6:
					ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->address.address6.sin6_family = AF_INET6;
					ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->address.address6.sin6_port = htons(forwarder_port);
					inet_pton_res = inet_pton(ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->layer3,
							forwarder_host, &(ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->address.address6.sin6_addr));
					break;
				default:
					panic("socket domain");
					break;
			}
			if (unlikely(inet_pton_res != 1))
				panic("inet_pton");
			ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->name = pfcq_strdup(forwarder);

			ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->check_attempts =
				(size_t)db_config_get_uint(config, forwarder, DB_CONFIG_FW_CHK_ATTEMPTS_KEY, DB_DEFAULT_FORWARDER_CHECK_ATTEMPTS);
			ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->check_timeout =
				db_config_get_u64(config, forwarder, DB_CONFIG_FW_CHK_TIMEOUT_KEY, DB_DEFAULT_FORWARDER_CHECK_TIMEOUT) * 1000ULL;
			const char* forwarder_check_query = db_config_get_cstr(config, forwarder, DB_CONFIG_FW_CHK_QUERY_KEY);
			if (unlikely(!forwarder_check_query))
			{
				inform("Forwarder: %s\n", forwarder);
				stop("No check query specified for forwarder in config file");
			}
			ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->check_query =
				pfcq_strdup(forwarder_check_query);
			if (unlikely(pthread_spin_init(&ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->stats.in_lock,
							PTHREAD_PROCESS_PRIVATE)))
				panic("pthread_spin_init");
			if (unlikely(pthread_spin_init(&ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->stats.out_lock,
							PTHREAD_PROCESS_PRIVATE)))
				panic("pthread_spin_init");

			ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->weight =
				db_config_get_u64(config, forwarder, DB_CONFIG_FW_WEIGHT_KEY, DB_DEFAULT_WEIGHT);
			ret->frontends[ret->frontends_count]->backend.total_weight +=
				ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->weight;

			ret->frontends[ret->frontends_count]->backend.forwarders_count++;
		}
		pfcq_free(backend_forwarders_iterator_p);

		const char* frontend_acl = NULL;
		frontend_acl = db_config_get_cstr(config, frontend, DB_CONFIG_FE_ACL_KEY);
		if (unlikely(!frontend_acl))
		{
			inform("Frontend: %s\n", frontend);
			stop("No ACL specified in config file");
		}
		char* frontend_acl_i = pfcq_strdup(frontend_acl);
		char* frontend_acl_p = frontend_acl_i;
		char* frontend_acl_source = strsep(&frontend_acl_i, DB_CONFIG_PARAMETERS_SEPARATOR);

		if (strcmp(frontend_acl_source, DB_CONFIG_ACL_SOURCE_LOCAL) == 0)
		{
			char* frontend_acl_name = strsep(&frontend_acl_i, DB_CONFIG_PARAMETERS_SEPARATOR);
			ret->frontends[ret->frontends_count]->acl_source = DB_ACL_SOURCE_LOCAL;
			db_acl_local_load(config, frontend_acl_name, &ret->frontends[ret->frontends_count]->acl);
		} else if (strcmp(frontend_acl_source, DB_CONFIG_ACL_SOURCE_MYSQL) == 0)
		{
			ret->frontends[ret->frontends_count]->acl_source = DB_ACL_SOURCE_MYSQL;
			panic("Not implemented");
		} else
		{
			inform("Frontend: %s\n", frontend);
			stop("Unknown ACL source specified in config file");
		}

		pfcq_free(frontend_acl_p);

		ret->frontends_count++;
	}
	pfcq_free(frontends_str_iterator_p);

	db_config_close(config);

	ret->watchdog_pool = pfpthq_init("watchdog", 1);
	ret->watchdog_eventfd = eventfd(0, 0);
	if (unlikely(ret->watchdog_eventfd == -1))
		panic("eventfd");
	pfpthq_inc(ret->watchdog_pool, &ret->watchdog_id, "watchdog", db_watchdog, (void*)ret);

	for (size_t i = 0; i < ret->frontends_count; i++)
	{
		if (unlikely(pthread_spin_init(&ret->frontends[i]->backend.queries_lock, PTHREAD_PROCESS_PRIVATE)))
			panic("pthread_spin_init");
		if (unlikely(pthread_spin_init(&ret->frontends[i]->stats.in_lock, PTHREAD_PROCESS_PRIVATE)))
			panic("pthread_spin_init");
		if (unlikely(pthread_spin_init(&ret->frontends[i]->stats.out_lock, PTHREAD_PROCESS_PRIVATE)))
			panic("pthread_spin_init");
		if (unlikely(pthread_spin_init(&ret->frontends[i]->stats.in_invalid_lock, PTHREAD_PROCESS_PRIVATE)))
			panic("pthread_spin_init");

		for (int j = 0; j < ret->frontends[i]->workers_count; j++)
		{
			struct db_worker* new_worker = pfcq_alloc(sizeof(struct db_worker));
			new_worker->frontend = ret->frontends[i];
			new_worker->eventfd = eventfd(0, 0);
			if (unlikely(new_worker->eventfd == -1))
				panic("eventfd");
			ret->frontends[i]->workers[j] = new_worker;
			pfpthq_inc(ret->frontends[i]->workers_pool, &new_worker->id, ret->frontends[i]->name, db_worker, new_worker);
		}
	}

	return ret;
}

void db_local_context_unload(struct db_local_context* _l_ctx)
{
	if (unlikely(eventfd_write(_l_ctx->watchdog_eventfd, 1) == -1))
		panic("eventfd_write");
	pfpthq_wait(_l_ctx->watchdog_pool);
	pfpthq_done(_l_ctx->watchdog_pool);

	for (size_t i = 0; i < _l_ctx->frontends_count; i++)
	{
		for (int j = 0; j < _l_ctx->frontends[i]->workers_count; j++)
			if (unlikely(eventfd_write(_l_ctx->frontends[i]->workers[j]->eventfd, 1) == -1))
				panic("eventfd_write");
		pfpthq_wait(_l_ctx->frontends[i]->workers_pool);
		pfpthq_done(_l_ctx->frontends[i]->workers_pool);
		for (int j = 0; j < _l_ctx->frontends[i]->workers_count; j++)
			pfcq_free(_l_ctx->frontends[i]->workers[j]);
		for (size_t j = 0; j < _l_ctx->frontends[i]->backend.forwarders_count; j++)
		{
			pfcq_free(_l_ctx->frontends[i]->backend.forwarders[j]->name);
			pfcq_free(_l_ctx->frontends[i]->backend.forwarders[j]->check_query);
			if (unlikely(pthread_spin_destroy(&_l_ctx->frontends[i]->backend.forwarders[j]->stats.in_lock)))
				panic("pthread_spin_destroy");
			if (unlikely(pthread_spin_destroy(&_l_ctx->frontends[i]->backend.forwarders[j]->stats.out_lock)))
				panic("pthread_spin_destroy");
			pfcq_free(_l_ctx->frontends[i]->backend.forwarders[j]);
		}
		pfcq_free(_l_ctx->frontends[i]->backend.forwarders);
		pfcq_free(_l_ctx->frontends[i]->workers);
		pfcq_free(_l_ctx->frontends[i]->name);
		if (unlikely(pthread_spin_destroy(&_l_ctx->frontends[i]->stats.in_lock)))
			panic("pthread_spin_destroy");
		if (unlikely(pthread_spin_destroy(&_l_ctx->frontends[i]->stats.out_lock)))
			panic("pthread_spin_destroy");
		if (unlikely(pthread_spin_destroy(&_l_ctx->frontends[i]->stats.in_invalid_lock)))
			panic("pthread_spin_destroy");
		if (unlikely(pthread_spin_destroy(&_l_ctx->frontends[i]->backend.queries_lock)))
			panic("pthread_spin_destroy");
		switch (_l_ctx->frontends[i]->acl_source)
		{
			case DB_ACL_SOURCE_LOCAL:
				db_acl_local_unload(&_l_ctx->frontends[i]->acl);
				break;
			case DB_ACL_SOURCE_MYSQL:
				panic("Not implemented");
				break;
			default:
				panic("Unknown source");
				break;
		}
	}
	for (size_t i = 0; i < _l_ctx->frontends_count; i++)
		pfcq_free(_l_ctx->frontends[i]);
	pfcq_free(_l_ctx->frontends);

	pfcq_free(_l_ctx);

	return;
}

