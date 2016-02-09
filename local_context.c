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

#include <acl_local.h>
#include <local_context.h>
#include <signal.h>
#include <stats.h>
#include <sys/epoll.h>
#ifndef MODE_DEBUG
#include <sys/resource.h>
#endif
#include <utils.h>
#include <watchdog.h>
#include <worker.h>

extern volatile sig_atomic_t should_exit;

db_local_context_t* db_local_context_load(const char* _config_file, db_global_context_t* _g_ctx)
{
	db_local_context_t* ret = NULL;
	dictionary* config = NULL;
#ifndef MODE_DEBUG
	rlim_t limit;
	struct rlimit limits;
#endif

	config = iniparser_load(_config_file);
	if (unlikely(!config))
		stop("Unable to load config file");

	ret = pfcq_alloc(sizeof(db_local_context_t));

	ret->db_watchdog_interval = ((uint64_t)iniparser_getint(config, DB_CONFIG_WATCHDOG_INTERVAL_KEY, DB_DEFAULT_WATCHDOG_INTERVAL)) * 1000000ULL;

	ret->stats_enabled = (unsigned short int)iniparser_getint(config, DB_CONFIG_STATS_ENABLED_KEY, 0);

	if (ret->stats_enabled)
	{
		const char* stats_layer3 = iniparser_getstring(config, DB_CONFIG_STATS_LAYER3_KEY, NULL);
		if (unlikely(!stats_layer3))
			stop("No stats L3 protocol specified in config file");
		if (strcmp(stats_layer3, DB_CONFIG_IPV4) == 0)
			ret->stats_layer3_family = PF_INET;
		else if (strcmp(stats_layer3, DB_CONFIG_IPV6) == 0)
			ret->stats_layer3_family = PF_INET6;
		else
			stop("Unknown stats L3 protocol specified in config file");

		unsigned short int stats_port = (unsigned short int)iniparser_getint(config, DB_CONFIG_STATS_PORT_KEY, DB_DEFAULT_STATS_PORT);

		const char* stats_bind = iniparser_getstring(config, DB_CONFIG_STATS_BIND_KEY, NULL);
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
	limit = (rlim_t)iniparser_getint(config, DB_CONFIG_RLIMIT_KEY, DB_DEFAULT_RLIMIT);

	limits.rlim_cur = limit;
	limits.rlim_max = limit;

	if (unlikely(setrlimit(RLIMIT_NOFILE, &limits) == -1))
	{
		fail("setrlimit");
		stop("Unable to set limits.");
	}
#endif

	const char* frontends_str = iniparser_getstring(config, DB_CONFIG_FRONTENDS_KEY, NULL);
	if (unlikely(!frontends_str))
		stop("No frontends configured in config file");
	char* frontends_str_iterator = pfcq_strdup(frontends_str);
	char* frontends_str_iterator_p = frontends_str_iterator;
	char* frontend = NULL;
	while (likely(frontend = strsep(&frontends_str_iterator, DB_CONFIG_LIST_SEPARATOR)))
	{
		if (unlikely(!ret->frontends))
			ret->frontends = pfcq_alloc(sizeof(db_frontend_t*));
		else
			ret->frontends = pfcq_realloc(ret->frontends, (ret->frontends_count + 1) * sizeof(db_frontend_t*));
		ret->frontends[ret->frontends_count] = pfcq_alloc(sizeof(db_frontend_t));
		ret->frontends[ret->frontends_count]->g_ctx = _g_ctx;

		char* frontend_workers_key = pfcq_mstring("%s:%s", frontend, "workers");
		char* frontend_dns_max_packet_length_key = pfcq_mstring("%s:%s", frontend, "dns_max_packet_length");
		char* frontend_port_key = pfcq_mstring("%s:%s", frontend, "port");
		char* frontend_backend_key = pfcq_mstring("%s:%s", frontend, "backend");
		char* frontend_layer3_key = pfcq_mstring("%s:%s", frontend, "layer3");
		char* frontend_bind_key = pfcq_mstring("%s:%s", frontend, "bind");
		char* frontend_acl_key = pfcq_mstring("%s:%s", frontend, "acl");

		ret->frontends[ret->frontends_count]->name = pfcq_strdup(frontend);
		ret->frontends[ret->frontends_count]->workers = pfcq_hint_cpus((int)iniparser_getint(config, frontend_workers_key, -1));
		ret->frontends[ret->frontends_count]->workers_pool = pfpthq_init(frontend, ret->frontends[ret->frontends_count]->workers);
		ret->frontends[ret->frontends_count]->workers_id = pfcq_alloc(ret->frontends[ret->frontends_count]->workers * sizeof(pthread_t));
		ret->frontends[ret->frontends_count]->dns_max_packet_length = (int)iniparser_getint(config, frontend_dns_max_packet_length_key, DB_DEFAULT_DNS_PACKET_SIZE);

		const char* frontend_layer3 = iniparser_getstring(config, frontend_layer3_key, NULL);
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

		unsigned short int frontend_port = (unsigned short int)iniparser_getint(config, frontend_port_key, DB_DEFAULT_DNS_PORT);
		const char* frontend_bind = iniparser_getstring(config, frontend_bind_key, NULL);
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

		const char* frontend_backend = iniparser_getstring(config, frontend_backend_key, NULL);
		if (unlikely(!frontend_backend))
		{
			inform("Frontend: %s\n", frontend);
			stop("No backend specified in config file");
		}

		char* backend_mode_key = pfcq_mstring("%s:%s", frontend_backend, "mode");
		char* backend_forwarders_key = pfcq_mstring("%s:%s", frontend_backend, "forwarders");

		const char* backend_mode = iniparser_getstring(config, backend_mode_key, NULL);
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

		const char* backend_forwarders = iniparser_getstring(config, backend_forwarders_key, NULL);
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
				ret->frontends[ret->frontends_count]->backend.forwarders = pfcq_alloc(sizeof(db_forwarder_t*));
			else
				ret->frontends[ret->frontends_count]->backend.forwarders =
					pfcq_realloc(ret->frontends[ret->frontends_count]->backend.forwarders,
						(ret->frontends[ret->frontends_count]->backend.forwarders_count + 1) * sizeof(db_forwarder_t*));
			ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count] = pfcq_alloc(sizeof(db_frontend_t));

			char* forwarder_host_key = pfcq_mstring("%s:%s", forwarder, "host");
			char* forwarder_port_key = pfcq_mstring("%s:%s", forwarder, "port");
			char* forwarder_layer3_key = pfcq_mstring("%s:%s", forwarder, "layer3");
			char* forwarder_check_attempts_key = pfcq_mstring("%s:%s", forwarder, "check_attempts");
			char* forwarder_check_timeout_key = pfcq_mstring("%s:%s", forwarder, "check_timeout");
			char* forwarder_check_query_key = pfcq_mstring("%s:%s", forwarder, "check_query");
			char* forwarder_weight_key = pfcq_mstring("%s:%s", forwarder, "weight");

			const char* forwarder_host = iniparser_getstring(config, forwarder_host_key, NULL);
			if (unlikely(!forwarder_host))
			{
				inform("Forwarder: %s\n", forwarder);
				stop("No forwarder host specified in config file");
			}

			const char* forwarder_layer3 = iniparser_getstring(config, forwarder_layer3_key, NULL);
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

			unsigned short int forwarder_port = (unsigned short int)iniparser_getint(config, forwarder_port_key, DB_DEFAULT_DNS_PORT);
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
				(size_t)iniparser_getint(config, forwarder_check_attempts_key, DB_DEFAULT_FORWARDER_CHECK_ATTEMPTS);
			ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->check_timeout =
				((uint64_t)iniparser_getint(config, forwarder_check_timeout_key, DB_DEFAULT_FORWARDER_CHECK_TIMEOUT)) * 1000ULL;
			const char* forwarder_check_query = iniparser_getstring(config, forwarder_check_query_key, NULL);
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
				(uint64_t)iniparser_getint(config, forwarder_weight_key, DB_DEFAULT_WEIGHT);
			ret->frontends[ret->frontends_count]->backend.total_weight +=
				ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->weight;

			pfcq_free(forwarder_host_key);
			pfcq_free(forwarder_port_key);
			pfcq_free(forwarder_layer3_key);
			pfcq_free(forwarder_check_attempts_key);
			pfcq_free(forwarder_check_timeout_key);
			pfcq_free(forwarder_check_query_key);
			pfcq_free(forwarder_weight_key);

			ret->frontends[ret->frontends_count]->backend.forwarders_count++;
		}
		pfcq_free(backend_forwarders_iterator_p);

		pfcq_free(backend_mode_key);
		pfcq_free(backend_forwarders_key);

#ifdef DB_INIPARSER4
		const char* frontend_acl = NULL;
#else /* DB_INIPARSER4 */
		char* frontend_acl = NULL;
#endif /* DB_INIPARSER4 */
		frontend_acl = iniparser_getstring(config, frontend_acl_key, NULL);
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

		pfcq_free(frontend_workers_key);
		pfcq_free(frontend_dns_max_packet_length_key);
		pfcq_free(frontend_port_key);
		pfcq_free(frontend_backend_key);
		pfcq_free(frontend_layer3_key);
		pfcq_free(frontend_bind_key);
		pfcq_free(frontend_acl_key);

		ret->frontends_count++;
	}
	pfcq_free(frontends_str_iterator_p);

	iniparser_freedict(config);

	ret->watchdog_pool = pfpthq_init("watchdog", 1);
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

		for (int j = 0; j < ret->frontends[i]->workers; j++)
			pfpthq_inc(ret->frontends[i]->workers_pool, &ret->frontends[i]->workers_id[j], ret->frontends[i]->name, db_worker, (void*)ret->frontends[i]);
	}

	return ret;
}

void db_local_context_unload(db_local_context_t* _l_ctx)
{
	for (size_t i = 0; i < _l_ctx->frontends_count; i++)
	{
		for (int j = 0; j < _l_ctx->frontends[i]->workers; j++)
			if (unlikely(pthread_kill(_l_ctx->frontends[i]->workers_id[j], SIGINT)))
				panic("pthread_kill");
		pfpthq_wait(_l_ctx->frontends[i]->workers_pool);
		pfpthq_done(_l_ctx->frontends[i]->workers_pool);
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
		pfcq_free(_l_ctx->frontends[i]->workers_id);
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

	pfpthq_wait(_l_ctx->watchdog_pool);
	pfpthq_done(_l_ctx->watchdog_pool);

	pfcq_free(_l_ctx);

	return;
}

