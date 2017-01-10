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

#include <ini_config.h>
#include <pthread.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include "request.h"
#include "types.h"

#include "contrib/pfcq/pfcq.h"

#include "global_context.h"

static void* db_gc(void* _data)
{
	int epoll_fd = -1;
	struct epoll_event epoll_event;
	struct epoll_event epoll_events[EPOLL_MAXEVENTS];

	if (unlikely(!_data))
		return NULL;
	struct db_global_context* ctx = _data;

	pfcq_zero(&epoll_event, sizeof(struct epoll_event));
	pfcq_zero(&epoll_events, EPOLL_MAXEVENTS * sizeof(struct epoll_event));

	epoll_fd = epoll_create1(0);
	if (unlikely(epoll_fd == -1))
		panic("epoll_create");
	epoll_event.data.fd = ctx->gc_eventfd;
	epoll_event.events = EPOLLIN;
	if (unlikely(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ctx->gc_eventfd, &epoll_event) == -1))
		panic("epoll_ctl");

	for (;;)
	{
		int epoll_count = epoll_wait(epoll_fd, epoll_events, EPOLL_MAXEVENTS, ctx->db_gc_interval);
		if (unlikely(epoll_count == -1))
		{
			// Ignore errors
			continue;
		} else
		{
			for (int i = 0; i < epoll_count; i++)
			{
				if (unlikely((epoll_events[i].events & EPOLLERR) ||
							(epoll_events[i].events & EPOLLHUP) ||
							!(epoll_events[i].events & EPOLLIN)))
				{
					// Ignore hangup
					continue;
				} else if (likely(epoll_events[i].data.fd == ctx->gc_eventfd))
				{
					// Shutdown
					goto lfree;
				}
			}
		}

		struct timespec current_time;
		if (unlikely(clock_gettime(CLOCK_REALTIME, &current_time) == -1))
			panic("clock_gettime");

		// Dead sockets cleaner
		struct db_request* current_item = NULL;
		struct db_request* tmp_item = NULL;
		for (size_t i = 0; i < UINT16_MAX; i++)
		{
			if (unlikely(pthread_mutex_lock(&ctx->db_requests.list[i].requests_lock)))
				panic("pthread_mutex_lock");
			for (current_item = TAILQ_FIRST(&ctx->db_requests.list[i].requests); current_item; current_item = tmp_item)
			{
				tmp_item = TAILQ_NEXT(current_item, tailq);
				int64_t diff_ns = __pfcq_timespec_diff_ns(current_item->ctime, current_time);
				if (unlikely(diff_ns >= (int64_t)ctx->db_requests.ttl))
					db_remove_request_unsafe(&ctx->db_requests, i, current_item);
			}
			if (unlikely(pthread_mutex_unlock(&ctx->db_requests.list[i].requests_lock)))
				panic("pthread_mutex_unlock");
		}
	}

lfree:
	if (unlikely(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, ctx->gc_eventfd, NULL) == -1))
		panic("epoll_ctl");
	if (unlikely(close(ctx->gc_eventfd) == -1))
		panic("close");

	pfpthq_dec(ctx->gc_pool);

	return NULL;
}

struct db_global_context* db_global_context_load(const char* _config_file)
{
	struct db_global_context* ret = NULL;
	struct collection_item* config = NULL;
	struct collection_item* item = NULL;

	ret = pfcq_alloc(sizeof(struct db_global_context));

	if (unlikely(config_from_file(APP_NAME, _config_file, &config, INI_STOP_ON_ANY, NULL)))
		stop("Unable to load config file");

	pfcq_zero(&ret->db_requests.list, UINT16_MAX * sizeof(struct db_request_bucket));
	ret->db_requests.list_index = 0;
	if (unlikely(pthread_spin_init(&ret->db_requests.list_index_lock, PTHREAD_PROCESS_PRIVATE)))
		panic("pthread_spin_init");
	for (size_t i = 0; i < UINT16_MAX; i++)
	{
		pfcq_zero(&ret->db_requests.list[i], sizeof(struct db_request_bucket));
		if (unlikely(pthread_mutex_init(&ret->db_requests.list[i].requests_lock, NULL)))
			panic("pthread_mutex_init");
		TAILQ_INIT(&ret->db_requests.list[i].requests);
	}
	ret->db_requests.requests_count = 0;
	if (unlikely(pthread_spin_init(&ret->db_requests.requests_count_lock, PTHREAD_PROCESS_PRIVATE)))
		panic("pthread_spin_init");

	if (unlikely(get_config_item(DB_CONFIG_GENERAL_SECTION, DB_CONFIG_REQUEST_TTL_KEY, config, &item)))
		stop("Unable to get \"" DB_CONFIG_REQUEST_TTL_KEY "\" value from config file");
	ret->db_requests.ttl = get_uint64_config_value(item, 0, DB_DEFAULT_REQUEST_TTL, NULL) * 1000000ULL;
	if (unlikely(ret->db_requests.ttl > INT64_MAX))
	{
		inform("Request TTL must not exceed %ld ms.\n", INT64_MAX);
		stop("Are you OK?");
	}

	if (unlikely(get_config_item(DB_CONFIG_GENERAL_SECTION, DB_CONFIG_RELOAD_RETRY_KEY, config, &item)))
		stop("Unable to get \"" DB_CONFIG_RELOAD_RETRY_KEY "\" value from config file");
	ret->reload_retry = get_uint64_config_value(item, 0, DB_DEFAULT_RELOAD_RETRY, NULL);
	if (unlikely(ret->reload_retry > INT64_MAX))
	{
		inform("Reload retry timeout must not exceed %ld ms.\n", INT64_MAX);
		stop("Are you OK?");
	}

	if (unlikely(get_config_item(DB_CONFIG_GENERAL_SECTION, DB_CONFIG_GC_INTERVAL_KEY, config, &item)))
		stop("Unable to get \"" DB_CONFIG_GC_INTERVAL_KEY "\" value from config file");
	ret->db_gc_interval = get_uint64_config_value(item, 0, DB_DEFAULT_GC_INTERVAL, NULL);
	ret->gc_pool = pfpthq_init("gc", 1);
	ret->gc_eventfd = eventfd(0, 0);
	if (unlikely(ret->gc_eventfd == -1))
		panic("eventfd");
	pfpthq_inc(ret->gc_pool, &ret->gc_id, "gc", db_gc, (void*)ret);

	free_ini_config(config);

	return ret;
}

void db_global_context_unload(struct db_global_context* _g_ctx)
{
	if (unlikely(eventfd_write(_g_ctx->gc_eventfd, 1) == -1))
		panic("eventfd_write");
	pfpthq_wait(_g_ctx->gc_pool);
	pfpthq_done(_g_ctx->gc_pool);

	for (size_t i = 0; i < UINT16_MAX; i++)
	{
		while (likely(!TAILQ_EMPTY(&_g_ctx->db_requests.list[i].requests)))
		{
			struct db_request* current_item = TAILQ_FIRST(&_g_ctx->db_requests.list[i].requests);
			db_remove_request_unsafe(&_g_ctx->db_requests, i, current_item);
		}
		if (unlikely(pthread_mutex_destroy(&_g_ctx->db_requests.list[i].requests_lock)))
			panic("pthread_mutex_destroy");
	}
	pfcq_zero(_g_ctx->db_requests.list, UINT16_MAX * sizeof(struct db_request_bucket));
	_g_ctx->db_requests.list_index = 0;
	if (unlikely(pthread_spin_destroy(&_g_ctx->db_requests.list_index_lock)))
		panic("pthread_spin_destroy");
	_g_ctx->db_requests.requests_count = 0;
	if (unlikely(pthread_spin_destroy(&_g_ctx->db_requests.requests_count_lock)))
		panic("pthread_spin_destroy");

	pfcq_free(_g_ctx);

	return;
}

