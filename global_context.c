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

#include <global_context.h>
#include <iniparser.h>
#include <signal.h>

extern volatile sig_atomic_t should_exit;

static void* db_gc(void* _data)
{
	if (unlikely(!_data))
		return NULL;
	db_global_context_t* ctx = _data;

	for (;;)
	{
		if (unlikely(should_exit))
			break;

		struct timespec current_time;
		if (unlikely(clock_gettime(CLOCK_REALTIME, &current_time) == -1))
			panic("clock_gettime");

		// Dead sockets cleaner
		struct db_item* current_item = NULL;
		struct db_item* tmp_item = NULL;
		for (size_t i = 0; i < ctx->db_hashlist.size; i++)
		{
			if (unlikely(pthread_mutex_lock(&ctx->db_hashlist.list[i].lock)))
				panic("pthread_mutex_lock");
			for (current_item = TAILQ_FIRST(&ctx->db_hashlist.list[i].items); current_item; current_item = tmp_item)
			{
				tmp_item = TAILQ_NEXT(current_item, tailq);
				int64_t diff_ns = __pfcq_timespec_diff_ns(current_item->ctime, current_time);
				if (unlikely(diff_ns >= (int64_t)ctx->db_hashlist.ttl))
					db_destroy_item_unsafe(&ctx->db_hashlist, i, current_item);
			}
			if (unlikely(pthread_mutex_unlock(&ctx->db_hashlist.list[i].lock)))
				panic("pthread_mutex_unlock");
		}

		pfcq_sleep(ctx->db_gc_interval);
	}

	pfpthq_dec(ctx->gc_pool);

	return NULL;
}

db_global_context_t* db_global_context_load(const char* _config_file)
{
	db_global_context_t* ret = NULL;
	dictionary* config = NULL;

	ret = pfcq_alloc(sizeof(db_global_context_t));

	config = iniparser_load(_config_file);
	if (unlikely(!config))
		stop("Unable to load config file");

	ret->db_hashlist.size = (size_t)iniparser_getint(config, DB_CONFIG_HASHLIST_SIZE_KEY, DB_DEFAULT_HASHLIST_SIZE);
	ret->db_hashlist.list = pfcq_alloc(ret->db_hashlist.size * sizeof(db_hashitem_t));
	for (size_t i = 0; i < ret->db_hashlist.size; i++)
	{
		pfcq_zero(&ret->db_hashlist.list[i], sizeof(db_hashitem_t));
		if (unlikely(pthread_mutex_init(&ret->db_hashlist.list[i].lock, NULL)))
			panic("pthread_mutex_init");
		TAILQ_INIT(&ret->db_hashlist.list[i].items);
	}

	ret->db_hashlist.ttl = ((uint64_t)iniparser_getint(config, DB_CONFIG_HASHLIST_TTL_KEY, DB_DEFAULT_HASHLIST_TTL)) * 1000000ULL;
	if (unlikely(ret->db_hashlist.ttl > INT64_MAX))
	{
		inform("Hashlist TTL must not exceed %ld ms.\n", INT64_MAX);
		stop("Are you OK?");
	}

	ret->db_gc_interval = ((uint64_t)iniparser_getint(config, DB_CONFIG_GC_INTERVAL_KEY, DB_DEFAULT_GC_INTERVAL)) * 1000000ULL;
	ret->gc_pool = pfpthq_init("gc", 1);
	pfpthq_inc(ret->gc_pool, &ret->gc_id, "gc", db_gc, (void*)ret);

	iniparser_freedict(config);

	return ret;
}

void db_global_context_unload(db_global_context_t* _g_ctx)
{
	pfpthq_wait(_g_ctx->gc_pool);
	pfpthq_done(_g_ctx->gc_pool);

	for (size_t i = 0; i < _g_ctx->db_hashlist.size; i++)
	{
		while (likely(!TAILQ_EMPTY(&_g_ctx->db_hashlist.list[i].items)))
		{
			struct db_item* current_item = TAILQ_FIRST(&_g_ctx->db_hashlist.list[i].items);
			db_destroy_item_unsafe(&_g_ctx->db_hashlist, i, current_item);
		}
		if (unlikely(pthread_mutex_destroy(&_g_ctx->db_hashlist.list[i].lock)))
			panic("pthread_mutex_destroy");
	}
	pfcq_free(_g_ctx->db_hashlist.list);

	pfcq_free(_g_ctx);

	return;
}

