/* vim: set tabstop=4:softtabstop=4:shiftwidth=4:noexpandtab */

/*
 * Copyright 2015 Lanet Network
 * Programmed by Oleksandr Natalenko <o.natalenko@lanet.ua>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <unistd.h>

#include "pfpthq.h"

#include "../pfcq/pfcq.h"

void pfpthq_inc(pfpthq_pool_t* _pool, pthread_t* _id, const char* _name, worker_handler_t _handler, void* _arg)
{
	if (_pool->max_workers_count > 0)
		if (unlikely(sem_wait(&_pool->dispatcher) == -1))
			panic("sem_wait");
	if (unlikely(pthread_mutex_lock(&_pool->workers_count_lock)))
		panic("pthread_mutex_lock");
	_pool->workers_count++;
	if (unlikely(_pool->workers_count == 1))
		if (unlikely(pthread_mutex_lock(&_pool->workers_global_lock)))
			panic("pthread_mutex_lock");
	if (unlikely(pthread_mutex_unlock(&_pool->workers_count_lock)))
		panic("pthread_mutex_unlock");
	if (unlikely(pthread_create(_id, NULL, _handler, _arg) != 0))
		panic("pthread_create");
	pthread_setname_np(*_id, _name);
	if (unlikely(pthread_detach(*_id) != 0))
		panic("pthread_detach");

	return;
}

void pfpthq_dec(pfpthq_pool_t* _pool)
{
	if (unlikely(pthread_mutex_lock(&_pool->workers_count_lock)))
		panic("pthread_mutex_lock");
	_pool->workers_count--;
	if (unlikely(_pool->workers_count == 0))
	{
		if (unlikely(pthread_mutex_unlock(&_pool->workers_count_lock)))
			panic("pthread_mutex_unlock");
		if (unlikely(pthread_mutex_unlock(&_pool->workers_global_lock)))
			panic("pthread_mutex_unlock");
	} else
		if (unlikely(pthread_mutex_unlock(&_pool->workers_count_lock)))
			panic("pthread_mutex_unlock");
	if (_pool->max_workers_count > 0)
		if (unlikely(sem_post(&_pool->dispatcher) == -1))
			panic("sem_post");

	return;
}

int pfpthq_get(pfpthq_pool_t* _pool)
{
	int ret = -1;

	if (unlikely(pthread_mutex_lock(&_pool->workers_count_lock)))
		panic("pthread_mutex_lock");
	ret = _pool->workers_count;
	if (unlikely(pthread_mutex_unlock(&_pool->workers_count_lock)))
		panic("pthread_mutex_unlock");

	return ret;
}

pfpthq_pool_t* pfpthq_init(const char* _pool_name, int _max)
{
	pfpthq_pool_t* new_pool = pfcq_alloc(sizeof(pfpthq_pool_t));
	new_pool->workers_count = 0;
	new_pool->pool_name = pfcq_strdup(_pool_name);
	if (unlikely(!new_pool->pool_name))
		panic("strdup");
	if (_max != 0)
		new_pool->max_workers_count = pfcq_hint_cpus(_max);
	else
		new_pool->max_workers_count = 0;
	if (unlikely(pthread_mutex_init(&new_pool->workers_count_lock, NULL)))
		panic("pthread_mutex_init");
	if (unlikely(pthread_mutex_init(&new_pool->workers_global_lock, NULL)))
		panic("pthread_mutex_init");

	if (new_pool->max_workers_count > 0)
		if (unlikely(sem_init(&new_pool->dispatcher, 0, new_pool->max_workers_count) == -1))
			panic("sem_init");

	if (_max != 0)
		debug("[Pool: %s] Using at most %d workers\n", new_pool->pool_name, new_pool->max_workers_count);
	else
		debug("[Pool: %s] Using unlimited number of workers\n", new_pool->pool_name);

	return new_pool;
}

void pfpthq_wait(pfpthq_pool_t* _pool)
{
	debug("[Pool: %s] Waiting for workers to be terminated...\n", _pool->pool_name);
	if (unlikely(pthread_mutex_lock(&_pool->workers_global_lock)))
		panic("pthread_mutex_lock");
	if (unlikely(pthread_mutex_unlock(&_pool->workers_global_lock)))
		panic("pthread_mutex_unlock");

	return;
}

void pfpthq_done(pfpthq_pool_t* _pool)
{
	if (unlikely(pthread_mutex_destroy(&_pool->workers_count_lock)))
		panic("pthread_mutex_destroy");
	if (unlikely(pthread_mutex_destroy(&_pool->workers_global_lock)))
		panic("pthread_mutex_destroy");

	if (_pool->max_workers_count > 0)
		if (unlikely(sem_destroy(&_pool->dispatcher) == -1))
			panic("sem_destroy");

	pfcq_free(_pool->pool_name);
	pfcq_free(_pool);

	return;
}

