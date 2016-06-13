/* vim: set tabstop=4:softtabstop=4:shiftwidth=4:noexpandtab */

/*
 * Copyright 2015 Lanet Network
 * Programmed by Oleksandr Natalenko <o.natalenko@lanet.ua>
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

#pragma once

#ifndef __PFPTHQ_H__
#define __PFPTHQ_H__

#include <pthread.h>
#include <semaphore.h>

typedef struct pfpthq_pool
{
	char* pool_name;
	int workers_count;
	int max_workers_count;
	pthread_mutex_t workers_count_lock;
	pthread_mutex_t workers_global_lock;
	sem_t dispatcher;
} pfpthq_pool_t;
typedef void* (worker_handler_t)(void*);

void pfpthq_inc(pfpthq_pool_t* _pool, pthread_t* _id, const char* _name, worker_handler_t _handler, void* _arg) __attribute__((nonnull(1, 2, 3)));
void pfpthq_dec(pfpthq_pool_t* _pool) __attribute__((nonnull(1)));
int pfpthq_get(pfpthq_pool_t* _pool) __attribute__((warn_unused_result, nonnull(1)));
pfpthq_pool_t* pfpthq_init(const char* _pool_name, int _max) __attribute__((nonnull(1), warn_unused_result));
void pfpthq_wait(pfpthq_pool_t* _pool) __attribute__((nonnull(1)));
void pfpthq_done(pfpthq_pool_t* _pool) __attribute__((nonnull(1)));

#endif /* __PFPTHQ_H__ */

