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

#ifndef __HASHITEMS_H__
#define __HASHITEMS_H__

#include <hash.h>
#include <pfcq.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/queue.h>

struct db_item
{
	TAILQ_ENTRY(db_item) tailq;
	db_hash_t hash;
	pfcq_net_address_t address;
	size_t forwarder;
	struct timespec ctime;
};

TAILQ_HEAD(db_items, db_item);

typedef struct db_hashitem
{
	struct db_items items;
	size_t items_count;
	pthread_mutex_t lock;
} db_hashitem_t;

typedef struct db_hashlist
{
	db_hashitem_t* list;
	size_t size;
	size_t max_collisions;
	pthread_spinlock_t max_collisions_lock;
	int __padding1;
	uint64_t ttl;
} db_hashlist_t;

void db_push_item(db_hashlist_t* _hashlist, struct db_item* _item) __attribute__((nonnull(1, 2)));
struct db_item* db_pop_item(db_hashlist_t* _hashlist, db_hash_t* _hash) __attribute__((nonnull(1, 2)));
void db_destroy_item_unsafe(db_hashlist_t* _hashlist, size_t _bucket, struct db_item* _item) __attribute__((nonnull(1, 3)));

#endif /* __HASHITEMS_H__ */

