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

#include <hashitems.h>
#include <pthread.h>

void db_push_item(db_hashlist_t* _hashlist, struct db_item* _item)
{
	size_t db_hashitem = _item->hash.crc % _hashlist->size;

	if (unlikely(pthread_mutex_lock(&_hashlist->list[db_hashitem].lock)))
		panic("pthread_mutex_lock");
	TAILQ_INSERT_TAIL(&_hashlist->list[db_hashitem].items, _item, tailq);
	_hashlist->list[db_hashitem].items_count++;
	if (unlikely(pthread_mutex_unlock(&_hashlist->list[db_hashitem].lock)))
		panic("pthread_mutex_unlock");

	if (unlikely(pthread_spin_lock(&_hashlist->items_count_lock)))
		panic("pthread_spin_lock");
	_hashlist->items_count++;
	if (unlikely(pthread_spin_unlock(&_hashlist->items_count_lock)))
		panic("pthread_spin_unlock");

	return;
}

struct db_item* db_pop_item(db_hashlist_t* _hashlist, db_hash_t* _hash)
{
	struct db_item* ret = NULL;

	struct db_item* current_item = NULL;
	size_t db_hashitem = _hash->crc % _hashlist->size;
	if (unlikely(pthread_mutex_lock(&_hashlist->list[db_hashitem].lock)))
		panic("pthread_mutex_lock");
	TAILQ_FOREACH(current_item, &_hashlist->list[db_hashitem].items, tailq)
		if (db_compare_hashes(&current_item->hash, _hash))
		{
			ret = current_item;
			break;
		}
	if (likely(ret))
	{
		TAILQ_REMOVE(&_hashlist->list[db_hashitem].items, ret, tailq);
		_hashlist->list[db_hashitem].items_count--;
	}
	if (unlikely(pthread_mutex_unlock(&_hashlist->list[db_hashitem].lock)))
		panic("pthread_mutex_unlock");

	if (unlikely(pthread_spin_lock(&_hashlist->items_count_lock)))
		panic("pthread_spin_lock");
	_hashlist->items_count--;
	if (unlikely(pthread_spin_unlock(&_hashlist->items_count_lock)))
		panic("pthread_spin_unlock");

	return ret;
}

void db_destroy_item_unsafe(db_hashlist_t* _hashlist, size_t _bucket, struct db_item* _item)
{
	TAILQ_REMOVE(&_hashlist->list[_bucket].items, _item, tailq);
	db_free_hash(&_item->hash);
	pfcq_free(_item);
	_hashlist->list[_bucket].items_count--;

	if (unlikely(pthread_spin_lock(&_hashlist->items_count_lock)))
		panic("pthread_spin_lock");
	_hashlist->items_count--;
	if (unlikely(pthread_spin_unlock(&_hashlist->items_count_lock)))
		panic("pthread_spin_unlock");

	return;
}

