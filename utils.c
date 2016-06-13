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

#include <dnsbalancer.h>
#include <utils.h>

#include "contrib/xxhash/xxhash.h"

static uint64_t db_netaddr_addr_hash64(sa_family_t _family, pfcq_net_address_t _netaddr)
{
	uint64_t ret = DB_HASH_SEED;
	unsigned long s_addr = 0;
	const uint8_t* s_addr_buf = NULL;
	const uint8_t* s6_addr_buf = NULL;
	uint32_t* s6_addr_piece = NULL;
	uint32_t s6_addr_piece_h = 0;

	switch (_family)
	{
		case PF_INET:
			s_addr = ntohl(_netaddr.address4.sin_addr.s_addr);
			s_addr_buf = (const uint8_t*)&s_addr;
			ret = XXH64(s_addr_buf, sizeof(unsigned long), ret);
			break;
		case PF_INET6:
			for (size_t i = 0; i < sizeof(_netaddr.address6.sin6_addr.s6_addr); i += sizeof(_netaddr.address6.sin6_addr.s6_addr) / sizeof(uint32_t))
			{
				s6_addr_piece = (uint32_t*)&_netaddr.address6.sin6_addr.s6_addr[i];
				s6_addr_piece_h = ntohl(*s6_addr_piece);
				s6_addr_buf = (const uint8_t*)&s6_addr_piece_h;
				ret = XXH64(s6_addr_buf, sizeof(uint32_t), ret);
			}
			break;
		default:
			panic("socket domain");
			break;
	}

	return ret;
}

static uint64_t db_netaddr_port_hash64(sa_family_t _family, pfcq_net_address_t _netaddr)
{
	uint64_t ret = DB_HASH_SEED;
	unsigned short u_port = 0;
	const uint8_t* u_port_buf = NULL;

	switch (_family)
	{
		case PF_INET:
			u_port = ntohs(_netaddr.address4.sin_port);
			u_port_buf = (const uint8_t*)&u_port;
			ret = XXH64(u_port_buf, sizeof(unsigned short), ret);
			break;
		case PF_INET6:
			u_port = ntohs(_netaddr.address6.sin6_port);
			u_port_buf = (const uint8_t*)&u_port;
			ret = XXH64(u_port_buf, sizeof(unsigned short), ret);
			break;
		default:
			panic("socket domain");
			break;
	}

	return ret;
}

__attribute__((always_inline)) static inline ssize_t __db_find_alive_forwarder_by_offset(uint64_t _offset, db_backend_t* _backend)
{
	ssize_t ret = -1;

	for (size_t tries = 0; tries < _backend->forwarders_count; tries++)
	{
		size_t index = (_offset + tries) % _backend->forwarders_count;
		if (likely(_backend->forwarders[index]->alive))
		{
			ret = index;
			break;
		}
	}

	return ret;
}

ssize_t db_find_alive_forwarder(db_frontend_t* _frontend, pfcq_fprng_context_t* _fprng_context, pfcq_net_address_t _netaddr)
{
	if (unlikely(!_frontend))
		return -1;

	ssize_t ret = -1;

	size_t queries = 0;
	if (unlikely(pthread_spin_lock(&_frontend->backend.queries_lock)))
		panic("pthread_spin_lock");
	queries = _frontend->backend.queries++;
	if (unlikely(pthread_spin_unlock(&_frontend->backend.queries_lock)))
		panic("pthread_spin_unlock");

	size_t index = 0;
	unsigned short int random_map[_frontend->backend.forwarders_count];
	uint64_t least_pkts = UINT64_MAX;
	uint64_t least_traffic = UINT64_MAX;
	uint64_t xor = 0;
	uint64_t hash1 = 0;
	uint64_t hash2 = 0;
	double probability = 0;
	double normalized_weight = 0;

	pfcq_zero(random_map, _frontend->backend.forwarders_count * sizeof(unsigned short int));

	switch (_frontend->backend.mode)
	{
		case DB_BE_MODE_RR:
			ret = __db_find_alive_forwarder_by_offset(queries, &_frontend->backend);
			break;
		case DB_BE_MODE_RANDOM:
			probability = (double)pfcq_fprng_get_u64(_fprng_context) / UINT64_MAX;
			for (size_t tries = 0; tries < _frontend->backend.forwarders_count; tries++)
			{
				for (index = 0; index < _frontend->backend.forwarders_count; index++)
				{
					normalized_weight = (double)_frontend->backend.forwarders[index]->weight / _frontend->backend.total_weight;
					if (_frontend->backend.forwarders[index]->alive && probability < normalized_weight)
					{
						ret = index;
						break;
					} else
						probability -= normalized_weight;
				}
				if (likely(ret != -1))
					break;
			}
			break;
		case DB_BE_MODE_LEAST_PKTS:
			for (index = 0; index < _frontend->backend.forwarders_count; index++)
				if (likely(_frontend->backend.forwarders[index]->alive))
					if (_frontend->backend.forwarders[index]->stats.in_pkts <= least_pkts)
					{
						least_pkts = _frontend->backend.forwarders[index]->stats.in_pkts;
						ret = index;
					}
			break;
		case DB_BE_MODE_LEAST_TRAFFIC:
			for (index = 0; index < _frontend->backend.forwarders_count; index++)
				if (likely(_frontend->backend.forwarders[index]->alive))
					if (_frontend->backend.forwarders[index]->stats.in_bytes <= least_traffic)
					{
						least_traffic = _frontend->backend.forwarders[index]->stats.in_bytes;
						ret = index;
					}
			break;
		case DB_BE_MODE_HASH_L3_L4:
			hash1 = db_netaddr_addr_hash64(_frontend->layer3, _netaddr);
			hash2 = db_netaddr_port_hash64(_frontend->layer3, _netaddr);
			xor = hash1 ^ hash2;
			ret = __db_find_alive_forwarder_by_offset(xor, &_frontend->backend);
			break;
		case DB_BE_MODE_HASH_L3:
			xor = db_netaddr_addr_hash64(_frontend->layer3, _netaddr);
			ret = __db_find_alive_forwarder_by_offset(xor, &_frontend->backend);
			break;
		case DB_BE_MODE_HASH_L4:
			xor = db_netaddr_port_hash64(_frontend->layer3, _netaddr);
			ret = __db_find_alive_forwarder_by_offset(xor, &_frontend->backend);
			break;
		default:
			ret = 0;
			break;
	}

	return ret;
}

