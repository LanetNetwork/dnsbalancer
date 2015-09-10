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

#include <acl.h>
#include <crc64speed.h>
#include <pthread.h>

void db_acl_free_item(struct db_acl_item* _item)
{
	pfcq_free(_item->s_action_parameters);
	pfcq_free(_item->s_action);
	pfcq_free(_item->s_list);
	pfcq_free(_item->s_matcher);
	pfcq_free(_item->s_netmask);
	pfcq_free(_item->s_address);
	pfcq_free(_item->s_layer3);
	pthread_spin_destroy(&_item->hits_lock);
	pfcq_free(_item);

	return;
}

void db_acl_free_list_item(struct db_list_item* _item)
{
	pfcq_free(_item->s_name);
	pfcq_free(_item->s_value);
	if (likely(_item->regex_compiled))
		regfree(&_item->regex);
	pfcq_free(_item);

	return;
}

db_acl_action_t db_check_query_acl(sa_family_t _layer3, pfcq_net_address_t* _address, db_prehash_t* _prehash, struct db_acl* _acl)
{
	db_acl_action_t ret = DB_ACL_ACTION_ALLOW;

	struct db_acl_item* current_acl_item = NULL;
	TAILQ_FOREACH(current_acl_item, _acl, tailq)
	{
		unsigned short int address_matched = 0;
		struct in6_addr anded6;
		switch (_layer3)
		{
			case PF_INET:
				address_matched = (unsigned short int)
					((_address->address4.sin_addr.s_addr & current_acl_item->netmask.address4.s_addr) == current_acl_item->address.address4.s_addr);
				break;
			case PF_INET6:
				for (size_t k = 0; k < 16; k++)
				{
					anded6.s6_addr[k] = (uint8_t)(_address->address6.sin6_addr.s6_addr[k] & current_acl_item->netmask.address6.s6_addr[k]);
					address_matched = (unsigned short int)(anded6.s6_addr[k] == current_acl_item->address.address6.s6_addr[k]);
					if (!address_matched)
						break;
				}
				break;
			default:
				panic("socket domain");
				break;
		}
		if (address_matched)
		{
			uint64_t fqdn_hash = crc64speed(0, (uint8_t*)_prehash->fqdn, strlen(_prehash->fqdn));
			unsigned short int matcher_matched = 0;
			struct db_list_item* current_list_item = NULL;
			TAILQ_FOREACH(current_list_item, &current_acl_item->list, tailq)
			{
				switch (current_acl_item->matcher)
				{
					case DB_ACL_MATCHER_STRICT:
						if (fqdn_hash == current_list_item->s_value_hash &&
								likely(strncmp(_prehash->fqdn, current_list_item->s_value, current_list_item->s_value_length) == 0))
						{
							matcher_matched = 1;
							goto found;
						}
						break;
					case DB_ACL_MATCHER_SUBDOMAIN: __noop;
						char* pos = strstr(_prehash->fqdn, current_list_item->s_value);
						if (pos && (size_t)(pos - _prehash->fqdn) == strlen(_prehash->fqdn) - strlen(current_list_item->s_value))
						{
							matcher_matched = 1;
							goto found;
						}
						break;
					case DB_ACL_MATCHER_REGEX:
						if (regexec(&current_list_item->regex, _prehash->fqdn, 0, NULL, 0) == REG_NOERROR)
						{
							matcher_matched = 1;
							goto found;
						}
						break;
					default:
						panic("Unknown matcher");
						break;
				}
			}
found:
			if (matcher_matched)
			{
				ret = current_acl_item->action;
				if (unlikely(pthread_spin_lock(&current_acl_item->hits_lock)))
					panic("pthread_spin_lock");
				current_acl_item->hits++;
				if (unlikely(pthread_spin_unlock(&current_acl_item->hits_lock)))
					panic("pthread_spin_unlock");
				break;
			}
		}
	}

	return ret;
}

