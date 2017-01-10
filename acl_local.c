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

#include "acl.h"
#include "config.h"

#include "acl_local.h"

void db_acl_local_load(struct collection_item* _config, const char* _acl_name, struct db_acl* _acl)
{
	int acl_items_count = 0;
	char** acl_items = NULL;

	acl_items = db_config_get_keys(_config, _acl_name, &acl_items_count);
	if (unlikely(acl_items_count < 1))
	{
		inform("No ACL %s found in config file\n", _acl_name);
		return;
	}
	TAILQ_INIT(_acl);
	for (int i = 0; i < acl_items_count; i++)
	{
		const char* acl_item_expr = db_config_get_cstr(_config, _acl_name, acl_items[i]);
		char* acl_item_expr_i = pfcq_strdup(acl_item_expr);
		char* acl_item_expr_p = acl_item_expr_i;

		char* acl_item_layer3 = strsep(&acl_item_expr_i, DB_CONFIG_PARAMETERS_SEPARATOR);
		if (unlikely(!acl_item_layer3))
		{
			inform("ACL: %s, no layer 3 specified\n", _acl_name);
			pfcq_free(acl_item_expr_p);
			continue;
		}

		char* acl_item_host = strsep(&acl_item_expr_i, DB_CONFIG_PARAMETERS_SEPARATOR);
		if (unlikely(!acl_item_host))
		{
			inform("ACL: %s, no host specified\n", _acl_name);
			pfcq_free(acl_item_expr_p);
			continue;
		}

		char* acl_item_netmask = strsep(&acl_item_expr_i, DB_CONFIG_PARAMETERS_SEPARATOR);
		if (unlikely(!acl_item_netmask))
		{
			inform("ACL: %s, no netmask specified\n", _acl_name);
			pfcq_free(acl_item_expr_p);
			continue;
		}
		char* acl_item_matcher = strsep(&acl_item_expr_i, DB_CONFIG_PARAMETERS_SEPARATOR);
		if (unlikely(!acl_item_matcher))
		{
			inform("ACL: %s, no matcher specified\n", _acl_name);
			pfcq_free(acl_item_expr_p);
			continue;
		}
		char* acl_item_list = strsep(&acl_item_expr_i, DB_CONFIG_PARAMETERS_SEPARATOR);
		if (unlikely(!acl_item_list))
		{
			inform("ACL: %s, no list specified\n", _acl_name);
			pfcq_free(acl_item_expr_p);
			continue;
		}
		char* acl_item_action = strsep(&acl_item_expr_i, DB_CONFIG_PARAMETERS_SEPARATOR);
		if (unlikely(!acl_item_action))
		{
			inform("ACL: %s, no action specified\n", _acl_name);
			pfcq_free(acl_item_expr_p);
			continue;
		}
		char* acl_item_action_parameters = strsep(&acl_item_expr_i, DB_CONFIG_PARAMETERS_SEPARATOR);
		if (unlikely(!acl_item_action_parameters))
		{
			inform("ACL: %s, no action parameters specified\n", _acl_name);
			pfcq_free(acl_item_expr_p);
			continue;
		}

		struct db_acl_item* new_acl_item = pfcq_alloc(sizeof(struct db_acl_item));

		new_acl_item->s_layer3 = pfcq_strdup(acl_item_layer3);
		new_acl_item->s_address = pfcq_strdup(acl_item_host);
		new_acl_item->s_netmask = pfcq_strdup(acl_item_netmask);
		new_acl_item->s_matcher = pfcq_strdup(acl_item_matcher);
		new_acl_item->s_list = pfcq_strdup(acl_item_list);
		new_acl_item->s_action = pfcq_strdup(acl_item_action);
		new_acl_item->s_action_parameters = pfcq_strdup(acl_item_action_parameters);
		if (unlikely(pthread_spin_init(&new_acl_item->hits_lock, PTHREAD_PROCESS_PRIVATE)))
			panic("pthread_spin_init");

		if (strcmp(acl_item_layer3, DB_CONFIG_IPV4) == 0)
			new_acl_item->layer3 = PF_INET;
		else if (strcmp(acl_item_layer3, DB_CONFIG_IPV6) == 0)
			new_acl_item->layer3 = PF_INET6;
		else
		{
			inform("ACL: %s, unknown layer 3 protocol specified in config file\n", _acl_name);
			db_acl_free_item(new_acl_item);
			pfcq_free(acl_item_expr_p);
			continue;
		}

		switch (new_acl_item->layer3)
		{
			case PF_INET:
				if (unlikely(inet_pton(new_acl_item->layer3, acl_item_host, &new_acl_item->address.address4) == -1))
				{
					inform("ACL: %s, unknown host specified in config file\n", _acl_name);
					db_acl_free_item(new_acl_item);
					pfcq_free(acl_item_expr_p);
					continue;
				}
				new_acl_item->netmask.address4.s_addr = htonl((~0UL) << (32 - strtol(acl_item_netmask, NULL, 10)));
				break;
			case PF_INET6:
				if (unlikely(inet_pton(new_acl_item->layer3, acl_item_host, &new_acl_item->address.address6) == -1))
				{
					inform("ACL: %s, unknown host specified in config file\n", _acl_name);
					db_acl_free_item(new_acl_item);
					pfcq_free(acl_item_expr_p);
					continue;
				}
				pfcq_zero(&new_acl_item->netmask.address6, sizeof(struct in6_addr));
				for (long j = 0; j < strtol(acl_item_netmask, NULL, 10); j++)
					new_acl_item->netmask.address6.s6_addr[j / 8] |= (uint8_t)(1 << (j % 8));
				break;
			default:
				panic("socket domain");
				break;
		}
		if (strcmp(acl_item_matcher, DB_CONFIG_ACL_MATCHER_STRICT) == 0)
			new_acl_item->matcher = DB_ACL_MATCHER_STRICT;
		else if (strcmp(acl_item_matcher, DB_CONFIG_ACL_MATCHER_SUBDOMAIN) == 0)
			new_acl_item->matcher = DB_ACL_MATCHER_SUBDOMAIN;
		else if (strcmp(acl_item_matcher, DB_CONFIG_ACL_MATCHER_REGEX) == 0)
			new_acl_item->matcher = DB_ACL_MATCHER_REGEX;
		else
		{
			inform("ACL: %s, unknown matcher specified in config file\n", _acl_name);
			db_acl_free_item(new_acl_item);
			pfcq_free(acl_item_expr_p);
			continue;
		}

		if (strcmp(acl_item_action, DB_CONFIG_ACL_ACTION_ALLOW) == 0)
			new_acl_item->action = DB_ACL_ACTION_ALLOW;
		else if (strcmp(acl_item_action, DB_CONFIG_ACL_ACTION_DENY) == 0)
			new_acl_item->action = DB_ACL_ACTION_DENY;
		else if (strcmp(acl_item_action, DB_CONFIG_ACL_ACTION_NXDOMAIN) == 0)
			new_acl_item->action = DB_ACL_ACTION_NXDOMAIN;
		else if (strcmp(acl_item_action, DB_CONFIG_ACL_ACTION_SET_A) == 0)
		{
			new_acl_item->action = DB_ACL_ACTION_SET_A;
			char* acl_item_action_parameters_i = pfcq_strdup(acl_item_action_parameters);
			char* acl_item_action_parameters_p = acl_item_action_parameters_i;
			char* set_a_address = strsep(&acl_item_action_parameters_i, DB_CONFIG_LIST_SEPARATOR);
			if (unlikely(inet_pton(PF_INET, set_a_address, &new_acl_item->action_parameters.set_a.address4) == -1))
			{
				inform("ACL: %s, unable to translate SET_A host specified in config file\n", _acl_name);
				db_acl_free_item(new_acl_item);
				pfcq_free(acl_item_expr_p);
				pfcq_free(acl_item_action_parameters_p);
				continue;
			}
			char* set_a_ttl = strsep(&acl_item_action_parameters_i, DB_CONFIG_LIST_SEPARATOR);
			if (!pfcq_isnumber(set_a_ttl))
			{
				inform("ACL: %s, unable to translate SET_A TTL specified in config file\n", _acl_name);
				db_acl_free_item(new_acl_item);
				pfcq_free(acl_item_expr_p);
				pfcq_free(acl_item_action_parameters_p);
				continue;
			}
			new_acl_item->action_parameters.set_a.ttl = strtoll(set_a_ttl, NULL, 10);
			pfcq_free(acl_item_action_parameters_p);
		} else
		{
			inform("ACL: %s, invalid action specified in config file\n", _acl_name);
			db_acl_free_item(new_acl_item);
			pfcq_free(acl_item_expr_p);
			continue;
		}

		int list_items_count = 0;
		char** list_items = NULL;

		list_items = db_config_get_keys(_config, acl_item_list, &list_items_count);
		if (unlikely(list_items_count < 1))
		{
			inform("ACL: %s, list: %s, no list found in config file\n", _acl_name, acl_item_list);
			db_acl_free_item(new_acl_item);
			pfcq_free(acl_item_expr_p);
			continue;
		}
		TAILQ_INIT(&new_acl_item->list);
		for (int j = 0; j < list_items_count; j++)
		{
			const char* list_item = db_config_get_cstr(_config, acl_item_list, list_items[j]);
			char* list_item_i = pfcq_strdup(list_item);
			char* list_item_p = list_item_i;

			struct db_list_item* new_list_item = pfcq_alloc(sizeof(struct db_list_item));
			new_list_item->s_name = pfcq_strdup(list_items[j]);

			// DNS RR type
			char* list_item_type = strsep(&list_item_i, DB_CONFIG_PARAMETERS_SEPARATOR);
			if (unlikely(!list_item_type))
			{
				inform("ACL: %s, no RR type specified in config file\n", _acl_name);
				pfcq_free(list_item_p);
				db_acl_free_list_item(new_list_item);
				continue;
			}
			if (strcmp(list_item_type, DB_CONFIG_ACL_RR_TYPE_ALL) == 0)
				new_list_item->rr_type = DB_ACL_RR_TYPE_ALL;
			else if (strcmp(list_item_type, DB_CONFIG_ACL_RR_TYPE_ANY) == 0)
				new_list_item->rr_type = DB_ACL_RR_TYPE_ANY;
			else
			{
				inform("ACL: %s, invalid RR type specified in config file\n", _acl_name);
				pfcq_free(list_item_p);
				db_acl_free_list_item(new_list_item);
				continue;
			}

			// DNS request FQDN
			char* list_item_fqdn = strsep(&list_item_i, DB_CONFIG_PARAMETERS_SEPARATOR);
			if (unlikely(!list_item_fqdn))
			{
				inform("ACL: %s, no FQDN specified in config file\n", _acl_name);
				pfcq_free(list_item_p);
				db_acl_free_list_item(new_list_item);
				continue;
			}
			new_list_item->s_fqdn = pfcq_strdup(list_item_fqdn);
			new_list_item->s_fqdn_length = strlen(new_list_item->s_fqdn);
			new_list_item->s_fqdn_hash = pfcq_fast_hash((uint8_t*)new_list_item->s_fqdn, new_list_item->s_fqdn_length, DB_HASH_SEED);

			pfcq_free(list_item_p);

			switch (new_acl_item->matcher)
			{
				case DB_ACL_MATCHER_STRICT:
					break;
				case DB_ACL_MATCHER_SUBDOMAIN:
					break;
				case DB_ACL_MATCHER_REGEX:
					if (unlikely(regcomp(&new_list_item->regex, new_list_item->s_fqdn, REG_EXTENDED | REG_NOSUB)))
					{
						inform("List: %s, unable to compile regex specified in config file\n", acl_item_list);
						db_acl_free_list_item(new_list_item);
						continue;
					} else
						new_list_item->regex_compiled = 1;
					break;
				default:
					panic("Unknown matcher");
					break;
			}
			TAILQ_INSERT_TAIL(&new_acl_item->list, new_list_item, tailq);
		}
		db_config_free_keys(list_items);

		TAILQ_INSERT_TAIL(_acl, new_acl_item, tailq);

		pfcq_free(acl_item_expr_p);
	}

	db_config_free_keys(acl_items);

	return;
}

void db_acl_local_unload(struct db_acl* _acl)
{
	while (likely(!TAILQ_EMPTY(_acl)))
	{
		struct db_acl_item* current_acl_item = TAILQ_FIRST(_acl);
		TAILQ_REMOVE(_acl, current_acl_item, tailq);
		while (likely(!TAILQ_EMPTY(&current_acl_item->list)))
		{
			struct db_list_item* current_list_item = TAILQ_FIRST(&current_acl_item->list);
			TAILQ_REMOVE(&current_acl_item->list, current_list_item, tailq);
			db_acl_free_list_item(current_list_item);
		}
		db_acl_free_item(current_acl_item);
	}

	return;
}

