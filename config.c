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

#include "defines.h"

#include "contrib/pfcq/pfcq.h"

#include "config.h"

db_config_t* db_config_open(const char* _filepath)
{
	db_config_t* ret = NULL;

	if (unlikely(config_from_file(APP_NAME, _filepath, &ret, INI_STOP_ON_ANY, NULL)))
		stop("Unable to load config file");

	return ret;
}

void db_config_close(db_config_t* _config)
{
	free_ini_config(_config);

	return;
}

static db_config_t* __db_config_get_item(db_config_t* _config, const char* _section, const char* _key)
{
	db_config_t* ret = NULL;

	if (unlikely(get_config_item(_section, _key, _config, &ret)))
	{
		inform("Section: %s, key: %s\n", _section, _key);
		stop("Unable to get item from config file");
	}

	return ret;
}

uint64_t db_config_get_u64(db_config_t* _config, const char* _section, const char* _key, uint64_t _default)
{
	int error = 0;
	uint64_t ret = 0;

	ret = get_uint64_config_value(__db_config_get_item(_config, _section, _key), 1, _default, &error);
	if (unlikely(error))
	{
		inform("Section: %s, key: %s\n", _section, _key);
		stop("Unable to get value from item in config file");
	}

	return ret;
}

int db_config_get_int(db_config_t* _config, const char* _section, const char* _key, int _default)
{
	int error = 0;
	int ret = 0;

	ret = get_int_config_value(__db_config_get_item(_config, _section, _key), 1, _default, &error);
	if (unlikely(error))
	{
		inform("Section: %s, key: %s\n", _section, _key);
		stop("Unable to get value from item in config file");
	}

	return ret;
}

unsigned db_config_get_uint(db_config_t* _config, const char* _section, const char* _key, unsigned _default)
{
	int error = 0;
	unsigned ret = 0;

	ret = get_unsigned_config_value(__db_config_get_item(_config, _section, _key), 1, _default, &error);
	if (unlikely(error))
	{
		inform("Section: %s, key: %s\n", _section, _key);
		stop("Unable to get value from item in config file");
	}

	return ret;
}

const char* db_config_get_cstr(db_config_t* _config, const char* _section, const char* _key)
{
	int error = 0;
	const char* ret = NULL;

	ret = get_const_string_config_value(__db_config_get_item(_config, _section, _key), &error);
	if (unlikely(error))
	{
		inform("Section: %s, key: %s\n", _section, _key);
		stop("Unable to get value from item in config file");
	}

	return ret;
}

char** db_config_get_keys(db_config_t* _config, const char* _section, int* _size)
{
	int error = 0;
	char** ret = NULL;

	ret = get_attribute_list(_config, _section, _size, &error);
	if (unlikely(error))
	{
		inform("Section: %s\n", _section);
		stop("Unable to enumerate keys in section of config file");
	}

	return ret;
}

void db_config_free_keys(char** _keys)
{
	free_attribute_list(_keys);

	return;
}

