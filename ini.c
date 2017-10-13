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

#include "pfcq.h"

#include "ini.h"

ds_cfg_t* ds_cfg_open(const char* _app_name, const char* _filepath)
{
	ds_cfg_t* ret = NULL;

	if (unlikely(config_from_file(_app_name, _filepath, &ret, INI_STOP_ON_ANY, NULL)))
		stop("Unable to load config file");

	return ret;
}

void ds_cfg_close(ds_cfg_t* _config)
{
	free_ini_config(_config);

	return;
}

static ds_cfg_t* __ds_cfg_get_item(ds_cfg_t* _config, const char* _section, const char* _key)
{
	ds_cfg_t* ret = NULL;

	if (unlikely(get_config_item(_section, _key, _config, &ret)))
	{
		inform("Section: %s, key: %s\n", _section, _key);
		stop("Unable to get item from config file");
	}

	return ret;
}

uint64_t ds_cfg_get_u64(ds_cfg_t* _config, const char* _section, const char* _key, uint64_t _default)
{
	int error = 0;
	uint64_t ret = 0;

	ret = get_uint64_config_value(__ds_cfg_get_item(_config, _section, _key), 1, _default, &error);
	if (unlikely(error))
	{
		inform("Section: %s, key: %s\n", _section, _key);
		stop("Unable to get value from item in config file");
	}

	return ret;
}

int ds_cfg_get_int(ds_cfg_t* _config, const char* _section, const char* _key, int _default)
{
	int error = 0;
	int ret = 0;

	ret = get_int_config_value(__ds_cfg_get_item(_config, _section, _key), 1, _default, &error);
	if (unlikely(error))
	{
		inform("Section: %s, key: %s\n", _section, _key);
		stop("Unable to get value from item in config file");
	}

	return ret;
}

unsigned ds_cfg_get_uint(ds_cfg_t* _config, const char* _section, const char* _key, unsigned _default)
{
	int error = 0;
	unsigned ret = 0;

	ret = get_unsigned_config_value(__ds_cfg_get_item(_config, _section, _key), 1, _default, &error);
	if (unlikely(error))
	{
		inform("Section: %s, key: %s\n", _section, _key);
		stop("Unable to get value from item in config file");
	}

	return ret;
}

const char* ds_cfg_get_cstr(ds_cfg_t* _config, const char* _section, const char* _key)
{
	const char* ret = NULL;

	ret = ds_cfg_try_get_cstr(_config, _section, _key);
	if (unlikely(!ret))
	{
		inform("Section: %s, key: %s\n", _section, _key);
		stop("Unable to get value from item in config file");
	}

	return ret;
}

const char* ds_cfg_try_get_cstr(ds_cfg_t* _config, const char* _section, const char* _key)
{
	int error = 0;
	const char* ret = NULL;

	ret = get_const_string_config_value(__ds_cfg_get_item(_config, _section, _key), &error);
	if (unlikely(error))
		ret = NULL;

	return ret;
}

char** ds_cfg_get_keys(ds_cfg_t* _config, const char* _section, int* _size)
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

void ds_cfg_free_keys(char** _keys)
{
	free_attribute_list(_keys);

	return;
}

char** ds_cfg_get_sections(ds_cfg_t* _config, int* _size)
{
	int error = 0;
	char** ret = NULL;

	ret = get_section_list(_config, _size, &error);
	if (unlikely(error))
	{
		stop("Unable to enumerate sections in config file");
	}

	return ret;
}

void ds_cfg_free_sections(char** _sections)
{
	free_section_list(_sections);
}

