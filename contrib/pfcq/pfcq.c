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

#include <ctype.h>
#include <dirent.h>
#include <fnmatch.h>

#define UNW_LOCAL_ONLY
#include <libunwind.h>

#include <limits.h>
#include <pthread.h>
#include <regex.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "pfcq.h"

#define STACKITEM_NAME_SIZE		256
#define STACKITEM_PREFIX_SYSLOG	"%ju) %s+%lx: ip = %lx, sp = %lx\n"
#define STACKITEM_PREFIX_STDERR	"\t"STACKITEM_PREFIX_SYSLOG
#define WARNING_SUFFIX_SYSLOG	"Warning #%d"
#define WARNING_SUFFIX_STDERR	WARNING_SUFFIX_SYSLOG", "

static pfcq_size_unit_t pfcq_units[] =
{
	{0ULL,				"B"},
	{1000ULL,			"kB"},
	{1000000ULL,		"MB"},
	{1000000000ULL,		"GB"},
	{1000000000000ULL,	"TB"},
	{1024ULL,			"KiB"},
	{1048576ULL,		"MiB"},
	{1073741824ULL,		"GiB"},
	{1099511627776ULL,	"TiB"},
	{0, 0},
};

static int pfcq_be_verbose;
static int pfcq_do_debug;
static int pfcq_warnings_count;
static int pfcq_use_syslog;
static pthread_mutex_t pfcq_warning_ordering_lock;

void __pfcq_debug(int _direct, const char* _format, ...)
{
	va_list arguments;

	va_start(arguments, _format);
	if (_direct || pfcq_be_verbose || pfcq_do_debug)
	{
		if (pfcq_use_syslog)
			vsyslog(LOG_DEBUG, _format, arguments);
		else
			vfprintf(stderr, _format, arguments);
	}
	va_end(arguments);

	return;
}

static void show_stacktrace(void)
{
	unw_cursor_t cursor;
	unw_context_t uc;
	unw_word_t ip = 0;
	unw_word_t sp = 0;
	unw_word_t offp = 0;
	size_t index = 0;
	char name[STACKITEM_NAME_SIZE];

	pfcq_zero(&cursor, sizeof(unw_cursor_t));
	pfcq_zero(&uc, sizeof(unw_context_t));
	pfcq_zero(name, STACKITEM_NAME_SIZE);

	unw_getcontext(&uc);
	unw_init_local(&cursor, &uc);

	__pfcq_debug(1, "Stacktrace:\n");
	while (unw_step(&cursor) > 0)
	{
		unw_get_proc_name(&cursor, name, STACKITEM_NAME_SIZE, &offp);
		unw_get_reg(&cursor, UNW_REG_IP, &ip);
		unw_get_reg(&cursor, UNW_REG_SP, &sp);
		__pfcq_debug(1, pfcq_use_syslog ? STACKITEM_PREFIX_SYSLOG : STACKITEM_PREFIX_STDERR,
			++index, name, (long)offp, (long)ip, (long)sp);
	}

	return;
}

void __pfcq_warning(const char* _message, const int _errno, const char* _file, int _line, int _direct)
{
	if (unlikely(pthread_mutex_lock(&pfcq_warning_ordering_lock)))
		exit(EX_SOFTWARE);
	if (likely(_direct))
	{
		pfcq_warnings_count++;
		__pfcq_debug(1, pfcq_use_syslog ? WARNING_SUFFIX_SYSLOG : WARNING_SUFFIX_STDERR, pfcq_warnings_count);
	}
	__pfcq_debug(1, "File=%s, line=%d\n", _file, _line);
	__pfcq_debug(1, "%s: %s\n", _message, strerror(_errno));
	show_stacktrace();
	if (unlikely(pthread_mutex_unlock(&pfcq_warning_ordering_lock)))
		exit(EX_SOFTWARE);

	return;
}

void __pfcq_fail(const char* _message, const int _errno)
{
	__pfcq_debug(1, "%s: %s\n", _message, strerror(_errno));

	return;
}

void __pfcq_stop(const char* _message)
{
	__pfcq_debug(1, "%s\n", _message);
	exit(EX_SOFTWARE);
}

void __pfcq_panic(const char* _message, const int _errno, const char* _file, int _line)
{
	__pfcq_warning(_message, _errno, _file, _line, 0);
	exit(EX_SOFTWARE);
}

void pfcq_debug_init(int _verbose, int _debug, int _syslog)
{
	pfcq_be_verbose = _verbose;
	pfcq_do_debug = _debug;
	pfcq_use_syslog = _syslog;
	pfcq_warnings_count = 0;
	if (unlikely(pthread_mutex_init(&pfcq_warning_ordering_lock, NULL)))
		panic("pthread_mutex_init");
	if (pfcq_use_syslog)
		openlog(NULL, LOG_PID, LOG_DAEMON);

	return;
}

void pfcq_debug_done(void)
{
	if (unlikely(pthread_mutex_destroy(&pfcq_warning_ordering_lock)))
		panic("pthread_mutex_init");
	if (pfcq_use_syslog)
		closelog();

	return;
}

void* pfcq_alloc(size_t _size)
{
	void* res = NULL;

	_size += sizeof(size_t);
	res = calloc(1, _size);
	if (unlikely(!res))
		panic("calloc");
	*(size_t*)res = _size;

	return ((size_t*)res) + 1;
}

void* pfcq_realloc(void* _old_pointer, size_t _new_size)
{
	void* tmp = NULL;

	_new_size += sizeof(size_t);
	_old_pointer = (void*)(((size_t*)_old_pointer) - 1);
	if (unlikely(!_old_pointer))
		panic("NULL pointer detected");

	tmp = realloc(_old_pointer, _new_size);
	if (unlikely(!tmp))
		panic("realloc");
	*(size_t*)tmp = _new_size;

	return ((size_t*)tmp) + 1;
}

void __pfcq_free(void** _pointer)
{
	void* p = *_pointer;

	if (likely(p))
	{
		size_t* s = (size_t*)p - 1;
		if (likely(s))
		{
			size_t size = *s;
			pfcq_zero(s, size);
			free(s);
			*_pointer = NULL;
		} else
			warning("Incorrect pointer given to pfcq_free()");
	} else
		warning("NULL pointer given to pfcq_free()");
}

int pfcq_isnumber(const char* _string)
{
	while (likely(*_string))
	{
		char current_char = *_string++;
		if (unlikely(isdigit(current_char) == 0))
			return 0;
	}

	return 1;
}

char* pfcq_mstring(const char* _format, ...)
{
	va_list arguments;
	char* ret = NULL;

	va_start(arguments, _format);
	int length = vsnprintf(NULL, 0, _format, arguments);
	va_end(arguments);

	if (unlikely(length < 0))
		return ret;

	ret = pfcq_alloc(length + 1);

	va_start(arguments, _format);
	vsprintf(ret, _format, arguments);
	va_end(arguments);

	return ret;
}

char* pfcq_strdup(const char* _string)
{
	return pfcq_mstring("%s", _string);
}

char* pfcq_cstring(char* _left, const char* _right)
{
	size_t left_length = strlen(_left);
	size_t right_length = strlen(_right);

	char* ret = pfcq_realloc(_left, left_length + right_length + 1);
	memcpy(ret + left_length, _right, right_length);
	ret[left_length + right_length] = '\0';

	return ret;
}

char* pfcq_bstring(const char* _buffer, size_t _buffer_size)
{
	char* ret = NULL;

	ret = pfcq_alloc(_buffer_size + 1);
	memcpy(ret, _buffer, _buffer_size);
	ret[_buffer_size] = '\0';

	return ret;
}

uint64_t pfcq_mbytes(const char* _human_readable)
{
	char* expression = pfcq_strdup("^([0-9]+)(");
	char* value = NULL;
	char* units = NULL;
	regex_t regex;
	regmatch_t matches[3];
	uint64_t ret = 0;

	pfcq_zero(&regex, sizeof(regex_t));
	pfcq_zero(matches, 3 * sizeof(regmatch_t));

	for (unsigned int i = 0; ; i++)
	{
		if (unlikely(pfcq_units[i].unit == 0))
			break;

		expression = pfcq_cstring(expression, pfcq_units[i].unit);
		expression = pfcq_cstring(expression, "|");
	}

	expression = pfcq_cstring(expression, ")$");

	if (unlikely(regcomp(&regex, expression, REG_EXTENDED)))
		return ret;

	if (unlikely(regexec(&regex, _human_readable, 3, matches, 0)))
		return ret;

	regfree(&regex);

	value = pfcq_alloc(matches[1].rm_eo - matches[1].rm_so + 1);
	units = pfcq_alloc(matches[2].rm_eo - matches[2].rm_so + 1);

	memcpy(value, &_human_readable[matches[1].rm_so], matches[1].rm_eo - matches[1].rm_so);
	memcpy(units, &_human_readable[matches[2].rm_so], matches[2].rm_eo - matches[2].rm_so);

	ret = strtoll(value, NULL, 10);
	for (unsigned int i = 0; ; i++)
	{
		if (unlikely(pfcq_units[i].unit == 0))
			break;
		if (strcmp(units, pfcq_units[i].unit) == 0)
		{
			ret *= pfcq_units[i].base;
			break;
		}
	}

	pfcq_free(value);
	pfcq_free(units);
	pfcq_free(expression);

	return ret;
}

unsigned short int pfcq_hint_cpus(int _hint)
{
	unsigned short int ret = 0;
	int res = 0;

	if (_hint < 1)
	{
		res = sysconf(_SC_NPROCESSORS_ONLN);
		if (unlikely(res == -1))
			ret = 1;
		else
			ret = (unsigned short int)res;
	} else
		ret = (unsigned short int)_hint;

	return ret;
}

static int pfcq_procfdfilter(const struct dirent* _dir)
{
	return !fnmatch("[0-9]*", _dir->d_name, 0);
}

static void pfcq_free_dirent_list(struct dirent*** _dirents, size_t _amount)
{
	for (size_t i = 0; i < _amount; i++)
		free((*_dirents)[i]);
	free(*_dirents);
}

int pfcq_isopened(const char* _path)
{
	int ret = 0;
	int n = -1;
	int k = -1;
	char proc_path[PATH_MAX];
	char fd_path[PATH_MAX];
	char resolved_path[PATH_MAX];
	struct dirent** names;
	struct dirent** fds;

	n = scandir("/proc", &names, pfcq_procfdfilter, 0);
	if (unlikely(n == -1))
	{
		warning("scandir");
		goto out;
	}

	for (int i = 0; i < n; i++)
	{
		pfcq_zero(proc_path, PATH_MAX);
		if (unlikely(snprintf(proc_path, PATH_MAX, "/proc/%s/fd", names[i]->d_name) < 0))
		{
			warning("snprintf");
			continue;
		}
		k = scandir(proc_path, &fds, pfcq_procfdfilter, 0);
		if (unlikely(k == -1))
			continue;
		for (int j = 0; j < k; j++)
		{
			pfcq_zero(fd_path, PATH_MAX);
			pfcq_zero(resolved_path, PATH_MAX);
			if (unlikely(snprintf(fd_path, PATH_MAX, "%s/%s", proc_path, fds[j]->d_name) < 0))
			{
				warning("snprintf");
				continue;
			}
			if (unlikely(readlink(fd_path, resolved_path, PATH_MAX) == -1))
				continue;
			if (unlikely(strncmp(_path, resolved_path, PATH_MAX) == 0))
			{
				pfcq_free_dirent_list(&fds, k);
				ret = 1;
				goto lfree;
			}
		}
		pfcq_free_dirent_list(&fds, k);
	}

lfree:
	pfcq_free_dirent_list(&names, n);

out:
	return ret;
}

char* pfcq_get_file_path_from_fd(int _fd, char* _buffer, size_t _buffer_size)
{
	ssize_t len = 0;

	if (unlikely(_fd <= 0))
		return NULL;

	if (unlikely(snprintf(_buffer, _buffer_size, "/proc/self/fd/%d", _fd) < 0))
		panic("snprintf");
	if (unlikely((len = readlink(_buffer, _buffer, _buffer_size - 1)) < 0))
		return NULL;

	_buffer[len] = '\0';

	return _buffer;
}

void pfcq_fprng_init(pfcq_fprng_context_t* _context)
{
	struct timespec current_time;

	if (unlikely(clock_gettime(CLOCK_REALTIME, &current_time) == -1))
		panic("clock_gettime");

	_context->seed = __pfcq_timespec_to_ns(current_time);
	srandom(_context->seed);
	for (size_t i = 0; i < sizeof(uint64_t) * CHAR_BIT; i++)
	{
		uint8_t shift = ((uint64_t)random()) % (sizeof(uint64_t) * CHAR_BIT);
		int long pattern = random();
		_context->seed ^= (pattern << shift);
	}

	return;
}

uint64_t pfcq_fprng_get_u64(pfcq_fprng_context_t* _context)
{
	_context->seed ^= (_context->seed << 21);
	_context->seed ^= (_context->seed >> 35);
	_context->seed ^= (_context->seed << 4);

	return _context->seed;
}

