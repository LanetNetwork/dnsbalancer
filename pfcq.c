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

#include <ctype.h>

#define UNW_LOCAL_ONLY
#include <libunwind.h>

#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
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

static int pfcq_be_verbose;
static int pfcq_do_debug;
static int pfcq_warnings_count;
static int pfcq_use_syslog;
static pthread_spinlock_t pfcq_warning_ordering_lock;

static inline uint64_t __pfcq_timespec_to_ns(struct timespec _timestamp) __attribute__((always_inline));

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
	pfcq_spin_lock(&pfcq_warning_ordering_lock);
	if (likely(_direct))
	{
		pfcq_warnings_count++;
		__pfcq_debug(1, pfcq_use_syslog ? WARNING_SUFFIX_SYSLOG : WARNING_SUFFIX_STDERR, pfcq_warnings_count);
	}
	__pfcq_debug(1, "File=%s, line=%d\n", _file, _line);
	__pfcq_debug(1, "%s: %s\n", _message, strerror(_errno));
	show_stacktrace();
	pfcq_spin_unlock(&pfcq_warning_ordering_lock);

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
	pfcq_spin_init(&pfcq_warning_ordering_lock);
	if (pfcq_use_syslog)
		openlog(NULL, LOG_PID, LOG_DAEMON);

	return;
}

void pfcq_debug_done(void)
{
	pfcq_spin_done(&pfcq_warning_ordering_lock);
	if (pfcq_use_syslog)
		closelog();

	return;
}

void pfcq_memset_g(void* _data, int _byte, size_t _size)
{
	volatile unsigned char* data = _data;

	while (_size--)
	{
		*data++ = (unsigned char)_byte;
	}

	return;
}

void* pfcq_alloc(size_t _size)
{
	void* ret = NULL;

	if (unlikely(_size == 0))
		panic("_size");

	ret = calloc(1, _size);
	if (unlikely(!ret))
		panic("calloc");

	return ret;
}

void* pfcq_realloc(void* _old_pointer, size_t _new_size)
{
	void* ret = NULL;

	if (unlikely(!_old_pointer))
		panic("_old_pointer");

	if (unlikely(_new_size == 0))
		panic("new_size");

	ret = realloc(_old_pointer, _new_size);
	if (unlikely(!ret))
		panic("realloc");

	return ret;
}

void __pfcq_free(void** _pointer)
{
	void* p = NULL;

	if (unlikely(!_pointer))
		panic("_pointer");

	p = *_pointer;
	if (unlikely(!p))
		panic("p");

	free(p);
	*_pointer = NULL;

	return;
}

int __pfcq_strlcmp(const char* _s1, const char* _s2)
{
	return strncmp(_s1, _s2, strlen(_s2));
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

char** pfcq_split_string(const char* _string, const char* _delimiter, size_t* _size)
{
	char* iter = pfcq_strdup(_string);
	char* iter_p = iter;
	char* part = NULL;
	char** ret = NULL;
	size_t nparts = 0;

	while (likely(part = strsep(&iter, _delimiter)))
	{
		if (unlikely(!ret))
			ret = pfcq_alloc(sizeof(char*));
		else
			ret = pfcq_realloc(ret, (nparts + 1) * sizeof(char*));

		ret[nparts] = pfcq_strdup(part);

		nparts++;
	}

	pfcq_free(iter_p);

	*_size = nparts;

	return ret;
}

void pfcq_free_split_string(char** _parts, size_t _nparts)
{
	for (size_t i = 0; i < _nparts; i++)
		pfcq_free(_parts[i]);
	pfcq_free(_parts);

	return;
}

unsigned long int pfcq_strtoul(const char* _nptr, int _base)
{
	char* endptr = NULL;
	unsigned long int ret = 0;

	ret = strtoul(_nptr, &endptr, _base);
	if (unlikely(*endptr != '\0' || (ret == ULONG_MAX && errno == ERANGE)))
		panic("strtoul");

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

int64_t pfcq_timespec_diff_ns(struct timespec _timestamp1, struct timespec _timestamp2)
{
	uint64_t ns1 = __pfcq_timespec_to_ns(_timestamp1);
	uint64_t ns2 = __pfcq_timespec_to_ns(_timestamp2);
	return ns2 - ns1;
}

struct timeval pfcq_us_to_timeval(uint64_t _us)
{
	struct timeval ret;

	ret.tv_sec = _us / 1000000ULL;
	ret.tv_usec = _us - ret.tv_sec * 1000000ULL;

	return ret;
}

void pfcq_sleep(uint64_t _ns)
{
	struct timespec time_to_sleep = pfcq_ns_to_timespec(_ns);

	while (likely(nanosleep(&time_to_sleep, &time_to_sleep) == -1 && errno == EINTR))
		continue;
}

struct timespec pfcq_ns_to_timespec(uint64_t _ns)
{
	struct timespec ret;

	ret.tv_sec = _ns / 1000000000ULL;
	ret.tv_nsec = _ns - ret.tv_sec * 1000000000ULL;

	return ret;
}

void pfcq_spin_init(pthread_spinlock_t* _lock)
{
	if (unlikely(pthread_spin_init(_lock, PTHREAD_PROCESS_PRIVATE) != 0))
		panic("pthread_spin_init");
}

void pfcq_spin_lock(pthread_spinlock_t* _lock)
{
	if (unlikely(pthread_spin_lock(_lock) != 0))
		panic("pthread_spin_lock");
}

void pfcq_spin_unlock(pthread_spinlock_t* _lock)
{
	if (unlikely(pthread_spin_unlock(_lock) != 0))
		panic("pthread_spin_unlock");
}

void pfcq_spin_done(pthread_spinlock_t* _lock)
{
	if (unlikely(pthread_spin_destroy(_lock) != 0))
		panic("pthread_spin_destroy");
}

uint64_t pfcq_fast_hash(const uint8_t* _data, size_t _data_size, uint64_t _seed)
{
	uint64_t ret = 0xcbf29ce484222325;

	for (size_t i = 0; i < _data_size; i++)
	{
		ret ^= _data[i];
		ret *= 0x100000001b3;
	}

	return ret ^ _seed;
}

static inline uint64_t __pfcq_timespec_to_ns(struct timespec _timestamp)
{
	return _timestamp.tv_sec * 1000000000ULL + _timestamp.tv_nsec;
}

bool pfcq_net_addr_cmp(struct pfcq_net_addr* _na1, struct pfcq_net_addr* _na2)
{
	if (_na1->family == _na2->family)
	{
		switch (_na1->family)
		{
			case AF_INET:
				return _na1->addr.ip4.sin_addr.s_addr == _na2->addr.ip4.sin_addr.s_addr;
				break;
			case AF_INET6:
				return _na1->addr.ip6.sin6_addr.s6_addr == _na2->addr.ip6.sin6_addr.s6_addr;
				break;
			default:
				panic("Unknown address family");
				break;
		}
	} else
		return false;
}

bool pfcq_net_addr_port_cmp(struct pfcq_net_addr* _na1, struct pfcq_net_addr* _na2)
{
	if (_na1->family == _na2->family)
	{
		switch (_na1->family)
		{
			case AF_INET:
				return ((_na1->addr.ip4.sin_addr.s_addr == _na2->addr.ip4.sin_addr.s_addr) &&
						(_na1->addr.ip4.sin_port == _na2->addr.ip4.sin_port));
				break;
			case AF_INET6:
				return ((_na1->addr.ip6.sin6_addr.s6_addr == _na2->addr.ip6.sin6_addr.s6_addr) &&
						(_na1->addr.ip6.sin6_port == _na2->addr.ip6.sin6_port));
				break;
			default:
				panic("Unknown address family");
				break;
		}
	} else
		return false;
}

void pfcq_counter_init(struct pfcq_counter* _counter)
{
#ifdef DS_HAVE_ATOMICS
	_counter->val = ATOMIC_VAR_INIT(0);
#else /* DS_HAVE_ATOMICS */
	pfcq_counter_reset(_counter);
#endif /* DS_HAVE_ATOMICS */
}

void pfcq_counter_reset(struct pfcq_counter* _counter)
{
	pfcq_counter_set(_counter, 0);
}

void pfcq_counter_inc(struct pfcq_counter* _counter)
{
#ifdef DS_HAVE_ATOMICS
	_counter->val++;
#else /* DS_HAVE_ATOMICS */
	AO_fetch_and_add1(&_counter->val);
#endif /* DS_HAVE_ATOMICS */
}

void pfcq_counter_dec(struct pfcq_counter* _counter)
{
#ifdef DS_HAVE_ATOMICS
	_counter->val--;
#else /* DS_HAVE_ATOMICS */
	AO_fetch_and_sub1(&_counter->val);
#endif /* DS_HAVE_ATOMICS */
}

size_t pfcq_counter_get(struct pfcq_counter* _counter)
{
#ifdef DS_HAVE_ATOMICS
	return _counter->val;
#else /* DS_HAVE_ATOMICS */
	return AO_load(&_counter->val);
#endif /* DS_HAVE_ATOMICS */
}

size_t pfcq_counter_get_inc_mod(struct pfcq_counter* _counter, size_t _mod, size_t _min)
{
#ifdef DS_HAVE_ATOMICS
	size_t orig_val = 0;
	atomic_size_t next_val = 0;
#else /* DS_HAVE_ATOMICS */
	AO_t orig_val = 0;
	AO_t next_val = 0;
#endif

	while (true)
	{
		orig_val = pfcq_counter_get(_counter);

		next_val = (orig_val + 1) % _mod;
		if (next_val < _min)
			next_val = _min;

#ifdef DS_HAVE_ATOMICS
		if (likely(atomic_compare_exchange_weak(&_counter->val, &orig_val, next_val)))
#else /* DS_HAVE_ATOMICS */
		if (likely(AO_compare_and_swap(&_counter->val, orig_val, next_val)))
#endif
			break;
	}

	return orig_val;
}

bool pfcq_counter_reset_if_gt(struct pfcq_counter* _counter, size_t _max)
{
#ifdef DS_HAVE_ATOMICS
	size_t orig_val = 0;
	atomic_size_t zero_val = 0;
#else /* DS_HAVE_ATOMICS */
	AO_t orig_val = 0;
	AO_t zero_val = 0;
#endif

	while (true)
	{
		orig_val = pfcq_counter_get(_counter);
		if (orig_val > _max)
		{

#ifdef DS_HAVE_ATOMICS
			if (likely(atomic_compare_exchange_weak(&_counter->val, &orig_val, zero_val)))
#else /* DS_HAVE_ATOMICS */
			if (likely(AO_compare_and_swap(&_counter->val, orig_val, zero_val)))
#endif
				return true;
			else
				continue;
		} else
			return false;
	}
}

void pfcq_counter_set(struct pfcq_counter* _counter, size_t _val)
{
#ifdef DS_HAVE_ATOMICS
	_counter->val = _val;
#else /* DS_HAVE_ATOMICS */
	AO_store(&_counter->val, (AO_t)_val);
#endif /* DS_HAVE_ATOMICS */
}

