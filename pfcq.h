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

#pragma once

#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "sys.h"

#define __noop					(void)0

#define inform(A, ...)			__pfcq_debug(1, A, __VA_ARGS__)
#define verbose(A, ...)			__pfcq_debug(0, A, __VA_ARGS__)

#ifdef MODE_DEBUG
#define debug(A, ...)			__pfcq_debug(0, A, __VA_ARGS__)
#else /* MODE_DEBUG */
#define debug(A, ...)			__noop
#endif /* MODE_DEBUG */

#define warning(A)				__pfcq_warning(A, errno, __FILE__, __LINE__, 1)
#define fail(A)					__pfcq_fail(A, errno)
#define stop(A)					__pfcq_stop(EX_SOFTWARE, A)
#define panic(A)				__pfcq_panic(A, errno, __FILE__, __LINE__)

#define pfcq_zero(A, B)			pfcq_memset_g(A, 0, B)
#define pfcq_free(A)			__pfcq_free((void**)&(A))

#ifdef __GNUC__
#define likely(x)				__builtin_expect(!!(x), 1)
#define unlikely(x)				__builtin_expect(!!(x), 0)
#else /* __GNUC__ */
#define likely(x)				(x)
#define unlikely(x)				(x)
#endif /* __GNUC__ */

// Convention: B *MUST* be string literal,
// otherwise compiler will throw an error
#define pfcq_strlcmp(A, B)		__pfcq_strlcmp(A, "" B)

// Under 23.5k+ QPS max 6 events are returned per worker;
// doubling it just in case
#define EPOLL_MAXEVENTS			12

struct pfcq_net_addr
{
	sa_family_t family;
	union addr
	{
		struct sockaddr_in ip4;
		struct sockaddr_in6 ip6;
	} addr;
};

struct pfcq_counter
{
#ifdef DS_HAVE_ATOMICS
	atomic_size_t val;
#else /* DS_HAVE_ATOMICS */
	AO_t val;
#endif /* DS_HAVE_ATOMICS */
};

void __pfcq_debug(int _direct, const char* _format, ...) __attribute__((format(printf, 2, 3)));
void __pfcq_warning(const char* _message, const int _errno, const char* _file, int _line, int _direct);
void __pfcq_fail(const char* _message, const int _errno);
void __pfcq_stop(const int _exit_code, const char* _message) __attribute__((noreturn));
void __pfcq_panic(const char* _message, const int _errno, const char* _file, int _line);
void pfcq_debug_init(int _verbose, int _debug, int _syslog);
void pfcq_debug_done(void);

void pfcq_memset_g(void* _data, int _byte, size_t _size);

#ifdef __clang__
void* pfcq_alloc(size_t _size) __attribute__((malloc, warn_unused_result));
void* pfcq_realloc(void* _old_pointer, size_t _new_size) __attribute__((malloc, warn_unused_result));
#else /* __clang__ */
void* pfcq_alloc(size_t _size) __attribute__((malloc, alloc_size(1), warn_unused_result));
void* pfcq_realloc(void* _old_pointer, size_t _new_size) __attribute__((malloc, alloc_size(2), warn_unused_result));
#endif /* __clang__ */
void __pfcq_free(void** _pointer);

int pfcq_isnumber(const char* _string) __attribute__((warn_unused_result));
int __pfcq_strlcmp(const char* _s1, const char* _s2) __attribute__((warn_unused_result));
char* pfcq_strdup(const char* _string) __attribute__((warn_unused_result));
char* pfcq_mstring(const char* _format, ...) __attribute__((format(printf, 1, 2), warn_unused_result));
char* pfcq_cstring(char* _left, const char* _right) __attribute__((warn_unused_result));
char* pfcq_bstring(const char* _buffer, size_t _buffer_size) __attribute__((warn_unused_result));
char** pfcq_split_string(const char* _string, const char* _delimiter, size_t* _size) __attribute__((warn_unused_result));
void pfcq_free_split_string(char** _parts, size_t _nparts);
unsigned long int pfcq_strtoul(const char* _nptr, int _base) __attribute__((warn_unused_result));

unsigned short int pfcq_hint_cpus(int _hint) __attribute__((warn_unused_result));

int64_t pfcq_timespec_diff_ns(struct timespec _timestamp1, struct timespec _timestamp2) __attribute__((warn_unused_result));
struct timeval pfcq_us_to_timeval(uint64_t _us) __attribute__((warn_unused_result));
void pfcq_sleep(uint64_t _us);
struct timespec pfcq_ns_to_timespec(uint64_t _ns) __attribute__((warn_unused_result));

void pfcq_spin_init(pthread_spinlock_t* _lock);
void pfcq_spin_lock(pthread_spinlock_t* _lock);
void pfcq_spin_unlock(pthread_spinlock_t* _lock);
void pfcq_spin_done(pthread_spinlock_t* _lock);

uint64_t pfcq_fast_hash(const uint8_t* _data, size_t _data_size, uint64_t _seed) __attribute__((warn_unused_result));

bool pfcq_net_addr_cmp(struct pfcq_net_addr* _na1, struct pfcq_net_addr* _na2) __attribute__((warn_unused_result));

void pfcq_counter_init(struct pfcq_counter* _counter);
void pfcq_counter_reset(struct pfcq_counter* _counter);
void pfcq_counter_inc(struct pfcq_counter* _counter);
void pfcq_counter_dec(struct pfcq_counter* _counter);
size_t pfcq_counter_get(struct pfcq_counter* _counter) __attribute__((warn_unused_result));
size_t pfcq_counter_get_inc_mod(struct pfcq_counter* _counter, size_t _mod, size_t _min) __attribute__((warn_unused_result));
bool pfcq_counter_reset_if_gt(struct pfcq_counter* _counter, size_t _max) __attribute__((warn_unused_result));
void pfcq_counter_set(struct pfcq_counter* _counter, size_t _val);

