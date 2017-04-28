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

#include <errno.h>
#include <netinet/in.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include "pfcq.h"
#include "rb.h"

#include "utils.h"

struct libavl_allocator ds_rb_allocator =
{
	ds_rb_malloc,
	ds_rb_free,
};

void* ds_rb_malloc(struct libavl_allocator* _allocator, size_t _libavl_size)
{
	if (unlikely(!_allocator))
		panic("_allocator");

	if (unlikely(_libavl_size == 0))
		panic("_libavl_size");

	return pfcq_alloc(_libavl_size);
}

void ds_rb_free(struct libavl_allocator* _allocator, void* _libavl_block)
{
	if (unlikely(!_allocator))
		panic("_allocator");

	if (unlikely(!_libavl_block))
		panic("_allocator");

	pfcq_free(_libavl_block);
}

void ds_rb_item_free(void* _rb_item, void* _rb_param)
{
	(void)_rb_param;

	pfcq_free(_rb_item);

	return;
}

void ds_tsk_free(struct ds_wrk_tsk* _tsk)
{
	pfcq_free(_tsk->buf);
	pfcq_free(_tsk);

	return;
}

void ds_rb_tsk_free(void* _rb_item, void* _rb_param)
{
	(void)_rb_param;

	struct ds_wrk_tsk* tsk = _rb_item;

	ds_tsk_free(tsk);

	return;
}

int ds_fe_sk_cmp(const void* _p1, const void* _p2, void* _param)
{
	(void)_param;

	const struct ds_fe_sk* s1 = _p1;
	const struct ds_fe_sk* s2 = _p2;

	return ds_int_cmp(s1->sk, s2->sk);
}

int ds_fwd_sk_cmp(const void* _p1, const void* _p2, void* _param)
{
	(void)_param;

	const struct ds_fwd_sk* s1 = _p1;
	const struct ds_fwd_sk* s2 = _p2;

	return ds_int_cmp(s1->sk, s2->sk);
}

int ds_tsk_cmp(const void* _p1, const void* _p2, void* _param)
{
	(void)_param;

	const struct ds_wrk_tsk* t1 = _p1;
	const struct ds_wrk_tsk* t2 = _p2;

	int _s0 = ds_int_cmp(t1->subst_id, t2->subst_id);
	if (_s0 == 0)
	{
		int _s1 = strncmp(t1->fqdn, t2->fqdn, HOST_NAME_MAX);
		if (_s1 == 0)
		{
			int _s2 = ds_int_cmp(t1->rr_type, t2->rr_type);
			if (_s2 == 0)
			{
				int _s3 = ds_int_cmp(t1->rr_class, t2->rr_class);
				if (_s3 == 0)
				{
					return ds_ptr_cmp(t1->fwd_sk->fwd, t2->fwd_sk->fwd);
				} else
					return _s3;
			} else
				return _s2;
		} else
			return _s1;
	} else
		return _s0;
}

void ds_epoll_add_fd(int _evfd, int _fd, uint32_t _events)
{
	struct epoll_event event;

	pfcq_zero(&event, sizeof(struct epoll_event));

	event.data.fd = _fd;
	event.events = _events;
	if (unlikely(epoll_ctl(_evfd, EPOLL_CTL_ADD, _fd, &event) == -1))
		panic("epoll_ctl");
}

void ds_epoll_del_fd(int _evfd, int _fd)
{
	if (unlikely(epoll_ctl(_evfd, EPOLL_CTL_DEL, _fd, NULL) == -1))
		panic("epoll_ctl");
}

void ds_produce_u64_val(int _fd, uint64_t _value)
{
	__attribute__((unused)) int res = 0;

	res = ds_write(_fd, &_value, sizeof(uint64_t));

	return;
}

void ds_produce_u64(int _fd)
{
	ds_produce_u64_val(_fd, 1);

	return;
}

void ds_consume_u64(int _fd)
{
	uint64_t value = 0;
	__attribute__((unused)) int res = 0;

	res = ds_read(_fd, &value, sizeof(uint64_t));

	return;
}

int ds_try_consume_u64(int _fd)
{
	uint64_t value = 0;
	int ret = 0;

	ret = ds_read(_fd, &value, sizeof(uint64_t));

	return ret;
}

int ds_int_cmp(int _i1, int _i2)
{
	if (_i1 > _i2)
		return 1;

	if (_i1 < _i2)
		return -1;

	return 0;
}

int ds_ptr_cmp(void* _p1, void* _p2)
{
	if (_p1 > _p2)
		return 1;

	if (_p1 < _p2)
		return -1;

	return 0;
}

int ds_epoll_wait(int _epfd, struct epoll_event* _events,
				  int _maxevents, int _timeout)
{
	int ret = -1;

	do {
		ret = epoll_wait(_epfd, _events, _maxevents, _timeout);
	} while (unlikely(ret == -1 && errno == EINTR));

	return ret;
}

ssize_t ds_read(int _fd, void* _buf, size_t _count)
{
	ssize_t ret = -1;

	do {
		ret = read(_fd, _buf, _count);
	} while (unlikely(ret == -1 && errno == EINTR));

	return ret;
}

ssize_t ds_write(int _fd, const void* _buf, size_t _count)
{
	ssize_t ret = -1;

	do {
		ret = write(_fd, _buf, _count);
	} while (unlikely(ret == -1 && errno == EINTR));

	return ret;
}

ssize_t ds_recvfrom(int _socket, void* restrict _buffer, size_t _length,
					struct pfcq_net_addr* _address)
{
	ssize_t ret = -1;
	socklen_t addr_len = 0;

	do {
		switch (_address->family)
		{
			case AF_INET:
				addr_len = sizeof(struct sockaddr_in);
				ret = recvfrom(_socket, _buffer, _length, 0,
							   (struct sockaddr*)&_address->addr.ip4, &addr_len);
				break;
			case AF_INET6:
				addr_len = sizeof(struct sockaddr_in6);
				ret = recvfrom(_socket, _buffer, _length, 0, (struct sockaddr*)
							   &_address->addr.ip6, &addr_len);
				break;
			default:
				panic("Unknown address family");
				break;
		}
	} while (unlikely(ret == -1 && errno == EINTR));

	return ret;
}

ssize_t ds_sendto(int _socket, const void* _message, size_t _length,
				  const struct pfcq_net_addr* _dest_addr)
{
	ssize_t ret = -1;

	do {
		switch (_dest_addr->family)
		{
			case AF_INET:
				ret = sendto(_socket, _message, _length, 0,
							 (const struct sockaddr*)&_dest_addr->addr.ip4,
							 (socklen_t)sizeof(struct sockaddr_in));
				break;
			case AF_INET6:
				ret = sendto(_socket, _message, _length, 0,
							 (const struct sockaddr*)&_dest_addr->addr.ip6,
							 (socklen_t)sizeof(struct sockaddr_in6));
				break;
			default:
				panic("Unknown address family");
				break;
		}
	} while (unlikely(ret == -1 && errno == EINTR));

	return ret;
}

ssize_t ds_recv(int _sockfd, void* _buf, size_t _len)
{
	ssize_t ret = -1;

	do {
		ret = recv(_sockfd, _buf, _len, 0);
	} while (unlikely(ret == -1 && errno == EINTR));

	return ret;
}

ssize_t ds_send(int _sockfd, const void* _buf, size_t _len)
{
	ssize_t ret = -1;

	do {
		ret = send(_sockfd, _buf, _len, 0);
	} while (unlikely(ret == -1 && errno == EINTR));

	return ret;
}

int ds_eventfd(unsigned int _initval, int _flags)
{
	int ret = -1;

	ret = eventfd(_initval, _flags);
	if (unlikely(ret == -1))
		panic("eventfd");

	return ret;
}

int ds_epoll_create(void)
{
	int ret = -1;

	ret = epoll_create1(0);
	if (unlikely(ret == -1))
		panic("epoll_create1");

	return ret;
}

void ds_close(int _fd)
{
	if (unlikely(close(_fd) == -1))
		panic("close");

	return;
}

int ds_af_to_pf(sa_family_t _af)
{
	if (_af == AF_INET)
		return PF_INET;
	else if (_af == AF_INET6)
		return PF_INET6;
	else
		panic("Unknown address family");
}

int ds_socket(int _domain, int _type, int _protocol)
{
	int ret = -1;

	ret = socket(_domain, _type, _protocol);
	if (unlikely(ret == -1))
		panic("socket");

	return ret;
}

void ds_setsockopt(int _socket, int _level, int _option_name,
			   const void* _option_value, socklen_t _option_len)
{
	if (unlikely(setsockopt(_socket, _level, _option_name,
							_option_value, _option_len) == -1))
		panic("setsockopt");

	return;
}

void ds_bind(int _socket, const struct pfcq_net_addr* _address)
{
	switch (_address->family)
	{
		case AF_INET:
			if (unlikely(bind(_socket, &_address->addr.ip4, (socklen_t)sizeof(struct sockaddr_in)) == -1))
				panic("bind");
			break;
		case AF_INET6:
			if (unlikely(bind(_socket, &_address->addr.ip6, (socklen_t)sizeof(struct sockaddr_in6)) == -1))
				panic("bind");
			break;
		default:
			panic("Unknown address family");
			break;
	}

	return;
}

void ds_connect(int _socket, const struct pfcq_net_addr* _address)
{
	switch (_address->family)
	{
		case AF_INET:
			if (unlikely(connect(_socket, &_address->addr.ip4, (socklen_t)sizeof(struct sockaddr_in)) == -1))
				panic("connect");
			break;
		case AF_INET6:
			if (unlikely(connect(_socket, &_address->addr.ip6, (socklen_t)sizeof(struct sockaddr_in6)) == -1))
				panic("connect");
			break;
		default:
			panic("Unknown address family");
			break;
	}

	return;
}

void ds_inet_pton(const char* _src_addr, in_port_t _src_port, struct pfcq_net_addr* _dst)
{
	if (inet_pton(AF_INET, _src_addr, (void*)&_dst->addr.ip4.sin_addr) == 1)
	{
		_dst->family = AF_INET;
		_dst->addr.ip4.sin_family = _dst->family;
		_dst->addr.ip4.sin_port = htons(_src_port);
		return;
	}

	if (inet_pton(AF_INET6, _src_addr, (void*)&_dst->addr.ip6.sin6_addr) == 1)
	{
		_dst->family = AF_INET6;
		_dst->addr.ip6.sin6_family = _dst->family;
		_dst->addr.ip6.sin6_port = htons(_src_port);
		return;
	}

	panic("inet_pton");

	return;
}

void ds_inet_vlsmton(const struct pfcq_net_addr* _src, const char* _vlsm, struct pfcq_net_addr* _dst)
{
	unsigned long int vlsm = pfcq_strtoul(_vlsm, 10);

	switch (_src->family)
	{
		case AF_INET:
			_dst->addr.ip4.sin_addr.s_addr = htonl((~0UL) << (32 - vlsm));
			break;
		case AF_INET6:
			for (unsigned long int i = 0; i < vlsm; i++)
			{
				_dst->addr.ip6.sin6_addr.s6_addr[i / 8] |= (uint8_t)(1 << (i % 8));
			}
			break;
		default:
			panic("Unknown address family");
			break;
	}

	return;
}

uint64_t ds_hash_address(struct pfcq_net_addr* _address)
{
	switch (_address->family)
	{
		case AF_INET:
			return pfcq_fast_hash((uint8_t*)&_address->addr.ip4.sin_addr, sizeof(struct in_addr), 0);
			break;
		case AF_INET6:
			return pfcq_fast_hash((uint8_t*)&_address->addr.ip6.sin6_addr, sizeof(struct in6_addr), 0);
			break;
		default:
			panic("Unknown address family");
			break;
	}
}

void ds_set_sock_dscp(int _socket, int _domain, int _dscp)
{
	switch (_domain)
	{
		case PF_INET:
			ds_setsockopt(_socket, IPPROTO_IP, IP_TOS, &_dscp, sizeof(int));
			break;
		case PF_INET6:
			ds_setsockopt(_socket, IPPROTO_IPV6, IPV6_TCLASS, &_dscp, sizeof(int));
			break;
		default:
			panic("Unknown socket domain");
			break;
	}

	return;
}

int ds_timerfd_create(int _clockid, int _flags)
{
	int ret = -1;

	ret = timerfd_create(_clockid, _flags);
	if (unlikely(ret == -1))
		panic("timerfd_create");

	return ret;
}

void ds_timerfd_settime(int _fd, uint64_t _period)
{
	struct itimerspec ds_its;

	pfcq_zero(&ds_its, sizeof(struct itimerspec));

	ds_its.it_value = pfcq_ns_to_timespec(_period);
	ds_its.it_interval.tv_sec = ds_its.it_value.tv_sec;
	ds_its.it_interval.tv_nsec = ds_its.it_value.tv_nsec;

	if (unlikely(timerfd_settime(_fd, 0, &ds_its, NULL) == -1))
		panic("timerfd_settime");

	return;
}

void ds_regcomp(regex_t* _preg, const char* _regex)
{
	if (unlikely(regcomp(_preg, _regex, REG_EXTENDED | REG_NOSUB)))
		panic("regcomp");
}

