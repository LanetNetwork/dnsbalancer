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

#include "rb.h"

#include "types.h"

extern struct libavl_allocator ds_rb_allocator;

void* ds_rb_malloc(struct libavl_allocator* _allocator, size_t _libavl_size) __attribute__((warn_unused_result));
void ds_rb_free(struct libavl_allocator* _allocator, void* _libavl_block);
void ds_rb_item_free(void* _rb_item, void* _rb_param);
void ds_tsk_free(struct ds_wrk_tsk* _tsk);
void ds_rb_tsk_free(void* _rb_item, void* _rb_param);
int ds_fe_sk_cmp(const void* _p1, const void* _p2, void* _param) __attribute__((warn_unused_result));
int ds_fwd_sk_cmp(const void* _p1, const void* _p2, void* _param) __attribute__((warn_unused_result));
int ds_tsk_cmp(const void* _p1, const void* _p2, void* _param) __attribute__((warn_unused_result));
void ds_epoll_add_fd(int _evfd, int _fd, uint32_t _events);
void ds_epoll_del_fd(int _evfd, int _fd);
void ds_produce_u64(int _fd);
void ds_consume_u64(int _fd);
int ds_try_consume_u64(int _fd) __attribute__((warn_unused_result));
int ds_int_cmp(int _i1, int _i2) __attribute__((warn_unused_result));
int ds_ptr_cmp(void* _p1, void* _p2) __attribute__((warn_unused_result));
int ds_epoll_wait(int _epfd, struct epoll_event* _events,
				  int _maxevents, int _timeout) __attribute__((warn_unused_result));
ssize_t ds_read(int _fd, void* _buf, size_t _count) __attribute__((warn_unused_result));
ssize_t ds_write(int _fd, const void* _buf, size_t _count) __attribute__((warn_unused_result));
ssize_t ds_recvfrom(int _socket, void* restrict _buffer, size_t _length,
					struct pfcq_net_addr* _address) __attribute__((warn_unused_result));
ssize_t ds_sendto(int _socket, const void* _message, size_t _length,
				  const struct pfcq_net_addr* _dest_addr) __attribute__((warn_unused_result));
ssize_t ds_recv(int _sockfd, void* _buf, size_t _len) __attribute__((warn_unused_result));
ssize_t ds_send(int _sockfd, const void* _buf, size_t _len) __attribute__((warn_unused_result));
int ds_eventfd(unsigned int _initval, int _flags) __attribute__((warn_unused_result));
int ds_epoll_create(void) __attribute__((warn_unused_result));
void ds_close(int _fd);
int ds_af_to_pf(sa_family_t _af) __attribute__((warn_unused_result));
int ds_socket(int _domain, int _type, int _protocol) __attribute__((warn_unused_result));
void ds_setsockopt(int _socket, int _level, int _option_name,
			   const void* _option_value, socklen_t _option_len);
void ds_bind(int _socket, const struct pfcq_net_addr* _address);
void ds_connect(int _socket, const struct pfcq_net_addr* _address);
void ds_inet_pton(const char* _src_addr, in_port_t _src_port, struct pfcq_net_addr* _dst);
void ds_inet_vlsmton(const struct pfcq_net_addr* _src, const char* _vlsm, struct pfcq_net_addr* _dst);
uint64_t ds_hash_address(struct pfcq_net_addr* _address) __attribute__((warn_unused_result));
void ds_set_sock_dscp(int _socket, int _domain, int _dscp);
int ds_timerfd_create(int _clockid, int _flags) __attribute__((warn_unused_result));
void ds_timerfd_settime(int _fd, uint64_t _period);
void ds_regcomp(regex_t* _preg, const char* _regex);

