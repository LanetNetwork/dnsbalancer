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

void* ds_rb_malloc(struct libavl_allocator*, size_t) __attribute__((warn_unused_result));
void ds_rb_free(struct libavl_allocator*, void*);
void ds_rb_item_free(void*, void*);
void ds_tsk_free(struct ds_wrk_tsk*);
void ds_rb_tsk_free(void*, void*);
int ds_fe_sk_cmp(const void*, const void*, void*) __attribute__((warn_unused_result));
int ds_fwd_sk_cmp(const void*, const void*, void*) __attribute__((warn_unused_result));
int ds_tsk_cmp(const void*, const void*, void*) __attribute__((warn_unused_result));
void ds_epoll_add_fd(int, int, uint32_t);
void ds_epoll_del_fd(int, int);
void ds_produce_u64(int);
void ds_consume_u64(int);
int ds_try_consume_u64(int) __attribute__((warn_unused_result));
int ds_int_cmp(int, int) __attribute__((warn_unused_result));
int ds_ptr_cmp(void*, void*) __attribute__((warn_unused_result));
int ds_epoll_wait(int, struct epoll_event*, int, int) __attribute__((warn_unused_result));
ssize_t ds_read(int, void*, size_t) __attribute__((warn_unused_result));
ssize_t ds_write(int, const void*, size_t) __attribute__((warn_unused_result));
ssize_t ds_recvfrom(int, void* restrict, size_t, struct pfcq_net_addr*) __attribute__((warn_unused_result));
ssize_t ds_sendto(int, const void*, size_t, const struct pfcq_net_addr*) __attribute__((warn_unused_result));
ssize_t ds_recv(int, void*, size_t) __attribute__((warn_unused_result));
ssize_t ds_send(int, const void*, size_t) __attribute__((warn_unused_result));
int ds_eventfd(unsigned int, int) __attribute__((warn_unused_result));
int ds_epoll_create(void) __attribute__((warn_unused_result));
void ds_close(int);
int ds_af_to_pf(sa_family_t) __attribute__((warn_unused_result));
int ds_socket(int, int, int) __attribute__((warn_unused_result));
void ds_setsockopt(int, int, int, const void*, socklen_t);
void ds_bind(int, const struct pfcq_net_addr*);
void ds_connect(int, const struct pfcq_net_addr*);
void ds_inet_pton(const char*, in_port_t, struct pfcq_net_addr*);
void ds_inet_vlsmton(const struct pfcq_net_addr*, const char*, struct pfcq_net_addr*);
uint64_t ds_hash_address(struct pfcq_net_addr*) __attribute__((warn_unused_result));
void ds_set_sock_dscp(int, int, int);
int ds_timerfd_create(int, int) __attribute__((warn_unused_result));
void ds_timerfd_settime(int, uint64_t);
void ds_regcomp(regex_t*, const char*);

