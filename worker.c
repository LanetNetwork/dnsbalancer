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

#include <sys/eventfd.h>
#include <sys/timerfd.h>

#include "evloop.h"
#include "pfcq.h"
#include "rb.h"
#include "utils.h"

#include "worker.h"

void* ds_wrk(void* _data)
{
	struct ds_wrk_ctx* data = _data;

	int option = 1;
	struct rb_traverser iter;
	struct ds_fwd_sk* cur_fwd_sk = NULL;
	struct ds_fwd_sk* cur_fwd_wdt_sk = NULL;

	pfcq_zero(&iter, sizeof(struct rb_traverser));

	data->wrk_fd = ds_epoll_create();
	data->poll_timeo = -1;

	data->tracking = rb_create(ds_tsk_cmp, NULL, &ds_rb_allocator);

	data->fe_sk_set = rb_create(ds_fe_sk_cmp, NULL, &ds_rb_allocator);
	for (size_t i = 0; i < data->ctx->nfes; i++)
	{
		struct ds_fe_sk* new_sk = pfcq_alloc(sizeof(struct ds_fe_sk));
		new_sk->fe = &data->ctx->fes[i];
		new_sk->sk = ds_socket(ds_af_to_pf(new_sk->fe->addr.family), SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
		ds_setsockopt(new_sk->sk, IPPROTO_IP, IP_FREEBIND,
				   (const void*)&option, sizeof(option));
		ds_setsockopt(new_sk->sk, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
				   (const void*)&option, sizeof(option));
		ds_set_sock_dscp(new_sk->sk, ds_af_to_pf(new_sk->fe->addr.family), new_sk->fe->dscp);
		ds_bind(new_sk->sk, &new_sk->fe->addr);
		ds_epoll_add_fd(data->wrk_fd, new_sk->sk, EPOLLIN);
		rb_insert(data->fe_sk_set, (void*)new_sk);
	}

	data->fwd_sk_set = rb_create(ds_fwd_sk_cmp, NULL, &ds_rb_allocator);
	for (size_t i = 0; i < data->ctx->nfwds; i++)
	{
		struct ds_fwd_sk* new_sk = pfcq_alloc(sizeof(struct ds_fwd_sk));
		new_sk->fwd = &data->ctx->fwds[i];
		new_sk->sk = ds_socket(ds_af_to_pf(new_sk->fwd->addr.family), SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
		ds_setsockopt(new_sk->sk, SOL_SOCKET, SO_REUSEADDR,
				   (const void*)&option, sizeof(option));
		ds_set_sock_dscp(new_sk->sk, ds_af_to_pf(new_sk->fwd->addr.family), new_sk->fwd->reg_dscp);
		ds_connect(new_sk->sk, &new_sk->fwd->addr);
		ds_epoll_add_fd(data->wrk_fd, new_sk->sk, EPOLLIN);
		rb_insert(data->fwd_sk_set, (void*)new_sk);
	}

	data->fwd_wdt_sk_set = rb_create(ds_fwd_sk_cmp, NULL, &ds_rb_allocator);
	for (size_t i = 0; i < data->ctx->nfwds; i++)
	{
		struct ds_fwd_sk* new_sk = pfcq_alloc(sizeof(struct ds_fwd_sk));
		new_sk->fwd = &data->ctx->fwds[i];
		new_sk->sk = ds_socket(ds_af_to_pf(new_sk->fwd->addr.family), SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
		ds_setsockopt(new_sk->sk, SOL_SOCKET, SO_REUSEADDR,
				   (const void*)&option, sizeof(option));
		ds_set_sock_dscp(new_sk->sk, ds_af_to_pf(new_sk->fwd->addr.family), new_sk->fwd->wdt_dscp);
		ds_connect(new_sk->sk, &new_sk->fwd->addr);
		ds_epoll_add_fd(data->wrk_fd, new_sk->sk, EPOLLIN);
		rb_insert(data->fwd_wdt_sk_set, (void*)new_sk);
	}

	data->ev_prep_fd = ds_eventfd(0, EFD_SEMAPHORE | EFD_NONBLOCK);
	data->ev_fwd_fd = ds_eventfd(0, EFD_SEMAPHORE | EFD_NONBLOCK);
	data->ev_rep_fd = ds_eventfd(0, EFD_SEMAPHORE | EFD_NONBLOCK);
	data->ev_wdt_rep_fd = ds_eventfd(0, EFD_SEMAPHORE | EFD_NONBLOCK);
	data->ev_gc_fd = ds_timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	ds_timerfd_settime(data->ev_gc_fd, data->ctx->gc_intvl);
	TAILQ_INIT(&data->prep_queue);
	TAILQ_INIT(&data->fwd_queue);
	TAILQ_INIT(&data->rep_queue);
	TAILQ_INIT(&data->wdt_rep_queue);
	pfcq_spin_init(&data->rep_queue_lock);
	pfcq_spin_init(&data->wdt_rep_queue_lock);
	ds_epoll_add_fd(data->wrk_fd, data->ev_prep_fd, EPOLLIN);
	ds_epoll_add_fd(data->wrk_fd, data->ev_fwd_fd, EPOLLIN);
	ds_epoll_add_fd(data->wrk_fd, data->ev_rep_fd, EPOLLIN);
	ds_epoll_add_fd(data->wrk_fd, data->ev_wdt_rep_fd, EPOLLIN);
	ds_epoll_add_fd(data->wrk_fd, data->ev_gc_fd, EPOLLIN);

	ds_epoll_add_fd(data->wrk_fd, data->ctx->exit_fd, EPOLLIN);
	ds_epoll_add_fd(data->wrk_fd, data->ctx->wdt_fd, EPOLLIN | EPOLLEXCLUSIVE);
	ds_epoll_add_fd(data->wrk_fd, data->ctx->tk_fd, EPOLLIN | EPOLLEXCLUSIVE);

	ds_produce_u64(data->ready);

	ds_loop(ds_wrk_loop_handler, data);

	rb_destroy(data->tracking, NULL);

	rb_destroy(data->fe_sk_set, ds_rb_item_free);

	rb_t_init(&iter, data->fwd_sk_set);
	cur_fwd_sk = rb_t_first(&iter, data->fwd_sk_set);
	do {
		ds_close(cur_fwd_sk->sk);
	} while (likely((cur_fwd_sk = rb_t_next(&iter)) != NULL));
	rb_destroy(data->fwd_sk_set, ds_rb_item_free);

	rb_t_init(&iter, data->fwd_wdt_sk_set);
	cur_fwd_wdt_sk = rb_t_first(&iter, data->fwd_wdt_sk_set);
	do {
		ds_close(cur_fwd_wdt_sk->sk);
	} while (likely((cur_fwd_wdt_sk = rb_t_next(&iter)) != NULL));
	rb_destroy(data->fwd_wdt_sk_set, ds_rb_item_free);

	ds_epoll_del_fd(data->wrk_fd, data->ctx->exit_fd);
	ds_epoll_del_fd(data->wrk_fd, data->ctx->tk_fd);
	ds_epoll_del_fd(data->wrk_fd, data->ev_prep_fd);
	ds_epoll_del_fd(data->wrk_fd, data->ev_fwd_fd);
	ds_epoll_del_fd(data->wrk_fd, data->ev_rep_fd);
	ds_epoll_del_fd(data->wrk_fd, data->ev_wdt_rep_fd);
	ds_epoll_del_fd(data->wrk_fd, data->ev_gc_fd);

	ds_close(data->ev_prep_fd);
	ds_close(data->ev_fwd_fd);
	ds_close(data->ev_rep_fd);
	ds_close(data->ev_wdt_rep_fd);
	ds_close(data->ev_gc_fd);

	pfcq_spin_done(&data->rep_queue_lock);
	pfcq_spin_done(&data->wdt_rep_queue_lock);

	ds_close(data->wrk_fd);

	return NULL;
}

