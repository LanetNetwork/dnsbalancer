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

#include "context.h"
#include "handlers.h"
#include "pfcq.h"
#include "rb.h"
#include "utils.h"

#include "evloop.h"

int ds_wrk_loop_handler(struct epoll_event _event, struct ds_wrk_ctx* _data)
{
	struct ds_fe_sk* fe_sk = NULL;
	struct ds_fe_sk ref_fe_sk;
	struct ds_fwd_sk* fwd_sk = NULL;
	struct ds_fwd_sk ref_fwd_sk;
	int ret = 0;

	pfcq_zero(&ref_fe_sk, sizeof(struct ds_fe_sk));

	// prepare to forward
	if (_event.data.fd == _data->ev_prep_fd)
	{
		ret = ds_wrk_prep_handler(_event.data.fd, _data);
		goto out;
	}

	// perform forwarding
	if (_event.data.fd == _data->ev_fwd_fd)
	{
		ret = ds_wrk_fwd_handler(_event.data.fd, _data);
		goto out;
	}

	// send reply
	if (_event.data.fd == _data->ev_rep_fd)
	{
		ret = ds_wrk_rep_handler(_event.data.fd, _data);
		goto out;
	}

	// process reply for watchdog
	if (_event.data.fd == _data->ev_wdt_rep_fd)
	{
		ret = ds_wrk_wdt_rep_handler(_event.data.fd, _data);
		goto out;
	}

	// perform exit
	if (_event.data.fd == _data->ctx->exit_fd)
	{
		ret = ds_wrk_exit_handler(_event.data.fd, _data);
		goto out;
	}

	// perform tracking tree GC
	if (_event.data.fd == _data->ev_gc_fd)
	{
		ret = ds_wrk_gc_handler(_event.data.fd, _data);
		goto out;
	}

	// prepare forwarders watchdog request
	if (_event.data.fd == _data->ctx->wdt_fd)
	{
		ret = ds_wrk_wdt_req_handler(_event.data.fd, _data);
		goto out;
	}

	// perform timekeeping tasks
	if (_event.data.fd == _data->ctx->tk_fd)
	{
		ret = ds_wrk_tk_handler(_event.data.fd, _data);
		goto out;
	}

	// accept request from client
	ref_fe_sk.sk = _event.data.fd;
	if ((fe_sk = rb_find(_data->fe_sk_set, &ref_fe_sk)))
	{
		ret = ds_wrk_acpt_handler(fe_sk, _data);
		goto out;
	}

	// obtain regular response from forwarder
	ref_fwd_sk.sk = _event.data.fd;
	if ((fwd_sk = rb_find(_data->fwd_sk_set, &ref_fwd_sk)))
	{
		ret = ds_wrk_obt_handler(fwd_sk, _data);
		goto out;
	}

	// obtain watchdog response from forwarder
	ref_fwd_sk.sk = _event.data.fd;
	if ((fwd_sk = rb_find(_data->fwd_wdt_sk_set, &ref_fwd_sk)))
	{
		ret = ds_wrk_obt_handler(fwd_sk, _data);
		goto out;
	}

out:
	return ret;
}

void ds_loop(ds_loop_handler_fn_t _handler, struct ds_wrk_ctx* _data)
{
	int events = -1;
	ssize_t has_read = -1;
	struct epoll_event got_events[EPOLL_MAXEVENTS];
	char* read_buf = NULL;

	pfcq_zero(got_events, EPOLL_MAXEVENTS * sizeof(struct epoll_event));

	read_buf = pfcq_alloc(_data->ctx->max_pkt_size);

	while (true)
	{
		events = ds_epoll_wait(_data->wrk_fd, got_events, EPOLL_MAXEVENTS, _data->poll_timeo);
		if (unlikely(events == 0))
		{
			if (unlikely(rb_count(_data->tracking) == 0 && pfcq_counter_get(&_data->ctx->in_flight) == 0))
				goto out;
			else
				continue;
		} else if (unlikely(events == -1))
		{
			// EINTR is caught in wrapper;
			// everything else is unexpected, so if it happens, something went wrong;
			// that's why panic immediately
			panic("epoll_wait");
		} else
		{
			for (size_t i = 0; i < (size_t)events; i++)
			{
				if (likely(got_events[i].events == EPOLLIN))
				{
					// consume data as no error happened
					if (unlikely(_handler(got_events[i], _data) == -1))
						goto out;
				} else if (unlikely(got_events[i].events == EPOLLERR))
				{
					// EPOLLERR might be returned if network issue happened
					// explicitly ignore this; also consume value and check
					// for error returned; ECONNREFUSED and EAGAIN are expected only,
					// otherwise panic immediately
					has_read = ds_read(got_events[i].data.fd, read_buf, _data->ctx->max_pkt_size);
					if (unlikely(has_read == -1 && errno != ECONNREFUSED && errno != EAGAIN))
					{
						inform("%d\n", errno);
						panic("ds_read");
					} else
						continue;
				} else
				{
					// nothing else is expected, so panic immediately,
					// because something went wrong
					inform("Got events: %d\n", got_events[i].events);
					panic("epoll_wait");
				}
			}
		}
	}

out:

	pfcq_free(read_buf);

	return;
}

