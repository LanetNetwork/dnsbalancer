/* vim: set tabstop=4:softtabstop=4:shiftwidth=4:noexpandtab */

/*
 * dnsbalancer - daemon to balance UDP DNS requests over DNS servers
 * Copyright (C) 2015 Lanet Network
 * Programmed by Oleksandr Natalenko <o.natalenko@lanet.ua>
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

#include <hashitems.h>
#include <microhttpd.h>
#include <stats.h>
#include <string.h>

static db_local_context_t* ctx = NULL;
static struct MHD_Daemon* mhd_daemon = NULL;

void db_stats_frontend_in(db_frontend_t* _frontend, uint64_t _delta_bytes)
{
	if (unlikely(pthread_spin_lock(&_frontend->stats.in_lock)))
		panic("pthread_spin_lock");
	_frontend->stats.in_pkts++;
	_frontend->stats.in_bytes += _delta_bytes;
	if (unlikely(pthread_spin_unlock(&_frontend->stats.in_lock)))
		panic("pthread_spin_unlock");

	return;
}

void db_stats_frontend_in_invalid(db_frontend_t* _frontend, uint64_t _delta_bytes)
{
	if (unlikely(pthread_spin_lock(&_frontend->stats.in_invalid_lock)))
		panic("pthread_spin_lock");
	_frontend->stats.in_pkts_invalid++;
	_frontend->stats.in_bytes_invalid += _delta_bytes;
	if (unlikely(pthread_spin_unlock(&_frontend->stats.in_invalid_lock)))
		panic("pthread_spin_unlock");

	return;
}

void db_stats_frontend_out(db_frontend_t* _frontend, uint64_t _delta_bytes, ldns_pkt_rcode _rcode)
{
	if (unlikely(pthread_spin_lock(&_frontend->stats.out_lock)))
		panic("pthread_spin_lock");
	_frontend->stats.out_pkts++;
	_frontend->stats.out_bytes += _delta_bytes;
	switch (_rcode)
	{
		case LDNS_RCODE_NOERROR:
			_frontend->stats.out_noerror++;
			break;
		case LDNS_RCODE_SERVFAIL:
			_frontend->stats.out_servfail++;
			break;
		case LDNS_RCODE_NXDOMAIN:
			_frontend->stats.out_nxdomain++;
			break;
		case LDNS_RCODE_REFUSED:
			_frontend->stats.out_refused++;
			break;
		default:
			_frontend->stats.out_other++;
			break;
	}
	if (unlikely(pthread_spin_unlock(&_frontend->stats.out_lock)))
		panic("pthread_spin_unlock");

	return;
}

static db_frontend_stats_t db_stats_frontend(db_frontend_t* _frontend)
{
	if (unlikely(pthread_spin_lock(&_frontend->stats.in_lock)))
		panic("pthread_spin_lock");
	if (unlikely(pthread_spin_lock(&_frontend->stats.in_invalid_lock)))
		panic("pthread_spin_lock");
	if (unlikely(pthread_spin_lock(&_frontend->stats.out_lock)))
		panic("pthread_spin_lock");

	db_frontend_stats_t ret = _frontend->stats;

	if (unlikely(pthread_spin_unlock(&_frontend->stats.out_lock)))
		panic("pthread_spin_unlock");
	if (unlikely(pthread_spin_unlock(&_frontend->stats.in_invalid_lock)))
		panic("pthread_spin_unlock");
	if (unlikely(pthread_spin_unlock(&_frontend->stats.in_lock)))
		panic("pthread_spin_unlock");

	return ret;
}

void db_stats_forwarder_in(db_forwarder_t* _forwarder, uint64_t _delta_bytes)
{
	if (unlikely(pthread_spin_lock(&_forwarder->stats.in_lock)))
		panic("pthread_spin_lock");
	_forwarder->stats.in_pkts++;
	_forwarder->stats.in_bytes += _delta_bytes;
	if (unlikely(pthread_spin_unlock(&_forwarder->stats.in_lock)))
		panic("pthread_spin_unlock");

	return;
}

void db_stats_forwarder_out(db_forwarder_t* _forwarder, uint64_t _delta_bytes, ldns_pkt_rcode _rcode)
{
	if (unlikely(pthread_spin_lock(&_forwarder->stats.out_lock)))
		panic("pthread_spin_lock");
	_forwarder->stats.out_pkts++;
	_forwarder->stats.out_bytes += _delta_bytes;
	switch (_rcode)
	{
		case LDNS_RCODE_NOERROR:
			_forwarder->stats.out_noerror++;
			break;
		case LDNS_RCODE_SERVFAIL:
			_forwarder->stats.out_servfail++;
			break;
		case LDNS_RCODE_NXDOMAIN:
			_forwarder->stats.out_nxdomain++;
			break;
		case LDNS_RCODE_REFUSED:
			_forwarder->stats.out_refused++;
			break;
		default:
			_forwarder->stats.out_other++;
			break;
	}
	if (unlikely(pthread_spin_unlock(&_forwarder->stats.out_lock)))
		panic("pthread_spin_unlock");

	return;
}

static db_forwarder_stats_t db_stats_forwarder(db_forwarder_t* _forwarder)
{
	if (unlikely(pthread_spin_lock(&_forwarder->stats.in_lock)))
		panic("pthread_spin_lock");
	if (unlikely(pthread_spin_lock(&_forwarder->stats.out_lock)))
		panic("pthread_spin_lock");

	db_forwarder_stats_t ret = _forwarder->stats;

	if (unlikely(pthread_spin_unlock(&_forwarder->stats.out_lock)))
		panic("pthread_spin_unlock");
	if (unlikely(pthread_spin_unlock(&_forwarder->stats.in_lock)))
		panic("pthread_spin_unlock");

	return ret;
}

static int db_queue_code(struct MHD_Connection* _connection, const char* _url, unsigned int _code)
{
	int ret = MHD_NO;
	struct MHD_Response* response = MHD_create_response_from_data(0, NULL, 0, 0);
	if (unlikely(!response))
		return ret;

	ret = MHD_queue_response(_connection, _code, response);
	MHD_destroy_response(response);

	return ret;
}

static int db_answer_to_connection(void* _data,
		struct MHD_Connection* _connection,
		const char* _url, const char* _method,
		const char* _version, const char* _upload_data,
		size_t* _upload_data_size, void** _context)
{
	(void)_data;
	(void)_version;
	(void)_upload_data;
	(void)_upload_data_size;
	(void)_context;

	int ret = MHD_NO;
	struct MHD_Response* response = NULL;

	if (unlikely(strcmp(_method, MHD_HTTP_METHOD_GET) != 0))
	{
		ret = db_queue_code(_connection, _url, MHD_HTTP_METHOD_NOT_ALLOWED);
		goto out;
	}

	if (strcmp(_url, "/stats") == 0)
	{
		char* stats = pfcq_mstring("%s\n", "# name,FRONTEND,in_pkts,in_bytes,in_invalid_pkts,in_invalid_bytes,out_pkts,out_bytes,noerror,servfail,nxdomain,refused,other");
		for (size_t i = 0; i < ctx->frontends_count; i++)
		{
			db_frontend_stats_t fe_stats = db_stats_frontend(ctx->frontends[i]);
			char* row = pfcq_mstring("%s,FRONTEND,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu\n",
					ctx->frontends[i]->name,
					fe_stats.in_pkts, fe_stats.in_bytes,
					fe_stats.in_pkts_invalid, fe_stats.in_bytes_invalid,
					fe_stats.out_pkts, fe_stats.out_bytes,
					fe_stats.out_noerror, fe_stats.out_servfail, fe_stats.out_nxdomain, fe_stats.out_refused, fe_stats.out_other);
			stats = pfcq_cstring(stats, row);
			pfcq_free(row);
		}
		stats = pfcq_cstring(stats, "# name,FORWARDER,frontend_name,in_pkts,in_bytes,out_pkts,out_bytes,noerror,servfail,nxdomain,refused,other\n");
		for (size_t i = 0; i < ctx->frontends_count; i++)
			for (size_t j = 0; j < ctx->frontends[i]->backend.forwarders_count; j++)
			{
				db_forwarder_stats_t frw_stats = db_stats_forwarder(ctx->frontends[i]->backend.forwarders[j]);
				char* row = pfcq_mstring("%s,FORWARDER,%s,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu\n",
						ctx->frontends[i]->backend.forwarders[j]->name,
						ctx->frontends[i]->name,
						frw_stats.in_pkts, frw_stats.in_bytes,
						frw_stats.out_pkts, frw_stats.out_bytes,
						frw_stats.out_noerror, frw_stats.out_servfail, frw_stats.out_nxdomain, frw_stats.out_refused, frw_stats.out_other);
				stats = pfcq_cstring(stats, row);
				pfcq_free(row);
			}

		response = MHD_create_response_from_buffer(strlen(stats), stats, MHD_RESPMEM_MUST_COPY);
		if (unlikely(!response))
		{
			ret = db_queue_code(_connection, _url, MHD_HTTP_INTERNAL_SERVER_ERROR);
		} else
		{
			ret = MHD_queue_response(_connection, MHD_HTTP_OK, response);
			MHD_destroy_response(response);
		}
		pfcq_free(stats);
		goto out;
	} else if (strcmp(_url, "/acls") == 0)
	{
		char* acls = pfcq_mstring("%s\n", "# ACLs");
		for (size_t i = 0; i < ctx->frontends_count; i++)
		{
			char* row = NULL;
			struct db_acl_item* current_acl_item = NULL;

			row = pfcq_mstring("# %s,FRONTEND\n", ctx->frontends[i]->name);
			acls = pfcq_cstring(acls, row);
			pfcq_free(row);
			row = pfcq_mstring("%s\n", "# layer3,address/netmask,regex,action,hits");
			acls = pfcq_cstring(acls, row);
			pfcq_free(row);

			TAILQ_FOREACH(current_acl_item, &ctx->frontends[i]->acl, tailq)
			{
				if (unlikely(pthread_spin_lock(&current_acl_item->hits_lock)))
					panic("pthread_spin_lock");
				uint64_t hits = current_acl_item->hits;
				if (unlikely(pthread_spin_unlock(&current_acl_item->hits_lock)))
					panic("pthread_spin_unlock");
				row = pfcq_mstring("%s,%s/%s,%s,%s,%lu\n", current_acl_item->s_layer3,
						current_acl_item->s_address, current_acl_item->s_netmask,
						current_acl_item->s_list, current_acl_item->s_action,
						hits);
				acls = pfcq_cstring(acls, row);
				pfcq_free(row);
			}
		}

		response = MHD_create_response_from_buffer(strlen(acls), acls, MHD_RESPMEM_MUST_COPY);
		if (unlikely(!response))
		{
			ret = db_queue_code(_connection, _url, MHD_HTTP_INTERNAL_SERVER_ERROR);
		} else
		{
			ret = MHD_queue_response(_connection, MHD_HTTP_OK, response);
			MHD_destroy_response(response);
		}
		pfcq_free(acls);
		goto out;
	} else
		ret = db_queue_code(_connection, _url, MHD_HTTP_NOT_FOUND);

out:
	return ret;
}

void db_stats_init(db_local_context_t* _ctx)
{
	ctx = _ctx;

	if (ctx->stats_enabled)
	{
		unsigned int options = MHD_USE_SELECT_INTERNALLY | MHD_USE_EPOLL_LINUX_ONLY;
		switch (ctx->stats_layer3_family)
		{
			case PF_INET:
				mhd_daemon =
					MHD_start_daemon(options,
							0, NULL, NULL, &db_answer_to_connection, NULL,
							MHD_OPTION_THREAD_POOL_SIZE, 1,
							MHD_OPTION_SOCK_ADDR,
							(struct sockaddr*)&ctx->stats_address.address4,
							MHD_OPTION_END);
				break;
			case PF_INET6:
				mhd_daemon =
					MHD_start_daemon(options | MHD_USE_IPv6,
							0, NULL, NULL, &db_answer_to_connection, NULL,
							MHD_OPTION_THREAD_POOL_SIZE, 1,
							MHD_OPTION_SOCK_ADDR,
							(struct sockaddr*)&ctx->stats_address.address6,
							MHD_OPTION_END);
				break;
			default:
				panic("socket domain");
				break;
		}
		if (unlikely(mhd_daemon == NULL))
			panic("MHD_start_daemon");
	}

	return;
}

void db_stats_done(void)
{
	if (mhd_daemon)
		MHD_stop_daemon(mhd_daemon);
	ctx = NULL;

	return;
}

