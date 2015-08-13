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

#include <bsd/unistd.h>
#include <crc64speed.h>
#include <getopt.h>
#include <hashitems.h>
#include <iniparser.h>
#include <ldns/ldns.h>
#include <pfcq.h>
#include <signal.h>
#include <stats.h>
#include <sys/epoll.h>
#ifndef MODE_DEBUG
#include <sys/resource.h>
#endif
#include <sysexits.h>

db_frontend_t** frontends = NULL;
size_t frontends_count = 0;
static volatile sig_atomic_t should_exit = 0;
static db_hashlist_t db_hashlist;
static uint64_t db_gc_interval = 0;
db_loadavg_t db_loadavg;
static struct db_loadavg_items db_loadavg_items;
static double db_loadavg_sampling_factor = 0;

static void __usage(char* _argv0)
{
	inform("Usage: %s --config=<filename> [--pid-file=<filename>] [--daemonize] [--verbose] [--debug] [--syslog]\n", basename(_argv0));
}

static void __version(void)
{
	inform("%s v%s\n", APP_NAME, APP_VERSION);
	inform("© %s, %s\n", APP_YEAR, APP_HOLDER);
	inform("Programmed by %s <%s>\n", APP_PROGRAMMER, APP_EMAIL);
}

static uint64_t db_sockaddr_addr_crc64(sa_family_t _family, void* _sockaddr)
{
	uint64_t ret = 0;
	unsigned long s_addr = 0;
	const uint8_t* s_addr_buf = NULL;
	const uint8_t* s6_addr_buf = NULL;
	uint32_t* s6_addr_piece = NULL;
	uint32_t s6_addr_piece_h = 0;
	pfcq_net_address_t address;

	switch (_family)
	{
		case PF_INET:
			memcpy(&address.address4, _sockaddr, sizeof(struct sockaddr_in));
			s_addr = ntohl(address.address4.sin_addr.s_addr);
			s_addr_buf = (const uint8_t*)&s_addr;
			ret = crc64speed(0, s_addr_buf, sizeof(unsigned long));
			break;
		case PF_INET6:
			memcpy(&address.address6, _sockaddr, sizeof(struct sockaddr_in6));
			for (size_t i = 0; i < sizeof(address.address6.sin6_addr.s6_addr); i += sizeof(address.address6.sin6_addr.s6_addr) / sizeof(uint32_t))
			{
				s6_addr_piece = (uint32_t*)&address.address6.sin6_addr.s6_addr[i];
				s6_addr_piece_h = ntohl(*s6_addr_piece);
				s6_addr_buf = (const uint8_t*)&s6_addr_piece_h;
				ret = crc64speed(ret, s6_addr_buf, sizeof(uint32_t));
			}
			break;
		default:
			panic("socket domain");
			break;
	}

	return ret;
}

static uint64_t db_sockaddr_port_crc64(sa_family_t _family, void* _sockaddr)
{
	uint64_t ret = 0;
	unsigned short u_port = 0;
	const uint8_t* u_port_buf = NULL;
	pfcq_net_address_t address;

	switch (_family)
	{
		case PF_INET:
			memcpy(&address.address4, _sockaddr, sizeof(struct sockaddr_in));
			u_port = ntohs(address.address4.sin_port);
			u_port_buf = (const uint8_t*)&u_port;
			ret = crc64speed(0, u_port_buf, sizeof(unsigned short));
			break;
		case PF_INET6:
			memcpy(&address.address6, _sockaddr, sizeof(struct sockaddr_in6));
			u_port = ntohs(address.address6.sin6_port);
			u_port_buf = (const uint8_t*)&u_port;
			ret = crc64speed(0, u_port_buf, sizeof(unsigned short));
			break;
		default:
			panic("socket domain");
			break;
	}

	return ret;
}

__attribute__((always_inline)) static inline ssize_t __db_find_alive_forwarder_by_offset(uint64_t _offset, db_backend_t* _backend)
{
	ssize_t ret = -1;

	for (size_t tries = 0; tries < _backend->forwarders_count; tries++)
	{
		size_t index = (_offset + tries) % _backend->forwarders_count;
		if (likely(_backend->forwarders[index]->alive))
		{
			ret = index;
			break;
		}
	}

	return ret;
}


static ssize_t db_find_alive_forwarder(db_frontend_t* _frontend, pfcq_fprng_context_t* _fprng_context, void* _sockaddr)
{
	if (unlikely(!_frontend))
		return -1;

	ssize_t ret = -1;

	size_t queries = 0;
	if (unlikely(pthread_spin_lock(&_frontend->backend.queries_lock)))
		panic("pthread_spin_lock");
	queries = _frontend->backend.queries++;
	if (unlikely(pthread_spin_unlock(&_frontend->backend.queries_lock)))
		panic("pthread_spin_unlock");

	size_t index = 0;
	unsigned short int random_map[_frontend->backend.forwarders_count];
	uint64_t least_pkts = UINT64_MAX;
	uint64_t least_traffic = UINT64_MAX;
	uint64_t xor = 0;
	uint64_t crc1 = 0;
	uint64_t crc2 = 0;
	double probability = 0;
	double normalized_weight = 0;

	pfcq_zero(random_map, _frontend->backend.forwarders_count * sizeof(unsigned short int));

	switch (_frontend->backend.mode)
	{
		case DB_BE_MODE_RR:
			ret = __db_find_alive_forwarder_by_offset(queries, &_frontend->backend);
			break;
		case DB_BE_MODE_RANDOM:
			probability = (double)pfcq_fprng_get_u64(_fprng_context) / UINT64_MAX;
			for (size_t tries = 0; tries < _frontend->backend.forwarders_count; tries++)
			{
				for (index = 0; index < _frontend->backend.forwarders_count; index++)
				{
					normalized_weight = (double)_frontend->backend.forwarders[index]->weight / _frontend->backend.total_weight;
					if (_frontend->backend.forwarders[index]->alive && probability < normalized_weight)
					{
						ret = index;
						break;
					} else
						probability -= normalized_weight;
				}
				if (likely(ret != -1))
					break;
			}
			break;
		case DB_BE_MODE_LEAST_PKTS:
			for (index = 0; index < _frontend->backend.forwarders_count; index++)
				if (likely(_frontend->backend.forwarders[index]->alive))
					if (_frontend->backend.forwarders[index]->stats.in_pkts <= least_pkts)
					{
						least_pkts = _frontend->backend.forwarders[index]->stats.in_pkts;
						ret = index;
					}
			break;
		case DB_BE_MODE_LEAST_TRAFFIC:
			for (index = 0; index < _frontend->backend.forwarders_count; index++)
				if (likely(_frontend->backend.forwarders[index]->alive))
					if (_frontend->backend.forwarders[index]->stats.in_bytes <= least_traffic)
					{
						least_traffic = _frontend->backend.forwarders[index]->stats.in_bytes;
						ret = index;
					}
			break;
		case DB_BE_MODE_HASH_L3_L4:
			crc1 = db_sockaddr_addr_crc64(_frontend->layer3, _sockaddr);
			crc2 = db_sockaddr_port_crc64(_frontend->layer3, _sockaddr);
			xor = crc1 ^ crc2;
			ret = __db_find_alive_forwarder_by_offset(xor, &_frontend->backend);
			break;
		case DB_BE_MODE_HASH_L3:
			xor = db_sockaddr_addr_crc64(_frontend->layer3, _sockaddr);
			ret = __db_find_alive_forwarder_by_offset(xor, &_frontend->backend);
			break;
		case DB_BE_MODE_HASH_L4:
			xor = db_sockaddr_port_crc64(_frontend->layer3, _sockaddr);
			ret = __db_find_alive_forwarder_by_offset(xor, &_frontend->backend);
			break;
		default:
			ret = 0;
			break;
	}

	return ret;
}

static int db_ping_forwarder(db_forwarder_t* _forwarder)
{
	int ret = 0;
	size_t db_ping_packet_buffer_size = 0;
	uint8_t* db_ping_packet_buffer = NULL;
	uint8_t db_echo_packet_buffer[DB_DEFAULT_DNS_PACKET_SIZE];
	struct timeval timeout = __pfcq_us_to_timeval(_forwarder->check_timeout);

	pfcq_zero(db_echo_packet_buffer, DB_DEFAULT_DNS_PACKET_SIZE);

	int db_ping_socket = socket(_forwarder->layer3, SOCK_DGRAM, IPPROTO_UDP);
	if (unlikely(db_ping_socket == -1))
		goto out;
	if (unlikely(setsockopt(db_ping_socket, SOL_SOCKET, SO_RCVTIMEO, (const void*)&timeout, sizeof(timeout)) == -1))
		goto out;
	if (unlikely(setsockopt(db_ping_socket, SOL_SOCKET, SO_SNDTIMEO, (const void*)&timeout, sizeof(timeout)) == -1))
		goto out;

	int connect_res = -1;
	switch (_forwarder->layer3)
	{
		case PF_INET:
			connect_res = connect(db_ping_socket, (const struct sockaddr*)&_forwarder->address.address4, (socklen_t)sizeof(struct sockaddr_in));
			break;
		case PF_INET6:
			connect_res = connect(db_ping_socket, (const struct sockaddr*)&_forwarder->address.address6, (socklen_t)sizeof(struct sockaddr_in6));
			break;
		default:
			break;
	}
	if (unlikely(connect_res == -1))
		goto socket_close;

	// Ping request
	ldns_pkt* db_ping_packet = ldns_pkt_new();
	if (unlikely(!db_ping_packet))
		goto packet_free;
	ldns_pkt_set_random_id(db_ping_packet);
	ldns_pkt_set_qr(db_ping_packet, 0);
	ldns_pkt_set_opcode(db_ping_packet, LDNS_PACKET_QUERY);
	ldns_pkt_set_tc(db_ping_packet, 0);
	ldns_pkt_set_rd(db_ping_packet, 1);
	ldns_rr* db_ping_packet_rr = NULL;
	if (unlikely(ldns_rr_new_question_frm_str(&db_ping_packet_rr, _forwarder->check_query, NULL, NULL) != LDNS_STATUS_OK))
		goto packet_free;
	int db_ping_push_res = ldns_pkt_push_rr(db_ping_packet, LDNS_SECTION_QUESTION, db_ping_packet_rr);
	if (unlikely(db_ping_push_res != LDNS_STATUS_OK && db_ping_push_res != LDNS_STATUS_EMPTY_LABEL))
		goto packet_free;
	if (unlikely(!ldns_pkt2wire(&db_ping_packet_buffer, db_ping_packet, &db_ping_packet_buffer_size) == LDNS_STATUS_OK))
		goto packet_free;
	if (unlikely(send(db_ping_socket, db_ping_packet_buffer, db_ping_packet_buffer_size, 0) == -1))
		goto ping_buffer_free;
	db_hash_t hash_request = db_make_hash(db_ping_packet, db_ping_packet_rr, db_ping_socket);

	// Ping reply
	ssize_t db_echo_packet_buffer_size = recv(db_ping_socket, db_echo_packet_buffer, DB_DEFAULT_DNS_PACKET_SIZE, 0);
	if (unlikely(db_echo_packet_buffer_size == -1))
		goto hash_request_free;

	ldns_pkt* db_echo_packet = NULL;
	if (unlikely(ldns_wire2pkt(&db_echo_packet, db_echo_packet_buffer, db_echo_packet_buffer_size) != LDNS_STATUS_OK))
		goto hash_request_free;

	if (unlikely(ldns_pkt_qdcount(db_echo_packet) != 1))
		goto pkt_free;

	ldns_rr_list* db_echo_queries = ldns_pkt_question(db_echo_packet);
	size_t db_echo_queries_count = ldns_rr_list_rr_count(db_echo_queries);
	for (size_t i = 0; i < db_echo_queries_count; i++)
	{
		ldns_rr* db_echo_query = ldns_rr_list_rr(db_echo_queries, i);
		if (likely(ldns_rr_is_question(db_echo_query)))
		{
			db_hash_t hash_reply = db_make_hash(db_echo_packet, db_echo_query, db_ping_socket);
			if (likely(db_compare_hashes(&hash_request, &hash_reply)))
				ret = 1;
			db_free_hash(&hash_reply);
			break;
		}
	}

pkt_free:
	ldns_pkt_free(db_echo_packet);
hash_request_free:
	db_free_hash(&hash_request);
ping_buffer_free:
	free(db_ping_packet_buffer);
packet_free:
	ldns_pkt_free(db_ping_packet);
socket_close:
	close(db_ping_socket);
out:
	return ret;
}

static void* db_gc(void* _data)
{
	if (unlikely(!_data))
		return NULL;
	pfpthq_pool_t* pool = _data;

	for (;;)
	{
		if (unlikely(should_exit))
			break;

		struct timespec current_time;
		if (unlikely(clock_gettime(CLOCK_REALTIME, &current_time) == -1))
			panic("clock_gettime");

		// Watchdog
		for (size_t i = 0; i < frontends_count; i++)
			for (size_t j = 0; j < frontends[i]->backend.forwarders_count; j++)
			{
				int db_ping_result = db_ping_forwarder(frontends[i]->backend.forwarders[j]);
				if (unlikely(!db_ping_result))
				{
					frontends[i]->backend.forwarders[j]->fails++;
					if (unlikely(frontends[i]->backend.forwarders[j]->fails >= frontends[i]->backend.forwarders[j]->check_attempts))
					{
						if (likely(frontends[i]->backend.forwarders[j]->alive))
							verbose("%s:%s forwarder is dead\n", frontends[i]->name, frontends[i]->backend.forwarders[j]->name);
						frontends[i]->backend.forwarders[j]->fails = 0;
						frontends[i]->backend.forwarders[j]->alive = 0;
					}
				} else
				{
					if (unlikely(!frontends[i]->backend.forwarders[j]->alive))
						verbose("%s:%s forwarder is alive\n", frontends[i]->name, frontends[i]->backend.forwarders[j]->name);
					frontends[i]->backend.forwarders[j]->fails = 0;
					frontends[i]->backend.forwarders[j]->alive = 1;
				}
			}

		// Dead sockets cleaner
		struct db_item* current_item = NULL;
		struct db_item* tmp_item = NULL;
		for (size_t i = 0; i < db_hashlist.size; i++)
		{
			if (unlikely(pthread_mutex_lock(&db_hashlist.list[i].lock)))
				panic("pthread_mutex_lock");
			for (current_item = TAILQ_FIRST(&db_hashlist.list[i].items); current_item; current_item = tmp_item)
			{
				tmp_item = TAILQ_NEXT(current_item, tailq);
				int64_t diff_ns = __pfcq_timespec_diff_ns(current_item->ctime, current_time);
				if (unlikely(diff_ns >= (int64_t)db_hashlist.ttl))
					db_destroy_item_unsafe(&db_hashlist, i, current_item);
			}
			if (unlikely(pthread_mutex_unlock(&db_hashlist.list[i].lock)))
				panic("pthread_mutex_unlock");
		}

		// Hashlist loadavg calculation
		struct db_loadavg_item* new_loadavg_item = pfcq_alloc(sizeof(struct db_loadavg_item));
		new_loadavg_item->timestamp = current_time;
		if (unlikely(pthread_spin_lock(&db_hashlist.max_collisions_lock)))
			panic("pthread_spin_lock");
		new_loadavg_item->max_collisions = db_hashlist.max_collisions;
		db_hashlist.max_collisions = 0;
		if (unlikely(pthread_spin_unlock(&db_hashlist.max_collisions_lock)))
			panic("pthread_spin_unlock");
		TAILQ_INSERT_HEAD(&db_loadavg_items, new_loadavg_item, tailq);

		struct db_loadavg_item* current_loadavg_item = NULL;
		struct db_loadavg_item* tmp_loadavg_item = NULL;
		for (current_loadavg_item = TAILQ_FIRST(&db_loadavg_items); current_loadavg_item; current_loadavg_item = tmp_loadavg_item)
		{
			tmp_loadavg_item = TAILQ_NEXT(current_loadavg_item, tailq);
			int64_t diff_ns = __pfcq_timespec_diff_ns(current_loadavg_item->timestamp, current_time);
			if (unlikely(diff_ns >= DB_LOADAVG_ITEM_TTL))
			{
				TAILQ_REMOVE(&db_loadavg_items, current_loadavg_item, tailq);
				pfcq_free(current_loadavg_item);
			}
		}

		current_loadavg_item = NULL;
		size_t mc_1 = 0;
		size_t mc_5 = 0;
		size_t mc_15 = 0;
		TAILQ_FOREACH(current_loadavg_item, &db_loadavg_items, tailq)
		{
			int64_t diff_ns = __pfcq_timespec_diff_ns(current_loadavg_item->timestamp, current_time);
			if (likely(diff_ns <= DB_1_MIN_NS))
				mc_1 += current_loadavg_item->max_collisions;
			if (unlikely(diff_ns <= DB_5_MINS_NS))
				mc_5 += current_loadavg_item->max_collisions;
			if (likely(diff_ns <= DB_15_MINS_NS))
				mc_15 += current_loadavg_item->max_collisions;
		}
		if (unlikely(pthread_spin_lock(&db_loadavg.la_lock)))
			panic("pthread_spin_lock");
		db_loadavg.la_1 = (double)mc_1 / ((double)DB_1_MIN_S / db_loadavg_sampling_factor);
		db_loadavg.la_5 = (double)mc_5 / ((double)DB_5_MINS_S / db_loadavg_sampling_factor);
		db_loadavg.la_15 = (double)mc_15 / ((double)DB_15_MINS_S / db_loadavg_sampling_factor);
		if (unlikely(pthread_spin_unlock(&db_loadavg.la_lock)))
			panic("pthread_spin_unlock");

		pfcq_sleep(db_gc_interval);
	}

	pfpthq_dec(pool);

	return NULL;
}

static void* db_worker(void* _data)
{
	if (unlikely(!_data))
		return NULL;

	db_frontend_t* data = _data;
	int option = 1;
	int epoll_fd = -1;
	int epoll_count = -1;
	int server = -1;
	int forwarders[data->backend.forwarders_count];
	pfcq_fprng_context_t fprng_context;
	struct epoll_event epoll_event;
	struct epoll_event epoll_events[EPOLL_MAXEVENTS];
	sigset_t db_newmask;
	sigset_t db_oldmask;

	pfcq_zero(forwarders, data->backend.forwarders_count * sizeof(int));
	pfcq_fprng_init(&fprng_context);
	pfcq_zero(&epoll_event, sizeof(struct epoll_event));
	pfcq_zero(&epoll_events, EPOLL_MAXEVENTS * sizeof(struct epoll_event));
	pfcq_zero(&db_newmask, sizeof(sigset_t));
	pfcq_zero(&db_oldmask, sizeof(sigset_t));

	if (unlikely(sigemptyset(&db_newmask) != 0))
		panic("sigemptyset");
	if (unlikely(sigaddset(&db_newmask, SIGTERM) != 0))
		panic("sigaddset");
	if (unlikely(sigaddset(&db_newmask, SIGINT) != 0))
		panic("sigaddset");
	if (unlikely(pthread_sigmask(SIG_BLOCK, &db_newmask, &db_oldmask) != 0))
		panic("pthread_sigmask");

	server = socket(data->layer3, SOCK_DGRAM, IPPROTO_UDP);
	if (unlikely(setsockopt(server, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, (const void*)&option, sizeof(option)) == -1))
		panic("setsockopt");
	int bind_res = -1;
	switch (data->layer3)
	{
		case PF_INET:
			bind_res = bind(server, (struct sockaddr*)&data->address.address4, sizeof(struct sockaddr_in));
			break;
		case PF_INET6:
			bind_res = bind(server, (struct sockaddr*)&data->address.address6, sizeof(struct sockaddr_in6));
			break;
		default:
			break;
	}
	if (unlikely(bind_res == -1))
	{
		fail("bind");
		stop("Unable to bind to listener socket.");
	}

	// Will query forwarders from fixed UDP sockets (not to pollute Linux conntrack table)
	for (size_t i = 0; i < data->backend.forwarders_count; i++)
	{
		forwarders[i] = socket(data->backend.forwarders[i]->layer3, SOCK_DGRAM, IPPROTO_UDP);
		if (unlikely(forwarders[i] == -1))
			panic("socket");
		int connect_res = -1;
		switch (data->backend.forwarders[i]->layer3)
		{
			case PF_INET:
				connect_res = connect(forwarders[i], (const struct sockaddr*)&data->backend.forwarders[i]->address.address4, (socklen_t)sizeof(struct sockaddr_in));
				break;
			case PF_INET6:
				connect_res = connect(forwarders[i], (const struct sockaddr*)&data->backend.forwarders[i]->address.address6, (socklen_t)sizeof(struct sockaddr_in6));
				break;
			default:
				break;
		}
		if (unlikely(connect_res == -1))
			panic("connect");
	}

	epoll_fd = epoll_create1(0);
	if (unlikely(epoll_fd == -1))
		panic("epoll_create");
	epoll_event.data.fd = server;
	epoll_event.events = EPOLLIN;
	if (unlikely(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server, &epoll_event) == -1))
		panic("epoll_ctl");
	for (size_t i = 0; i < data->backend.forwarders_count; i++)
	{
		epoll_event.data.fd = forwarders[i];
		epoll_event.events = EPOLLIN;
		if (unlikely(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, forwarders[i], &epoll_event) == -1))
			panic("epoll_ctl");
	}

	for (;;)
	{
		epoll_count = epoll_pwait(epoll_fd, epoll_events, EPOLL_MAXEVENTS, -1, &db_oldmask);
		if (unlikely(epoll_count == -1))
		{
			if (likely(errno == EINTR))
			{
				if (likely(should_exit)) // Shutdown gracefully
				{
					goto lfree;
				} else
					continue;
			} else
				continue;
		} else
		{
			for (int i = 0; i < epoll_count; i++)
			{
				if (unlikely((epoll_events[i].events & EPOLLERR) ||
							(epoll_events[i].events & EPOLLHUP) ||
							!(epoll_events[i].events & EPOLLIN)))
				{
					continue;
				} else if (likely(epoll_events[i].data.fd == server))
				{
					// Accept request from client
					uint8_t server_buffer[data->dns_max_packet_length];
					pfcq_net_address_t address;
					socklen_t client_address_length;
					ssize_t query_size = -1;
					switch (data->layer3)
					{
						case PF_INET:
							client_address_length = (socklen_t)sizeof(struct sockaddr_in);
							query_size = recvfrom(server, server_buffer, data->dns_max_packet_length, 0,
									(struct sockaddr*)&address.address4, &client_address_length);
							break;
						case PF_INET6:
							client_address_length = (socklen_t)sizeof(struct sockaddr_in6);
							query_size = recvfrom(server, server_buffer, data->dns_max_packet_length, 0,
									(struct sockaddr*)&address.address6, &client_address_length);
							break;
						default:
							break;
					}
					if (unlikely(query_size == -1))
						continue;

					db_stats_frontend_in(data, query_size);

					// Find alive forwarder
					ssize_t forwarder_index = -1;
					switch (data->layer3)
					{
						case PF_INET:
							forwarder_index = db_find_alive_forwarder(data, &fprng_context, (void*)&address.address4);
							break;
						case PF_INET6:
							forwarder_index = db_find_alive_forwarder(data, &fprng_context, (void*)&address.address6);
							break;
						default:
							panic("socket domain");
					}
					if (unlikely(forwarder_index == -1))
						continue;

					// Parse request into LDNS structure
					ldns_pkt* client_query_packet = NULL;
					if (unlikely(ldns_wire2pkt(&client_query_packet, server_buffer, query_size) != LDNS_STATUS_OK))
					{
						db_stats_frontend_in_invalid(data, query_size);
						continue;
					}
					if (unlikely(ldns_pkt_qdcount(client_query_packet) != 1))
					{
						db_stats_frontend_in_invalid(data, query_size);
						ldns_pkt_free(client_query_packet);
						continue;
					}
					ldns_rr_list* client_queries = ldns_pkt_question(client_query_packet);
					size_t client_queries_count = ldns_rr_list_rr_count(client_queries);
					for (size_t j = 0; j < client_queries_count; j++)
					{
						ldns_rr* client_query = ldns_rr_list_rr(client_queries, j);
						if (likely(ldns_rr_is_question(client_query)))
						{
							// Check query against ACL
							struct db_acl_item* current_acl_item = NULL;
							db_acl_action_t query_action = DB_ACL_ACTION_ALLOW;
							TAILQ_FOREACH(current_acl_item, &data->acl, tailq)
							{
								unsigned short int address_matched = 0;
								struct in6_addr anded6;
								switch (data->layer3)
								{
									case PF_INET:
										address_matched = (unsigned short int)
											((address.address4.sin_addr.s_addr & current_acl_item->netmask.address4.s_addr) == current_acl_item->address.address4.s_addr);
										break;
									case PF_INET6:
										for (size_t k = 0; k < 16; k++)
										{
											anded6.s6_addr[k] = (uint8_t)(address.address6.sin6_addr.s6_addr[k] & current_acl_item->netmask.address6.s6_addr[k]);
											address_matched = (unsigned short int)(anded6.s6_addr[k] == current_acl_item->address.address6.s6_addr[k]);
											if (!address_matched)
												break;
										}
										break;
									default:
										panic("socket domain");
										break;
								}
								if (address_matched)
								{
									char* fqdn = ldns_rdf2str(ldns_rr_owner(client_query));
									unsigned short int regex_matched = (unsigned short int)(regexec(&current_acl_item->regex, fqdn, 0, NULL, 0) == 0);
									free(fqdn);
									if (regex_matched)
									{
										query_action = current_acl_item->action;
										if (unlikely(pthread_spin_lock(&current_acl_item->hits_lock)))
											panic("pthread_spin_lock");
										current_acl_item->hits++;
										if (unlikely(pthread_spin_unlock(&current_acl_item->hits_lock)))
											panic("pthread_spin_unlock");
										break;
									}
								}
							}
							if (query_action == DB_ACL_ACTION_DENY)
							{
								ldns_pkt_free(client_query_packet);
								goto denied;
							}

							// Make request ID from query string and DNS packet ID.
							// CRC64 hash is used to distribute requests over hash tables,
							// raw hash is used to select record from specific table
							// when answering to request
							struct db_item* new_item = pfcq_alloc(sizeof(struct db_item));
							new_item->hash = db_make_hash(client_query_packet, client_query, forwarders[forwarder_index]);
							new_item->forwarder = forwarder_index;
							switch (data->layer3)
							{
								case PF_INET:
									memcpy(&new_item->address.address4, &address.address4, sizeof(struct sockaddr_in));
									break;
								case PF_INET6:
									memcpy(&new_item->address.address6, &address.address6, sizeof(struct sockaddr_in6));
									break;
								default:
									panic("socket domain");
									break;
							}
							if (unlikely(clock_gettime(CLOCK_REALTIME, &new_item->ctime)))
								panic("clock_gettime");
							db_push_item(&db_hashlist, new_item);
							break;
						}
					}
					ldns_pkt_free(client_query_packet);

					// Forward request to forwarder
					ssize_t send_res = send(forwarders[forwarder_index], server_buffer, query_size, 0);
					if (likely(send_res != -1))
						db_stats_forwarder_in(data->backend.forwarders[forwarder_index], send_res);
denied:
					__noop;
				} else
				{
					// Accept answer from forwarder
					uint8_t backend_buffer[data->dns_max_packet_length];
					ssize_t answer_size = recv(epoll_events[i].data.fd, backend_buffer, data->dns_max_packet_length, 0);
					if (unlikely(answer_size == -1))
						continue;

					// Parse answer to LDNS structure
					ldns_pkt* backend_answer_packet = NULL;
					if (unlikely(ldns_wire2pkt(&backend_answer_packet, backend_buffer, answer_size) != LDNS_STATUS_OK))
						continue;
					if (unlikely(ldns_pkt_qdcount(backend_answer_packet) != 1))
					{
						ldns_pkt_free(backend_answer_packet);
						continue;
					}
					ldns_rr_list* backend_queries = ldns_pkt_question(backend_answer_packet);
					size_t backend_queries_count = ldns_rr_list_rr_count(backend_queries);
					for (size_t j = 0; j < backend_queries_count; j++)
					{
						ldns_rr* backend_query = ldns_rr_list_rr(backend_queries, j);
						if (likely(ldns_rr_is_question(backend_query)))
						{
							// Calculate answer ID from DNS metadata
							db_hash_t hash = db_make_hash(backend_answer_packet, backend_query, epoll_events[i].data.fd);
							// Select info from hash table
							struct db_item* found_item = db_pop_item(&db_hashlist, &hash);
							db_free_hash(&hash);
							if (likely(found_item))
							{
								ldns_pkt_rcode backend_answer_packet_rcode = ldns_pkt_get_rcode(backend_answer_packet);
								db_stats_forwarder_out(data->backend.forwarders[found_item->forwarder], answer_size, backend_answer_packet_rcode);
								// Send answer to client
								ssize_t sendto_res = -1;
								switch (data->layer3)
								{
									case PF_INET:
										sendto_res = sendto(server, backend_buffer, answer_size, 0,
												(const struct sockaddr*)&found_item->address.address4, (socklen_t)sizeof(struct sockaddr_in));
										break;
									case PF_INET6:
										sendto_res = sendto(server, backend_buffer, answer_size, 0,
												(const struct sockaddr*)&found_item->address.address6, (socklen_t)sizeof(struct sockaddr_in6));
										break;
									default:
										panic("socket domain");
										break;
								}
								db_free_hash(&found_item->hash);
								pfcq_free(found_item);
								if (likely(sendto_res != -1))
									db_stats_frontend_out(data, sendto_res, backend_answer_packet_rcode);
								break;
							}
						}
					}
					ldns_pkt_free(backend_answer_packet);
				}
			}
		}
	}

lfree:
	verbose("Exiting worker %#lx...\n", pthread_self());

	if (unlikely(pthread_sigmask(SIG_UNBLOCK, &db_newmask, NULL) != 0))
		panic("pthread_sigmask");

	if (unlikely(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, server, &epoll_event) == -1))
		panic("epoll_ctl");
	if (unlikely(close(server) == -1))
		panic("close");

	for (size_t i = 0; i < data->backend.forwarders_count; i++)
	{
		epoll_event.data.fd = forwarders[i];
		epoll_event.events = EPOLLIN;
		if (unlikely(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, forwarders[i], &epoll_event) == -1))
			panic("epoll_ctl");
		if (unlikely(close(forwarders[i]) == -1))
			panic("close");
	}

	pfpthq_dec(data->workers_pool);

	return NULL;
}

static void sigall_handler(int _signo)
{
	(void)_signo;

	if (likely(!should_exit))
		should_exit = 1;

	return;
}

int main(int argc, char** argv, char** envp)
{
	crc64speed_init();

	int opts = 0;
	int daemonize = 0;
	int be_verbose = 0;
	int do_debug = 0;
	int use_syslog = 0;
	unsigned short int stats_enabled = 0;
	sa_family_t stats_layer3_family = PF_INET;
	pfcq_net_address_t stats_address;
	pthread_t gc_id = 0;
	pfpthq_pool_t* gc_pool;
	char* pid_file = NULL;
	char* config_file = NULL;
	dictionary* config = NULL;
#ifndef MODE_DEBUG
	rlim_t limit;
	struct rlimit limits;
#endif
	struct sigaction db_sigaction;
	sigset_t db_newmask;
	sigset_t db_oldmask;

	struct option longopts[] = {
		{"config",		required_argument,	NULL, 'a'},
		{"pid-file", 	required_argument,	NULL, 'b'},
		{"daemonize",	no_argument,		NULL, 'c'},
		{"verbose",		no_argument,		NULL, 'd'},
		{"debug",		no_argument,		NULL, 'e'},
		{"syslog",		no_argument,		NULL, 'f'},
		{"help",		no_argument,		NULL, 'g'},
		{"version",		no_argument,		NULL, 'h'},
		{0, 0, 0, 0}
	};

	pfcq_zero(&stats_address, sizeof(pfcq_net_address_t));
	pfcq_zero(&db_sigaction, sizeof(struct sigaction));
	pfcq_zero(&db_newmask, sizeof(sigset_t));
	pfcq_zero(&db_oldmask, sizeof(sigset_t));

	while ((opts = getopt_long(argc, argv, "abcdef", longopts, NULL)) != -1)
		switch (opts)
		{
			case 'a':
				config_file = strdupa(optarg);
				break;
			case 'b':
				pid_file = strdupa(optarg);
				break;
			case 'c':
				daemonize = 1;
				break;
			case 'd':
				be_verbose = 1;
				break;
			case 'e':
				do_debug = 1;
				break;
			case 'f':
				use_syslog = 1;
				break;
			case 'g':
				__version();
				__usage(argv[0]);
				exit(EX_USAGE);
				break;
			case 'h':
				__version();
				exit(EX_USAGE);
				break;
			default:
				__usage(argv[0]);
				stop("Unknown option occurred.");
				break;
		}

	if (daemonize)
		if (unlikely(daemon(0, 0) != 0))
			panic("daemon");

	if (pid_file)
	{
		FILE* pid_file_hd = fopen(pid_file, "w");
		if (unlikely(!pid_file_hd))
			panic("fopen");
		if (unlikely(fprintf(pid_file_hd, "%d", getpid()) < 0))
			panic("fprintf");
		if (unlikely(fclose(pid_file_hd) == EOF))
			panic("fclose");
	}

	pfcq_debug_init(be_verbose, do_debug, use_syslog);

	if (unlikely(!config_file))
		stop("No config file specified");

	config = iniparser_load(config_file);
	if (unlikely(!config))
		stop("Unable to load config file");

	db_hashlist.size = (size_t)iniparser_getint(config, DB_CONFIG_HASHLIST_SIZE_KEY, DB_DEFAULT_HASHLIST_SIZE);
	db_hashlist.list = pfcq_alloc(db_hashlist.size * sizeof(db_hashitem_t));
	for (size_t i = 0; i < db_hashlist.size; i++)
	{
		pfcq_zero(&db_hashlist.list[i], sizeof(db_hashitem_t));
		if (unlikely(pthread_mutex_init(&db_hashlist.list[i].lock, NULL)))
			panic("pthread_mutex_init");
		TAILQ_INIT(&db_hashlist.list[i].items);
	}
	db_hashlist.max_collisions = 0;
	if (unlikely(pthread_spin_init(&db_hashlist.max_collisions_lock, PTHREAD_PROCESS_PRIVATE)))
		panic("pthread_spin_init");

	db_hashlist.ttl = ((uint64_t)iniparser_getint(config, DB_CONFIG_HASHLIST_TTL_KEY, DB_DEFAULT_HASHLIST_TTL)) * 1000000ULL;
	if (unlikely(db_hashlist.ttl > INT64_MAX))
	{
		inform("Hashlist TTL must not exceed %ld ms.\n", INT64_MAX);
		stop("Are you OK?");
	}

	TAILQ_INIT(&db_loadavg_items);

	db_gc_interval = ((uint64_t)iniparser_getint(config, DB_CONFIG_GC_INTERVAL_KEY, DB_DEFAULT_GC_INTERVAL)) * 1000000ULL;
	db_loadavg_sampling_factor = (double)db_gc_interval / (double)DB_1_SEC_NS;

	if (unlikely(pthread_spin_init(&db_loadavg.la_lock, PTHREAD_PROCESS_PRIVATE)))
		panic("pthread_spin_init");

	stats_enabled = (unsigned short int)iniparser_getint(config, DB_CONFIG_STATS_ENABLED_KEY, 0);

	if (stats_enabled)
	{
		char* stats_layer3 = iniparser_getstring(config, DB_CONFIG_STATS_LAYER3_KEY, NULL);
		if (unlikely(!stats_layer3))
			stop("No stats L3 protocol specified in config file");
		if (strcmp(stats_layer3, DB_CONFIG_IPV4) == 0)
			stats_layer3_family = PF_INET;
		else if (strcmp(stats_layer3, DB_CONFIG_IPV6) == 0)
			stats_layer3_family = PF_INET6;
		else
			stop("Unknown stats L3 protocol specified in config file");

		unsigned short int stats_port = (unsigned short int)iniparser_getint(config, DB_CONFIG_STATS_PORT_KEY, DB_DEFAULT_STATS_PORT);

		char* stats_bind = iniparser_getstring(config, DB_CONFIG_STATS_BIND_KEY, NULL);
		if (unlikely(!stats_bind))
			stop("No stats bind address specified in config file");
		int inet_pton_stats_bind_res = -1;
		switch (stats_layer3_family)
		{
			case PF_INET:
				stats_address.address4.sin_family = AF_INET;
				inet_pton_stats_bind_res = inet_pton(AF_INET, stats_bind, &stats_address.address4.sin_addr);
				stats_address.address4.sin_port = htons(stats_port);
				break;
			case PF_INET6:
				stats_address.address6.sin6_family = AF_INET6;
				inet_pton_stats_bind_res = inet_pton(AF_INET6, stats_bind, &stats_address.address6.sin6_addr);
				stats_address.address6.sin6_port = htons(stats_port);
				break;
			default:
				panic("socket domain");
				break;
		}
		if (unlikely(inet_pton_stats_bind_res != 1))
			panic("inet_pton");
	}

#ifndef MODE_DEBUG
	limit = (rlim_t)iniparser_getint(config, DB_CONFIG_RLIMIT_KEY, DB_DEFAULT_RLIMIT);

	limits.rlim_cur = limit;
	limits.rlim_max = limit;

	if (unlikely(setrlimit(RLIMIT_NOFILE, &limits) == -1))
	{
		fail("setrlimit");
		stop("Unable to set limits.");
	}
#endif

	char* frontends_str = iniparser_getstring(config, DB_CONFIG_FRONTENDS_KEY, NULL);
	if (unlikely(!frontends_str))
		stop("No frontends configured in config file");
	char* frontends_str_iterator = strdup(frontends_str);
	char* frontends_str_iterator_p = frontends_str_iterator;
	char* frontend = NULL;
	while (likely(frontend = strsep(&frontends_str_iterator, DB_CONFIG_LIST_SEPARATOR)))
	{
		if (unlikely(!frontends))
			frontends = pfcq_alloc(sizeof(db_frontend_t*));
		else
			frontends = pfcq_realloc(frontends, (frontends_count + 1) * sizeof(db_frontend_t*));
		frontends[frontends_count] = pfcq_alloc(sizeof(db_frontend_t));

		char* frontend_workers_key = pfcq_mstring("%s:%s", frontend, "workers");
		char* frontend_dns_max_packet_length_key = pfcq_mstring("%s:%s", frontend, "dns_max_packet_length");
		char* frontend_port_key = pfcq_mstring("%s:%s", frontend, "port");
		char* frontend_backend_key = pfcq_mstring("%s:%s", frontend, "backend");
		char* frontend_layer3_key = pfcq_mstring("%s:%s", frontend, "layer3");
		char* frontend_bind_key = pfcq_mstring("%s:%s", frontend, "bind");
		char* frontend_acl_key = pfcq_mstring("%s:%s", frontend, "acl");

		frontends[frontends_count]->name = pfcq_strdup(frontend);
		frontends[frontends_count]->workers = pfcq_hint_cpus((int)iniparser_getint(config, frontend_workers_key, -1));
		frontends[frontends_count]->workers_pool = pfpthq_init(frontend, frontends[frontends_count]->workers);
		frontends[frontends_count]->workers_id = pfcq_alloc(frontends[frontends_count]->workers * sizeof(pthread_t));
		frontends[frontends_count]->dns_max_packet_length = (int)iniparser_getint(config, frontend_dns_max_packet_length_key, DB_DEFAULT_DNS_PACKET_SIZE);

		char* frontend_layer3 = iniparser_getstring(config, frontend_layer3_key, NULL);
		if (unlikely(!frontend_layer3))
		{
			inform("Frontend: %s\n", frontend);
			stop("No frontend L3 protocol specified in config file");
		}
		if (strcmp(frontend_layer3, DB_CONFIG_IPV4) == 0)
			frontends[frontends_count]->layer3 = PF_INET;
		else if (strcmp(frontend_layer3, DB_CONFIG_IPV6) == 0)
			frontends[frontends_count]->layer3 = PF_INET6;
		else
		{
			inform("Frontend: %s\n", frontend);
			stop("Unknown frontend L3 protocol specified in config file");
		}

		unsigned short int frontend_port = (unsigned short int)iniparser_getint(config, frontend_port_key, DB_DEFAULT_DNS_PORT);
		char* frontend_bind = iniparser_getstring(config, frontend_bind_key, NULL);
		if (unlikely(!frontend_bind))
		{
			inform("Frontend: %s\n", frontend);
			stop("No bind address specified in config file");
		}
		int inet_pton_bind_res = -1;
		switch (frontends[frontends_count]->layer3)
		{
			case PF_INET:
				frontends[frontends_count]->address.address4.sin_family = AF_INET;
				inet_pton_bind_res = inet_pton(AF_INET, frontend_bind, &frontends[frontends_count]->address.address4.sin_addr);
				frontends[frontends_count]->address.address4.sin_port = htons(frontend_port);
				break;
			case PF_INET6:
				frontends[frontends_count]->address.address6.sin6_family = AF_INET6;
				inet_pton_bind_res = inet_pton(AF_INET6, frontend_bind, &frontends[frontends_count]->address.address6.sin6_addr);
				frontends[frontends_count]->address.address6.sin6_port = htons(frontend_port);
				break;
			default:
				panic("socket domain");
				break;
		}
		if (unlikely(inet_pton_bind_res != 1))
			panic("inet_pton");

		char* frontend_backend = iniparser_getstring(config, frontend_backend_key, NULL);
		if (unlikely(!frontend_backend))
		{
			inform("Frontend: %s\n", frontend);
			stop("No backend specified in config file");
		}

		char* backend_mode_key = pfcq_mstring("%s:%s", frontend_backend, "mode");
		char* backend_forwarders_key = pfcq_mstring("%s:%s", frontend_backend, "forwarders");

		char* backend_mode = iniparser_getstring(config, backend_mode_key, NULL);
		if (unlikely(!backend_mode))
		{
			inform("Backend: %s\n", frontend_backend);
			stop("No backend mode specified in config file");
		}
		if (likely(strcmp(backend_mode, DB_CONFIG_RR) == 0))
			frontends[frontends_count]->backend.mode = DB_BE_MODE_RR;
		else if (likely(strcmp(backend_mode, DB_CONFIG_RANDOM) == 0))
			frontends[frontends_count]->backend.mode = DB_BE_MODE_RANDOM;
		else if (likely(strcmp(backend_mode, DB_CONFIG_LEAST_PKTS) == 0))
			frontends[frontends_count]->backend.mode = DB_BE_MODE_LEAST_PKTS;
		else if (likely(strcmp(backend_mode, DB_CONFIG_LEAST_TRAFFIC) == 0))
			frontends[frontends_count]->backend.mode = DB_BE_MODE_LEAST_TRAFFIC;
		else if (likely(strcmp(backend_mode, DB_CONFIG_HASH_L3_L4) == 0))
			frontends[frontends_count]->backend.mode = DB_BE_MODE_HASH_L3_L4;
		else if (likely(strcmp(backend_mode, DB_CONFIG_HASH_L3) == 0))
			frontends[frontends_count]->backend.mode = DB_BE_MODE_HASH_L3;
		else if (likely(strcmp(backend_mode, DB_CONFIG_HASH_L4) == 0))
			frontends[frontends_count]->backend.mode = DB_BE_MODE_HASH_L4;
		else
		{
			inform("Backend: %s\n", frontend_backend);
			stop("Unknown backend mode specified in config file");
		}

		char* backend_forwarders = iniparser_getstring(config, backend_forwarders_key, NULL);
		if (unlikely(!backend_forwarders))
		{
			inform("Backend: %s\n", frontend_backend);
			stop("No forwarders specified in config file");
		}
		char* backend_forwarders_iterator = strdup(backend_forwarders);
		char* backend_forwarders_iterator_p = backend_forwarders_iterator;
		char* forwarder = NULL;
		while (likely(forwarder = strsep(&backend_forwarders_iterator, DB_CONFIG_LIST_SEPARATOR)))
		{
			if (unlikely(!frontends[frontends_count]->backend.forwarders))
				frontends[frontends_count]->backend.forwarders = pfcq_alloc(sizeof(db_forwarder_t*));
			else
				frontends[frontends_count]->backend.forwarders =
					pfcq_realloc(frontends[frontends_count]->backend.forwarders, (frontends[frontends_count]->backend.forwarders_count + 1) * sizeof(db_forwarder_t*));
			frontends[frontends_count]->backend.forwarders[frontends[frontends_count]->backend.forwarders_count] = pfcq_alloc(sizeof(db_frontend_t));

			char* forwarder_host_key = pfcq_mstring("%s:%s", forwarder, "host");
			char* forwarder_port_key = pfcq_mstring("%s:%s", forwarder, "port");
			char* forwarder_layer3_key = pfcq_mstring("%s:%s", forwarder, "layer3");
			char* forwarder_check_attempts_key = pfcq_mstring("%s:%s", forwarder, "check_attempts");
			char* forwarder_check_timeout_key = pfcq_mstring("%s:%s", forwarder, "check_timeout");
			char* forwarder_check_query_key = pfcq_mstring("%s:%s", forwarder, "check_query");
			char* forwarder_weight_key = pfcq_mstring("%s:%s", forwarder, "weight");

			char* forwarder_host = iniparser_getstring(config, forwarder_host_key, NULL);
			if (unlikely(!forwarder_host))
			{
				inform("Forwarder: %s\n", forwarder);
				stop("No forwarder host specified in config file");
			}

			char* forwarder_layer3 = iniparser_getstring(config, forwarder_layer3_key, NULL);
			if (unlikely(!forwarder_layer3))
			{
				inform("Forwarder: %s\n", forwarder);
				stop("No forwarder L3 protocol specified in config file");
			}
			if (strcmp(forwarder_layer3, DB_CONFIG_IPV4) == 0)
				frontends[frontends_count]->backend.forwarders[frontends[frontends_count]->backend.forwarders_count]->layer3 = PF_INET;
			else if (strcmp(forwarder_layer3, DB_CONFIG_IPV6) == 0)
				frontends[frontends_count]->backend.forwarders[frontends[frontends_count]->backend.forwarders_count]->layer3 = PF_INET6;
			else
			{
				inform("Forwarder: %s\n", forwarder);
				stop("Unknown forwarder L3 protocol specified in config file");
			}

			unsigned short int forwarder_port = (unsigned short int)iniparser_getint(config, forwarder_port_key, DB_DEFAULT_DNS_PORT);
			int inet_pton_res = -1;
			switch (frontends[frontends_count]->backend.forwarders[frontends[frontends_count]->backend.forwarders_count]->layer3)
			{
				case PF_INET:
					frontends[frontends_count]->backend.forwarders[frontends[frontends_count]->backend.forwarders_count]->address.address4.sin_family = AF_INET;
					frontends[frontends_count]->backend.forwarders[frontends[frontends_count]->backend.forwarders_count]->address.address4.sin_port = htons(forwarder_port);
					inet_pton_res = inet_pton(frontends[frontends_count]->backend.forwarders[frontends[frontends_count]->backend.forwarders_count]->layer3,
							forwarder_host, &(frontends[frontends_count]->backend.forwarders[frontends[frontends_count]->backend.forwarders_count]->address.address4.sin_addr));
					break;
				case PF_INET6:
					frontends[frontends_count]->backend.forwarders[frontends[frontends_count]->backend.forwarders_count]->address.address6.sin6_family = AF_INET6;
					frontends[frontends_count]->backend.forwarders[frontends[frontends_count]->backend.forwarders_count]->address.address6.sin6_port = htons(forwarder_port);
					inet_pton_res = inet_pton(frontends[frontends_count]->backend.forwarders[frontends[frontends_count]->backend.forwarders_count]->layer3,
							forwarder_host, &(frontends[frontends_count]->backend.forwarders[frontends[frontends_count]->backend.forwarders_count]->address.address6.sin6_addr));
					break;
				default:
					panic("socket domain");
					break;
			}
			if (unlikely(inet_pton_res != 1))
				panic("inet_pton");
			frontends[frontends_count]->backend.forwarders[frontends[frontends_count]->backend.forwarders_count]->name = pfcq_strdup(forwarder);

			frontends[frontends_count]->backend.forwarders[frontends[frontends_count]->backend.forwarders_count]->check_attempts =
				(size_t)iniparser_getint(config, forwarder_check_attempts_key, DB_DEFAULT_FORWARDER_CHECK_ATTEMPTS);
			frontends[frontends_count]->backend.forwarders[frontends[frontends_count]->backend.forwarders_count]->check_timeout =
				((uint64_t)iniparser_getint(config, forwarder_check_timeout_key, DB_DEFAULT_FORWARDER_CHECK_TIMEOUT)) * 1000ULL;
			char* forwarder_check_query = iniparser_getstring(config, forwarder_check_query_key, NULL);
			if (unlikely(!forwarder_check_query))
			{
				inform("Forwarder: %s\n", forwarder);
				stop("No check query specified for forwarder in config file");
			}
			frontends[frontends_count]->backend.forwarders[frontends[frontends_count]->backend.forwarders_count]->check_query =
				pfcq_strdup(forwarder_check_query);
			if (unlikely(pthread_spin_init(&frontends[frontends_count]->backend.forwarders[frontends[frontends_count]->backend.forwarders_count]->stats.in_lock,
							PTHREAD_PROCESS_PRIVATE)))
				panic("pthread_spin_init");
			if (unlikely(pthread_spin_init(&frontends[frontends_count]->backend.forwarders[frontends[frontends_count]->backend.forwarders_count]->stats.out_lock,
							PTHREAD_PROCESS_PRIVATE)))
				panic("pthread_spin_init");
			frontends[frontends_count]->backend.forwarders[frontends[frontends_count]->backend.forwarders_count]->weight =
				(uint64_t)iniparser_getint(config, forwarder_weight_key, DB_DEFAULT_WEIGHT);
			frontends[frontends_count]->backend.total_weight +=
				frontends[frontends_count]->backend.forwarders[frontends[frontends_count]->backend.forwarders_count]->weight;

			pfcq_free(forwarder_host_key);
			pfcq_free(forwarder_port_key);
			pfcq_free(forwarder_layer3_key);
			pfcq_free(forwarder_check_attempts_key);
			pfcq_free(forwarder_check_timeout_key);
			pfcq_free(forwarder_check_query_key);
			pfcq_free(forwarder_weight_key);

			frontends[frontends_count]->backend.forwarders_count++;
		}
		free(backend_forwarders_iterator_p);

		pfcq_free(backend_mode_key);
		pfcq_free(backend_forwarders_key);

		char* frontend_acl = iniparser_getstring(config, frontend_acl_key, NULL);
		if (unlikely(!frontend_acl))
		{
			inform("Frontend: %s\n", frontend);
			stop("No ACL specified in config file");
		}
		char** acl_items = iniparser_getseckeys(config, frontend_acl);
		if (unlikely(!acl_items))
		{
			inform("ACL: %s\n", frontend_acl);
			stop("No ACLs found in config file");
		}
		int acl_items_count = iniparser_getsecnkeys(config, frontend_acl);
		TAILQ_INIT(&frontends[frontends_count]->acl);
		for (int i = 0; i < acl_items_count; i++)
		{
			char* acl_item_expr = iniparser_getstring(config, acl_items[i], NULL);
			char* acl_item_expr_i = pfcq_strdup(acl_item_expr);
			char* acl_item_expr_p = acl_item_expr_i;

			char* acl_item_layer3 = strsep(&acl_item_expr, "/");
			char* acl_item_host = strsep(&acl_item_expr, "/");
			char* acl_item_netmask = strsep(&acl_item_expr, "/");
			char* acl_item_regex = strsep(&acl_item_expr, "/");
			char* acl_item_action = strsep(&acl_item_expr, "/");

			struct db_acl_item* new_acl_item = pfcq_alloc(sizeof(struct db_acl_item));

			new_acl_item->s_layer3 = pfcq_strdup(acl_item_layer3);
			new_acl_item->s_address = pfcq_strdup(acl_item_host);
			new_acl_item->s_netmask = pfcq_strdup(acl_item_netmask);
			new_acl_item->s_regex = pfcq_strdup(acl_item_regex);
			new_acl_item->s_action = pfcq_strdup(acl_item_action);
			if (unlikely(pthread_spin_init(&new_acl_item->hits_lock, PTHREAD_PROCESS_PRIVATE)))
				panic("pthread_spin_init");

			if (strcmp(acl_item_layer3, DB_CONFIG_IPV4) == 0)
				new_acl_item->layer3 = PF_INET;
			else if (strcmp(acl_item_layer3, DB_CONFIG_IPV6) == 0)
				new_acl_item->layer3 = PF_INET6;
			else
			{
				inform("ACL: %s\n", frontend_acl);
				stop("Unknown ACL L3 protocol specified in config file");
			}
			switch (new_acl_item->layer3)
			{
				case PF_INET:
					if (unlikely(inet_pton(new_acl_item->layer3, acl_item_host, &new_acl_item->address.address4) == -1))
						panic("inet_pton");
					new_acl_item->netmask.address4.s_addr = htonl((~0UL) << (32 - strtol(acl_item_netmask, NULL, 10)));
					break;
				case PF_INET6:
					if (unlikely(inet_pton(new_acl_item->layer3, acl_item_host, &new_acl_item->address.address6) == -1))
						panic("inet_pton");
					pfcq_zero(&new_acl_item->netmask.address6, sizeof(struct in6_addr));
					for (long j = 0; j < strtol(acl_item_netmask, NULL, 10); j++)
						new_acl_item->netmask.address6.s6_addr[j / 8] |= (uint8_t)(1 << (j % 8));
					break;
				default:
					panic("socket domain");
					break;
			}
			if (unlikely(regcomp(&new_acl_item->regex, acl_item_regex, REG_EXTENDED | REG_NOSUB)))
			{
				inform("ACL: %s\n", frontend_acl);
				stop("Unable to compile regex specified in config file");
			}
			if (strcmp(acl_item_action, DB_CONFIG_ACL_ACTION_ALLOW) == 0)
				new_acl_item->action = DB_ACL_ACTION_ALLOW;
			else if (strcmp(acl_item_action, DB_CONFIG_ACL_ACTION_DENY) == 0)
				new_acl_item->action = DB_ACL_ACTION_DENY;
			else
			{
				inform("ACL: %s\n", frontend_acl);
				stop("Invalid action specified in config file");
			}
			TAILQ_INSERT_TAIL(&frontends[frontends_count]->acl, new_acl_item, tailq);

			pfcq_free(acl_item_expr_p);
		}
		free(acl_items);

		pfcq_free(frontend_workers_key);
		pfcq_free(frontend_dns_max_packet_length_key);
		pfcq_free(frontend_port_key);
		pfcq_free(frontend_backend_key);
		pfcq_free(frontend_layer3_key);
		pfcq_free(frontend_bind_key);
		pfcq_free(frontend_acl_key);

		frontends_count++;
	}
	free(frontends_str_iterator_p);

	iniparser_freedict(config);

	gc_pool = pfpthq_init("gc", 1);
	pfpthq_inc(gc_pool, &gc_id, "gc", db_gc, (void*)gc_pool);

	for (size_t i = 0; i < frontends_count; i++)
	{
		if (unlikely(pthread_spin_init(&frontends[i]->backend.queries_lock, PTHREAD_PROCESS_PRIVATE)))
			panic("pthread_spin_init");
		if (unlikely(pthread_spin_init(&frontends[i]->stats.in_lock, PTHREAD_PROCESS_PRIVATE)))
			panic("pthread_spin_init");
		if (unlikely(pthread_spin_init(&frontends[i]->stats.out_lock, PTHREAD_PROCESS_PRIVATE)))
			panic("pthread_spin_init");
		if (unlikely(pthread_spin_init(&frontends[i]->stats.in_invalid_lock, PTHREAD_PROCESS_PRIVATE)))
			panic("pthread_spin_init");

		for (int j = 0; j < frontends[i]->workers; j++)
			pfpthq_inc(frontends[i]->workers_pool, &frontends[i]->workers_id[j], frontends[i]->name, db_worker, (void*)frontends[i]);
	}

	db_sigaction.sa_handler = sigall_handler;
	if (unlikely(sigemptyset(&db_sigaction.sa_mask) != 0))
		panic("sigemptyset");
	db_sigaction.sa_flags = 0;
	if (unlikely(sigaction(SIGTERM, &db_sigaction, NULL) != 0))
		panic("sigaction");
	if (unlikely(sigaction(SIGINT, &db_sigaction, NULL) != 0))
		panic("sigaction");
	if (unlikely(sigemptyset(&db_newmask) != 0))
		panic("sigemptyset");
	if (unlikely(sigaddset(&db_newmask, SIGTERM) != 0))
		panic("sigaddset");
	if (unlikely(sigaddset(&db_newmask, SIGINT) != 0))
		panic("sigaddset");
	if (unlikely(pthread_sigmask(SIG_BLOCK, &db_newmask, &db_oldmask) != 0))
		panic("pthread_sigmask");

	setproctitle_init(argc, argv, envp);
	setproctitle("Serving %u frontend(s)", frontends_count);

	db_stats_init(stats_enabled, stats_layer3_family, &stats_address);

	while (likely(!should_exit))
		sigsuspend(&db_oldmask);

	verbose("%s\n", "Got interrupt signal, attempting to exit gracefully...");

	db_stats_done();

	for (size_t i = 0; i < frontends_count; i++)
	{
		for (int j = 0; j < frontends[i]->workers; j++)
			if (unlikely(pthread_kill(frontends[i]->workers_id[j], SIGINT)))
				panic("pthread_kill");
		pfpthq_wait(frontends[i]->workers_pool);
		pfpthq_done(frontends[i]->workers_pool);
		for (size_t j = 0; j < frontends[i]->backend.forwarders_count; j++)
		{
			pfcq_free(frontends[i]->backend.forwarders[j]->name);
			pfcq_free(frontends[i]->backend.forwarders[j]->check_query);
			if (unlikely(pthread_spin_destroy(&frontends[i]->backend.forwarders[j]->stats.in_lock)))
				panic("pthread_spin_destroy");
			if (unlikely(pthread_spin_destroy(&frontends[i]->backend.forwarders[j]->stats.out_lock)))
				panic("pthread_spin_destroy");
			pfcq_free(frontends[i]->backend.forwarders[j]);
		}
		pfcq_free(frontends[i]->backend.forwarders);
		pfcq_free(frontends[i]->workers_id);
		pfcq_free(frontends[i]->name);
		if (unlikely(pthread_spin_destroy(&frontends[i]->stats.in_lock)))
			panic("pthread_spin_destroy");
		if (unlikely(pthread_spin_destroy(&frontends[i]->stats.out_lock)))
			panic("pthread_spin_destroy");
		if (unlikely(pthread_spin_destroy(&frontends[i]->stats.in_invalid_lock)))
			panic("pthread_spin_destroy");
		if (unlikely(pthread_spin_destroy(&frontends[i]->backend.queries_lock)))
			panic("pthread_spin_destroy");
		while (likely(!TAILQ_EMPTY(&frontends[i]->acl)))
		{
			struct db_acl_item* current_acl_item = TAILQ_FIRST(&frontends[i]->acl);
			TAILQ_REMOVE(&frontends[i]->acl, current_acl_item, tailq);
			pfcq_free(current_acl_item->s_layer3);
			pfcq_free(current_acl_item->s_address);
			pfcq_free(current_acl_item->s_netmask);
			pfcq_free(current_acl_item->s_regex);
			pfcq_free(current_acl_item->s_action);
			regfree(&current_acl_item->regex);
			pthread_spin_destroy(&current_acl_item->hits_lock);
			pfcq_free(current_acl_item);
		}
	}
	for (size_t i = 0; i < frontends_count; i++)
		pfcq_free(frontends[i]);
	pfcq_free(frontends);

	pfpthq_wait(gc_pool);
	pfpthq_done(gc_pool);

	if (unlikely(pthread_spin_destroy(&db_loadavg.la_lock)))
		panic("pthread_spin_destroy");

	while (likely(!TAILQ_EMPTY(&db_loadavg_items)))
	{
		struct db_loadavg_item* current_item = TAILQ_FIRST(&db_loadavg_items);
		TAILQ_REMOVE(&db_loadavg_items, current_item, tailq);
		pfcq_free(current_item);
	}

	for (size_t i = 0; i < db_hashlist.size; i++)
	{
		while (likely(!TAILQ_EMPTY(&db_hashlist.list[i].items)))
		{
			struct db_item* current_item = TAILQ_FIRST(&db_hashlist.list[i].items);
			db_destroy_item_unsafe(&db_hashlist, i, current_item);
		}
		if (unlikely(pthread_mutex_destroy(&db_hashlist.list[i].lock)))
			panic("pthread_mutex_destroy");
	}
	pfcq_free(db_hashlist.list);
	if (unlikely(pthread_spin_destroy(&db_hashlist.max_collisions_lock)))
		panic("pthread_spin_destroy");

	if (unlikely(pthread_sigmask(SIG_UNBLOCK, &db_newmask, NULL) != 0))
		panic("pthread_sigmask");

	verbose("%s\n", "Bye.");

	pfcq_debug_done();

	if (pid_file)
		if (unlikely(unlink(pid_file) == -1))
			panic("unlink");

	exit(EX_OK);
}

