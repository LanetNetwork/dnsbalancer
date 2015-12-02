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

#include <acl_local.h>
#include <crc64speed.h>
#include <iniparser.h>
#include <local_context.h>
#include <request.h>
#include <signal.h>
#include <stats.h>
#include <sys/epoll.h>
#ifndef MODE_DEBUG
#include <sys/resource.h>
#endif

extern volatile sig_atomic_t should_exit;

static uint64_t db_netaddr_addr_crc64(sa_family_t _family, pfcq_net_address_t _netaddr)
{
	uint64_t ret = 0;
	unsigned long s_addr = 0;
	const uint8_t* s_addr_buf = NULL;
	const uint8_t* s6_addr_buf = NULL;
	uint32_t* s6_addr_piece = NULL;
	uint32_t s6_addr_piece_h = 0;

	switch (_family)
	{
		case PF_INET:
			s_addr = ntohl(_netaddr.address4.sin_addr.s_addr);
			s_addr_buf = (const uint8_t*)&s_addr;
			ret = crc64speed(0, s_addr_buf, sizeof(unsigned long));
			break;
		case PF_INET6:
			for (size_t i = 0; i < sizeof(_netaddr.address6.sin6_addr.s6_addr); i += sizeof(_netaddr.address6.sin6_addr.s6_addr) / sizeof(uint32_t))
			{
				s6_addr_piece = (uint32_t*)&_netaddr.address6.sin6_addr.s6_addr[i];
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

static uint64_t db_netaddr_port_crc64(sa_family_t _family, pfcq_net_address_t _netaddr)
{
	uint64_t ret = 0;
	unsigned short u_port = 0;
	const uint8_t* u_port_buf = NULL;

	switch (_family)
	{
		case PF_INET:
			u_port = ntohs(_netaddr.address4.sin_port);
			u_port_buf = (const uint8_t*)&u_port;
			ret = crc64speed(0, u_port_buf, sizeof(unsigned short));
			break;
		case PF_INET6:
			u_port = ntohs(_netaddr.address6.sin6_port);
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

static ssize_t db_find_alive_forwarder(db_frontend_t* _frontend, pfcq_fprng_context_t* _fprng_context, pfcq_net_address_t _netaddr)
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
			crc1 = db_netaddr_addr_crc64(_frontend->layer3, _netaddr);
			crc2 = db_netaddr_port_crc64(_frontend->layer3, _netaddr);
			xor = crc1 ^ crc2;
			ret = __db_find_alive_forwarder_by_offset(xor, &_frontend->backend);
			break;
		case DB_BE_MODE_HASH_L3:
			xor = db_netaddr_addr_crc64(_frontend->layer3, _netaddr);
			ret = __db_find_alive_forwarder_by_offset(xor, &_frontend->backend);
			break;
		case DB_BE_MODE_HASH_L4:
			xor = db_netaddr_port_crc64(_frontend->layer3, _netaddr);
			ret = __db_find_alive_forwarder_by_offset(xor, &_frontend->backend);
			break;
		default:
			ret = 0;
			break;
	}

	return ret;
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
				panic("socket domain");
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
							panic("socket domain");
							break;
					}
					if (unlikely(query_size == -1))
						continue;

					db_stats_frontend_in(data, query_size);

					// Find alive forwarder
					ssize_t forwarder_index = db_find_alive_forwarder(data, &fprng_context, address);
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
							// Extract query info
							db_request_data_t request_data = db_make_request_data(client_query_packet, forwarders[forwarder_index]);

							// Check query against ACL
							switch (db_check_query_acl(data->layer3, &address, &request_data, &data->acl))
							{
								case DB_ACL_ACTION_ALLOW:
								{
									// Put all info about new request into request table
									struct db_request* new_request = db_make_request(client_query_packet, request_data, address, forwarder_index);
									// Get new request ID
									uint16_t new_id = db_insert_request(&data->g_ctx->db_requests, new_request);

									// Create new DNS query packet with substituted ID
									ldns_pkt_set_id(client_query_packet, new_id);
									uint8_t* request_buffer = NULL;
									size_t request_buffer_size = 0;
									ldns_pkt2wire(&request_buffer, client_query_packet, &request_buffer_size);

									// Forward new request to forwarder
									ssize_t send_res = send(forwarders[forwarder_index], request_buffer, request_buffer_size, 0);
									if (likely(send_res != -1))
										db_stats_forwarder_in(data->backend.forwarders[forwarder_index], send_res);
									pfcq_zero(request_buffer, request_buffer_size);
									free(request_buffer);
									request_buffer = NULL;
									break;
								}
								case DB_ACL_ACTION_DENY:
									// Silently drop request, do nothing
									break;
								case DB_ACL_ACTION_NXDOMAIN:
								{
									// Create NXDOMAIN response packet
									ldns_pkt* nxdomain_packet = ldns_pkt_new();

									ldns_pkt_set_id(nxdomain_packet, ldns_pkt_id(client_query_packet));
									ldns_pkt_set_qr(nxdomain_packet, 1);
									ldns_pkt_set_rd(nxdomain_packet, 1);
									ldns_pkt_set_ra(nxdomain_packet, 1);
									ldns_pkt_set_opcode(nxdomain_packet, LDNS_PACKET_QUERY);
									ldns_pkt_set_rcode(nxdomain_packet, LDNS_RCODE_NXDOMAIN);

									// Dup queries into NXDOMAIN response
									ldns_rr_list* nxdomain_rr_list = ldns_rr_list_clone(client_queries);
									ldns_pkt_push_rr_list(nxdomain_packet, LDNS_SECTION_QUESTION, nxdomain_rr_list);

									// Send NXDOMAIN to client
									uint8_t* nxdomain_buffer = NULL;
									size_t nxdomain_buffer_size;
									ldns_pkt2wire(&nxdomain_buffer, nxdomain_packet, &nxdomain_buffer_size);
									switch (data->layer3)
									{
										case PF_INET:
											sendto(server, nxdomain_buffer, nxdomain_buffer_size, 0,
													(const struct sockaddr*)&address.address4, (socklen_t)sizeof(struct sockaddr_in));
											break;
										case PF_INET6:
											sendto(server, nxdomain_buffer, nxdomain_buffer_size, 0,
													(const struct sockaddr*)&address.address6, (socklen_t)sizeof(struct sockaddr_in6));
											break;
										default:
											panic("socket domain");
											break;
									}

									ldns_rr_list_free(nxdomain_rr_list);
									ldns_pkt_free(nxdomain_packet);
									pfcq_zero(nxdomain_buffer, nxdomain_buffer_size);
									free(nxdomain_buffer);
									nxdomain_buffer = NULL;
									break;
								}
								case DB_ACL_ACTION_SET_A:
									// TODO: return specific A record
									break;
								default:
									panic("Unknown ACL action occurred");
									break;
							}

							// Only 1 query is processed within 1 DNS packet
							break;
						}
					}

					ldns_pkt_free(client_query_packet);
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
							// Get DNS response data
							db_request_data_t request_data = db_make_request_data(backend_answer_packet, epoll_events[i].data.fd);
							// Select request from request table
							struct db_request* found_request = db_eject_request(&data->g_ctx->db_requests, ldns_pkt_id(backend_answer_packet), request_data);
							if (likely(found_request))
							{
								// Restore original request ID
								ldns_pkt_set_id(backend_answer_packet, found_request->original_id);
								uint8_t* response_buffer = NULL;
								size_t response_buffer_size = 0;
								ldns_pkt2wire(&response_buffer, backend_answer_packet, &response_buffer_size);

								ldns_pkt_rcode backend_answer_packet_rcode = ldns_pkt_get_rcode(backend_answer_packet);
								db_stats_forwarder_out(data->backend.forwarders[found_request->forwarder_index], answer_size, backend_answer_packet_rcode);
								// Send answer to client
								ssize_t sendto_res = -1;
								switch (data->layer3)
								{
									case PF_INET:
										sendto_res = sendto(server, response_buffer, response_buffer_size, 0,
												(const struct sockaddr*)&found_request->client_address.address4, (socklen_t)sizeof(struct sockaddr_in));
										break;
									case PF_INET6:
										sendto_res = sendto(server, response_buffer, response_buffer_size, 0,
												(const struct sockaddr*)&found_request->client_address.address6, (socklen_t)sizeof(struct sockaddr_in6));
										break;
									default:
										panic("socket domain");
										break;
								}
								pfcq_zero(response_buffer, response_buffer_size);
								free(response_buffer);
								response_buffer = NULL;
								pfcq_free(found_request);
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
			panic("socket domain");
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
	db_request_data_t request_data = db_make_request_data(db_ping_packet, db_ping_socket);

	// Ping reply
	ssize_t db_echo_packet_buffer_size = recv(db_ping_socket, db_echo_packet_buffer, DB_DEFAULT_DNS_PACKET_SIZE, 0);
	if (unlikely(db_echo_packet_buffer_size == -1))
		goto ping_buffer_free;

	ldns_pkt* db_echo_packet = NULL;
	if (unlikely(ldns_wire2pkt(&db_echo_packet, db_echo_packet_buffer, db_echo_packet_buffer_size) != LDNS_STATUS_OK))
		goto ping_buffer_free;

	if (unlikely(ldns_pkt_qdcount(db_echo_packet) != 1))
		goto pkt_free;

	ldns_rr_list* db_echo_queries = ldns_pkt_question(db_echo_packet);
	size_t db_echo_queries_count = ldns_rr_list_rr_count(db_echo_queries);
	for (size_t i = 0; i < db_echo_queries_count; i++)
	{
		ldns_rr* db_echo_query = ldns_rr_list_rr(db_echo_queries, i);
		if (likely(ldns_rr_is_question(db_echo_query)))
		{
			db_request_data_t reply_data = db_make_request_data(db_echo_packet, db_ping_socket);
			if (likely(db_compare_request_data(request_data, reply_data)))
				ret = 1;
			break;
		}
	}

pkt_free:
	ldns_pkt_free(db_echo_packet);
ping_buffer_free:
	free(db_ping_packet_buffer);
packet_free:
	ldns_pkt_free(db_ping_packet);
socket_close:
	close(db_ping_socket);
out:
	return ret;
}

static void* db_watchdog(void* _data)
{
	if (unlikely(!_data))
		return NULL;
	db_local_context_t* ctx = _data;

	for (;;)
	{
		if (unlikely(should_exit))
			break;

		// Watchdog
		for (size_t i = 0; i < ctx->frontends_count; i++)
			for (size_t j = 0; j < ctx->frontends[i]->backend.forwarders_count; j++)
			{
				int db_ping_result = db_ping_forwarder(ctx->frontends[i]->backend.forwarders[j]);
				if (unlikely(!db_ping_result))
				{
					ctx->frontends[i]->backend.forwarders[j]->fails++;
					if (unlikely(ctx->frontends[i]->backend.forwarders[j]->fails >= ctx->frontends[i]->backend.forwarders[j]->check_attempts))
					{
						if (likely(ctx->frontends[i]->backend.forwarders[j]->alive))
							verbose("%s:%s forwarder is dead\n", ctx->frontends[i]->name, ctx->frontends[i]->backend.forwarders[j]->name);
						ctx->frontends[i]->backend.forwarders[j]->fails = 0;
						ctx->frontends[i]->backend.forwarders[j]->alive = 0;
					}
				} else
				{
					if (unlikely(!ctx->frontends[i]->backend.forwarders[j]->alive))
						verbose("%s:%s forwarder is alive\n", ctx->frontends[i]->name, ctx->frontends[i]->backend.forwarders[j]->name);
					ctx->frontends[i]->backend.forwarders[j]->fails = 0;
					ctx->frontends[i]->backend.forwarders[j]->alive = 1;
				}
			}
		pfcq_sleep(ctx->db_watchdog_interval);
	}

	pfpthq_dec(ctx->watchdog_pool);

	return NULL;
}

db_local_context_t* db_local_context_load(const char* _config_file, db_global_context_t* _g_ctx)
{
	db_local_context_t* ret = NULL;
	dictionary* config = NULL;
#ifndef MODE_DEBUG
	rlim_t limit;
	struct rlimit limits;
#endif

	config = iniparser_load(_config_file);
	if (unlikely(!config))
		stop("Unable to load config file");

	ret = pfcq_alloc(sizeof(db_local_context_t));

	ret->db_watchdog_interval = ((uint64_t)iniparser_getint(config, DB_CONFIG_WATCHDOG_INTERVAL_KEY, DB_DEFAULT_WATCHDOG_INTERVAL)) * 1000000ULL;

	ret->stats_enabled = (unsigned short int)iniparser_getint(config, DB_CONFIG_STATS_ENABLED_KEY, 0);

	if (ret->stats_enabled)
	{
		const char* stats_layer3 = iniparser_getstring(config, DB_CONFIG_STATS_LAYER3_KEY, NULL);
		if (unlikely(!stats_layer3))
			stop("No stats L3 protocol specified in config file");
		if (strcmp(stats_layer3, DB_CONFIG_IPV4) == 0)
			ret->stats_layer3_family = PF_INET;
		else if (strcmp(stats_layer3, DB_CONFIG_IPV6) == 0)
			ret->stats_layer3_family = PF_INET6;
		else
			stop("Unknown stats L3 protocol specified in config file");

		unsigned short int stats_port = (unsigned short int)iniparser_getint(config, DB_CONFIG_STATS_PORT_KEY, DB_DEFAULT_STATS_PORT);

		const char* stats_bind = iniparser_getstring(config, DB_CONFIG_STATS_BIND_KEY, NULL);
		if (unlikely(!stats_bind))
			stop("No stats bind address specified in config file");
		int inet_pton_stats_bind_res = -1;
		switch (ret->stats_layer3_family)
		{
			case PF_INET:
				ret->stats_address.address4.sin_family = AF_INET;
				inet_pton_stats_bind_res = inet_pton(AF_INET, stats_bind, &ret->stats_address.address4.sin_addr);
				ret->stats_address.address4.sin_port = htons(stats_port);
				break;
			case PF_INET6:
				ret->stats_address.address6.sin6_family = AF_INET6;
				inet_pton_stats_bind_res = inet_pton(AF_INET6, stats_bind, &ret->stats_address.address6.sin6_addr);
				ret->stats_address.address6.sin6_port = htons(stats_port);
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

	const char* frontends_str = iniparser_getstring(config, DB_CONFIG_FRONTENDS_KEY, NULL);
	if (unlikely(!frontends_str))
		stop("No frontends configured in config file");
	char* frontends_str_iterator = pfcq_strdup(frontends_str);
	char* frontends_str_iterator_p = frontends_str_iterator;
	char* frontend = NULL;
	while (likely(frontend = strsep(&frontends_str_iterator, DB_CONFIG_LIST_SEPARATOR)))
	{
		if (unlikely(!ret->frontends))
			ret->frontends = pfcq_alloc(sizeof(db_frontend_t*));
		else
			ret->frontends = pfcq_realloc(ret->frontends, (ret->frontends_count + 1) * sizeof(db_frontend_t*));
		ret->frontends[ret->frontends_count] = pfcq_alloc(sizeof(db_frontend_t));
		ret->frontends[ret->frontends_count]->g_ctx = _g_ctx;

		char* frontend_workers_key = pfcq_mstring("%s:%s", frontend, "workers");
		char* frontend_dns_max_packet_length_key = pfcq_mstring("%s:%s", frontend, "dns_max_packet_length");
		char* frontend_port_key = pfcq_mstring("%s:%s", frontend, "port");
		char* frontend_backend_key = pfcq_mstring("%s:%s", frontend, "backend");
		char* frontend_layer3_key = pfcq_mstring("%s:%s", frontend, "layer3");
		char* frontend_bind_key = pfcq_mstring("%s:%s", frontend, "bind");
		char* frontend_acl_key = pfcq_mstring("%s:%s", frontend, "acl");

		ret->frontends[ret->frontends_count]->name = pfcq_strdup(frontend);
		ret->frontends[ret->frontends_count]->workers = pfcq_hint_cpus((int)iniparser_getint(config, frontend_workers_key, -1));
		ret->frontends[ret->frontends_count]->workers_pool = pfpthq_init(frontend, ret->frontends[ret->frontends_count]->workers);
		ret->frontends[ret->frontends_count]->workers_id = pfcq_alloc(ret->frontends[ret->frontends_count]->workers * sizeof(pthread_t));
		ret->frontends[ret->frontends_count]->dns_max_packet_length = (int)iniparser_getint(config, frontend_dns_max_packet_length_key, DB_DEFAULT_DNS_PACKET_SIZE);

		const char* frontend_layer3 = iniparser_getstring(config, frontend_layer3_key, NULL);
		if (unlikely(!frontend_layer3))
		{
			inform("Frontend: %s\n", frontend);
			stop("No frontend L3 protocol specified in config file");
		}
		if (strcmp(frontend_layer3, DB_CONFIG_IPV4) == 0)
			ret->frontends[ret->frontends_count]->layer3 = PF_INET;
		else if (strcmp(frontend_layer3, DB_CONFIG_IPV6) == 0)
			ret->frontends[ret->frontends_count]->layer3 = PF_INET6;
		else
		{
			inform("Frontend: %s\n", frontend);
			stop("Unknown frontend L3 protocol specified in config file");
		}

		unsigned short int frontend_port = (unsigned short int)iniparser_getint(config, frontend_port_key, DB_DEFAULT_DNS_PORT);
		const char* frontend_bind = iniparser_getstring(config, frontend_bind_key, NULL);
		if (unlikely(!frontend_bind))
		{
			inform("Frontend: %s\n", frontend);
			stop("No bind address specified in config file");
		}
		int inet_pton_bind_res = -1;
		switch (ret->frontends[ret->frontends_count]->layer3)
		{
			case PF_INET:
				ret->frontends[ret->frontends_count]->address.address4.sin_family = AF_INET;
				inet_pton_bind_res = inet_pton(AF_INET, frontend_bind, &ret->frontends[ret->frontends_count]->address.address4.sin_addr);
				ret->frontends[ret->frontends_count]->address.address4.sin_port = htons(frontend_port);
				break;
			case PF_INET6:
				ret->frontends[ret->frontends_count]->address.address6.sin6_family = AF_INET6;
				inet_pton_bind_res = inet_pton(AF_INET6, frontend_bind, &ret->frontends[ret->frontends_count]->address.address6.sin6_addr);
				ret->frontends[ret->frontends_count]->address.address6.sin6_port = htons(frontend_port);
				break;
			default:
				panic("socket domain");
				break;
		}
		if (unlikely(inet_pton_bind_res != 1))
			panic("inet_pton");

		const char* frontend_backend = iniparser_getstring(config, frontend_backend_key, NULL);
		if (unlikely(!frontend_backend))
		{
			inform("Frontend: %s\n", frontend);
			stop("No backend specified in config file");
		}

		char* backend_mode_key = pfcq_mstring("%s:%s", frontend_backend, "mode");
		char* backend_forwarders_key = pfcq_mstring("%s:%s", frontend_backend, "forwarders");

		const char* backend_mode = iniparser_getstring(config, backend_mode_key, NULL);
		if (unlikely(!backend_mode))
		{
			inform("Backend: %s\n", frontend_backend);
			stop("No backend mode specified in config file");
		}
		if (likely(strcmp(backend_mode, DB_CONFIG_RR) == 0))
			ret->frontends[ret->frontends_count]->backend.mode = DB_BE_MODE_RR;
		else if (likely(strcmp(backend_mode, DB_CONFIG_RANDOM) == 0))
			ret->frontends[ret->frontends_count]->backend.mode = DB_BE_MODE_RANDOM;
		else if (likely(strcmp(backend_mode, DB_CONFIG_LEAST_PKTS) == 0))
			ret->frontends[ret->frontends_count]->backend.mode = DB_BE_MODE_LEAST_PKTS;
		else if (likely(strcmp(backend_mode, DB_CONFIG_LEAST_TRAFFIC) == 0))
			ret->frontends[ret->frontends_count]->backend.mode = DB_BE_MODE_LEAST_TRAFFIC;
		else if (likely(strcmp(backend_mode, DB_CONFIG_HASH_L3_L4) == 0))
			ret->frontends[ret->frontends_count]->backend.mode = DB_BE_MODE_HASH_L3_L4;
		else if (likely(strcmp(backend_mode, DB_CONFIG_HASH_L3) == 0))
			ret->frontends[ret->frontends_count]->backend.mode = DB_BE_MODE_HASH_L3;
		else if (likely(strcmp(backend_mode, DB_CONFIG_HASH_L4) == 0))
			ret->frontends[ret->frontends_count]->backend.mode = DB_BE_MODE_HASH_L4;
		else
		{
			inform("Backend: %s\n", frontend_backend);
			stop("Unknown backend mode specified in config file");
		}

		const char* backend_forwarders = iniparser_getstring(config, backend_forwarders_key, NULL);
		if (unlikely(!backend_forwarders))
		{
			inform("Backend: %s\n", frontend_backend);
			stop("No forwarders specified in config file");
		}
		char* backend_forwarders_iterator = pfcq_strdup(backend_forwarders);
		char* backend_forwarders_iterator_p = backend_forwarders_iterator;
		char* forwarder = NULL;
		while (likely(forwarder = strsep(&backend_forwarders_iterator, DB_CONFIG_LIST_SEPARATOR)))
		{
			if (unlikely(!ret->frontends[ret->frontends_count]->backend.forwarders))
				ret->frontends[ret->frontends_count]->backend.forwarders = pfcq_alloc(sizeof(db_forwarder_t*));
			else
				ret->frontends[ret->frontends_count]->backend.forwarders =
					pfcq_realloc(ret->frontends[ret->frontends_count]->backend.forwarders,
						(ret->frontends[ret->frontends_count]->backend.forwarders_count + 1) * sizeof(db_forwarder_t*));
			ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count] = pfcq_alloc(sizeof(db_frontend_t));

			char* forwarder_host_key = pfcq_mstring("%s:%s", forwarder, "host");
			char* forwarder_port_key = pfcq_mstring("%s:%s", forwarder, "port");
			char* forwarder_layer3_key = pfcq_mstring("%s:%s", forwarder, "layer3");
			char* forwarder_check_attempts_key = pfcq_mstring("%s:%s", forwarder, "check_attempts");
			char* forwarder_check_timeout_key = pfcq_mstring("%s:%s", forwarder, "check_timeout");
			char* forwarder_check_query_key = pfcq_mstring("%s:%s", forwarder, "check_query");
			char* forwarder_weight_key = pfcq_mstring("%s:%s", forwarder, "weight");

			const char* forwarder_host = iniparser_getstring(config, forwarder_host_key, NULL);
			if (unlikely(!forwarder_host))
			{
				inform("Forwarder: %s\n", forwarder);
				stop("No forwarder host specified in config file");
			}

			const char* forwarder_layer3 = iniparser_getstring(config, forwarder_layer3_key, NULL);
			if (unlikely(!forwarder_layer3))
			{
				inform("Forwarder: %s\n", forwarder);
				stop("No forwarder L3 protocol specified in config file");
			}
			if (strcmp(forwarder_layer3, DB_CONFIG_IPV4) == 0)
				ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->layer3 = PF_INET;
			else if (strcmp(forwarder_layer3, DB_CONFIG_IPV6) == 0)
				ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->layer3 = PF_INET6;
			else
			{
				inform("Forwarder: %s\n", forwarder);
				stop("Unknown forwarder L3 protocol specified in config file");
			}

			unsigned short int forwarder_port = (unsigned short int)iniparser_getint(config, forwarder_port_key, DB_DEFAULT_DNS_PORT);
			int inet_pton_res = -1;
			switch (ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->layer3)
			{
				case PF_INET:
					ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->address.address4.sin_family = AF_INET;
					ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->address.address4.sin_port = htons(forwarder_port);
					inet_pton_res = inet_pton(ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->layer3,
							forwarder_host, &(ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->address.address4.sin_addr));
					break;
				case PF_INET6:
					ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->address.address6.sin6_family = AF_INET6;
					ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->address.address6.sin6_port = htons(forwarder_port);
					inet_pton_res = inet_pton(ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->layer3,
							forwarder_host, &(ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->address.address6.sin6_addr));
					break;
				default:
					panic("socket domain");
					break;
			}
			if (unlikely(inet_pton_res != 1))
				panic("inet_pton");
			ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->name = pfcq_strdup(forwarder);

			ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->check_attempts =
				(size_t)iniparser_getint(config, forwarder_check_attempts_key, DB_DEFAULT_FORWARDER_CHECK_ATTEMPTS);
			ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->check_timeout =
				((uint64_t)iniparser_getint(config, forwarder_check_timeout_key, DB_DEFAULT_FORWARDER_CHECK_TIMEOUT)) * 1000ULL;
			const char* forwarder_check_query = iniparser_getstring(config, forwarder_check_query_key, NULL);
			if (unlikely(!forwarder_check_query))
			{
				inform("Forwarder: %s\n", forwarder);
				stop("No check query specified for forwarder in config file");
			}
			ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->check_query =
				pfcq_strdup(forwarder_check_query);
			if (unlikely(pthread_spin_init(&ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->stats.in_lock,
							PTHREAD_PROCESS_PRIVATE)))
				panic("pthread_spin_init");
			if (unlikely(pthread_spin_init(&ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->stats.out_lock,
							PTHREAD_PROCESS_PRIVATE)))
				panic("pthread_spin_init");
			ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->weight =
				(uint64_t)iniparser_getint(config, forwarder_weight_key, DB_DEFAULT_WEIGHT);
			ret->frontends[ret->frontends_count]->backend.total_weight +=
				ret->frontends[ret->frontends_count]->backend.forwarders[ret->frontends[ret->frontends_count]->backend.forwarders_count]->weight;

			pfcq_free(forwarder_host_key);
			pfcq_free(forwarder_port_key);
			pfcq_free(forwarder_layer3_key);
			pfcq_free(forwarder_check_attempts_key);
			pfcq_free(forwarder_check_timeout_key);
			pfcq_free(forwarder_check_query_key);
			pfcq_free(forwarder_weight_key);

			ret->frontends[ret->frontends_count]->backend.forwarders_count++;
		}
		pfcq_free(backend_forwarders_iterator_p);

		pfcq_free(backend_mode_key);
		pfcq_free(backend_forwarders_key);

#ifdef DB_INIPARSER4
		const char* frontend_acl = NULL;
#else /* DB_INIPARSER4 */
		char* frontend_acl = NULL;
#endif /* DB_INIPARSER4 */
		frontend_acl = iniparser_getstring(config, frontend_acl_key, NULL);
		if (unlikely(!frontend_acl))
		{
			inform("Frontend: %s\n", frontend);
			stop("No ACL specified in config file");
		}
		char* frontend_acl_i = pfcq_strdup(frontend_acl);
		char* frontend_acl_p = frontend_acl_i;
		char* frontend_acl_source = strsep(&frontend_acl_i, DB_CONFIG_PARAMETERS_SEPARATOR);

		if (strcmp(frontend_acl_source, DB_CONFIG_ACL_SOURCE_LOCAL) == 0)
		{
			char* frontend_acl_name = strsep(&frontend_acl_i, DB_CONFIG_PARAMETERS_SEPARATOR);
			ret->frontends[ret->frontends_count]->acl_source = DB_ACL_SOURCE_LOCAL;
			db_acl_local_load(config, frontend_acl_name, &ret->frontends[ret->frontends_count]->acl);
		} else if (strcmp(frontend_acl_source, DB_CONFIG_ACL_SOURCE_MYSQL) == 0)
		{
			ret->frontends[ret->frontends_count]->acl_source = DB_ACL_SOURCE_MYSQL;
			panic("Not implemented");
		} else
		{
			inform("Frontend: %s\n", frontend);
			stop("Unknown ACL source specified in config file");
		}

		pfcq_free(frontend_acl_p);

		pfcq_free(frontend_workers_key);
		pfcq_free(frontend_dns_max_packet_length_key);
		pfcq_free(frontend_port_key);
		pfcq_free(frontend_backend_key);
		pfcq_free(frontend_layer3_key);
		pfcq_free(frontend_bind_key);
		pfcq_free(frontend_acl_key);

		ret->frontends_count++;
	}
	pfcq_free(frontends_str_iterator_p);

	iniparser_freedict(config);

	ret->watchdog_pool = pfpthq_init("watchdog", 1);
	pfpthq_inc(ret->watchdog_pool, &ret->watchdog_id, "watchdog", db_watchdog, (void*)ret);

	for (size_t i = 0; i < ret->frontends_count; i++)
	{
		if (unlikely(pthread_spin_init(&ret->frontends[i]->backend.queries_lock, PTHREAD_PROCESS_PRIVATE)))
			panic("pthread_spin_init");
		if (unlikely(pthread_spin_init(&ret->frontends[i]->stats.in_lock, PTHREAD_PROCESS_PRIVATE)))
			panic("pthread_spin_init");
		if (unlikely(pthread_spin_init(&ret->frontends[i]->stats.out_lock, PTHREAD_PROCESS_PRIVATE)))
			panic("pthread_spin_init");
		if (unlikely(pthread_spin_init(&ret->frontends[i]->stats.in_invalid_lock, PTHREAD_PROCESS_PRIVATE)))
			panic("pthread_spin_init");

		for (int j = 0; j < ret->frontends[i]->workers; j++)
			pfpthq_inc(ret->frontends[i]->workers_pool, &ret->frontends[i]->workers_id[j], ret->frontends[i]->name, db_worker, (void*)ret->frontends[i]);
	}

	return ret;
}

void db_local_context_unload(db_local_context_t* _l_ctx)
{
	for (size_t i = 0; i < _l_ctx->frontends_count; i++)
	{
		for (int j = 0; j < _l_ctx->frontends[i]->workers; j++)
			if (unlikely(pthread_kill(_l_ctx->frontends[i]->workers_id[j], SIGINT)))
				panic("pthread_kill");
		pfpthq_wait(_l_ctx->frontends[i]->workers_pool);
		pfpthq_done(_l_ctx->frontends[i]->workers_pool);
		for (size_t j = 0; j < _l_ctx->frontends[i]->backend.forwarders_count; j++)
		{
			pfcq_free(_l_ctx->frontends[i]->backend.forwarders[j]->name);
			pfcq_free(_l_ctx->frontends[i]->backend.forwarders[j]->check_query);
			if (unlikely(pthread_spin_destroy(&_l_ctx->frontends[i]->backend.forwarders[j]->stats.in_lock)))
				panic("pthread_spin_destroy");
			if (unlikely(pthread_spin_destroy(&_l_ctx->frontends[i]->backend.forwarders[j]->stats.out_lock)))
				panic("pthread_spin_destroy");
			pfcq_free(_l_ctx->frontends[i]->backend.forwarders[j]);
		}
		pfcq_free(_l_ctx->frontends[i]->backend.forwarders);
		pfcq_free(_l_ctx->frontends[i]->workers_id);
		pfcq_free(_l_ctx->frontends[i]->name);
		if (unlikely(pthread_spin_destroy(&_l_ctx->frontends[i]->stats.in_lock)))
			panic("pthread_spin_destroy");
		if (unlikely(pthread_spin_destroy(&_l_ctx->frontends[i]->stats.out_lock)))
			panic("pthread_spin_destroy");
		if (unlikely(pthread_spin_destroy(&_l_ctx->frontends[i]->stats.in_invalid_lock)))
			panic("pthread_spin_destroy");
		if (unlikely(pthread_spin_destroy(&_l_ctx->frontends[i]->backend.queries_lock)))
			panic("pthread_spin_destroy");
		switch (_l_ctx->frontends[i]->acl_source)
		{
			case DB_ACL_SOURCE_LOCAL:
				db_acl_local_unload(&_l_ctx->frontends[i]->acl);
				break;
			case DB_ACL_SOURCE_MYSQL:
				panic("Not implemented");
				break;
			default:
				panic("Unknown source");
				break;
		}
	}
	for (size_t i = 0; i < _l_ctx->frontends_count; i++)
		pfcq_free(_l_ctx->frontends[i]);
	pfcq_free(_l_ctx->frontends);

	pfpthq_wait(_l_ctx->watchdog_pool);
	pfpthq_done(_l_ctx->watchdog_pool);

	pfcq_free(_l_ctx);

	return;
}

