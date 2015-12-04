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

#include <dnsbalancer.h>
#include <errno.h>
#include <global_context.h>
#include <pfcq.h>
#include <signal.h>
#include <stats.h>
#include <sys/epoll.h>
#include <utils.h>
#include <worker.h>

extern volatile sig_atomic_t should_exit;

void* db_worker(void* _data)
{
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

									// Substitute new ID to client DNS query
									*(uint16_t*)server_buffer = htons(new_id);

									// Forward new request to forwarder
									ssize_t send_res = send(forwarders[forwarder_index], server_buffer, query_size, 0);
									if (likely(send_res != -1))
										db_stats_forwarder_in(data->backend.forwarders[forwarder_index], send_res);
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
								// Substitute original request ID to response
								*(uint16_t*)backend_buffer = htons(found_request->original_id);

								ldns_pkt_rcode backend_answer_packet_rcode = ldns_pkt_get_rcode(backend_answer_packet);
								db_stats_forwarder_out(data->backend.forwarders[found_request->forwarder_index], answer_size, backend_answer_packet_rcode);
								// Send answer to client
								ssize_t sendto_res = -1;
								switch (data->layer3)
								{
									case PF_INET:
										sendto_res = sendto(server, backend_buffer, answer_size, 0,
												(const struct sockaddr*)&found_request->client_address.address4, (socklen_t)sizeof(struct sockaddr_in));
										break;
									case PF_INET6:
										sendto_res = sendto(server, backend_buffer, answer_size, 0,
												(const struct sockaddr*)&found_request->client_address.address6, (socklen_t)sizeof(struct sockaddr_in6));
										break;
									default:
										panic("socket domain");
										break;
								}
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

