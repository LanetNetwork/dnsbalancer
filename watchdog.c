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

#include <local_context.h>
#include <signal.h>
#include <watchdog.h>

extern volatile sig_atomic_t should_exit;

int db_ping_forwarder(db_forwarder_t* _forwarder)
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

void* db_watchdog(void* _data)
{
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

