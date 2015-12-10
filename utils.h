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

#pragma once

#ifndef __UTILS_H__
#define __UTILS_H__

#define DB_LOG2(X) ((unsigned)(CHAR_BIT * sizeof(unsigned long long) - __builtin_clzll((X)) - 1))

uint64_t db_netaddr_addr_crc64(sa_family_t _family, pfcq_net_address_t _netaddr);
uint64_t db_netaddr_port_crc64(sa_family_t _family, pfcq_net_address_t _netaddr);
ssize_t db_find_alive_forwarder(db_frontend_t* _frontend, pfcq_fprng_context_t* _fprng_context, pfcq_net_address_t _netaddr);

#endif /* __UTILS_H__ */

