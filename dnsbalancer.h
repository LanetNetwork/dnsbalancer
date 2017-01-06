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

#ifndef __DNSBALANCER_H__
#define __DNSBALANCER_H__

#include <sys/socket.h>

#if !defined(SO_REUSEPORT)
#error "SO_REUSEPORT is undeclared (pre-3.9 Linux kernel?)"
#endif /* !defined(SO_REUSEPORT) */

#define APP_NAME							"dnsbalancer"
#define APP_VERSION							"0.0.2"
#define APP_YEAR							"2015-2017"
#define APP_INITIAL_HOLDER					"Lanet Network"
#define APP_PROGRAMMER						"Oleksandr Natalenko"
#define APP_EMAIL							"oleksandr@natalenko.name"

#endif /* __DNSBALANCER_H__ */

