/* vim: set tabstop=4:softtabstop=4:shiftwidth=4:noexpandtab */

/*
 * dnsbalancer - daemon to balance UDP DNS requests over DNS servers
 * Copyright (C) 2015-2016 Lanet Network
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

#ifndef __DNSBALANCER_H__
#define __DNSBALANCER_H__

#include <sys/socket.h>

#if !defined(SO_REUSEPORT)
#error "SO_REUSEPORT is undeclared (pre-3.9 Linux kernel?)"
#endif /* !defined(SO_REUSEPORT) */

#define APP_NAME							"dnsbalancer"
#define APP_VERSION							"0.0.1"
#define APP_YEAR							"2015-2016"
#define APP_HOLDER							"Lanet Network"
#define APP_PROGRAMMER						"Oleksandr Natalenko"
#define APP_EMAIL							"o.natalenko@lanet.ua"

#endif /* __DNSBALANCER_H__ */

