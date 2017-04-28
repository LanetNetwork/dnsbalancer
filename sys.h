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

#ifdef DS_HAVE_ATOMICS
#include <stdatomic.h>
#else /* DS_HAVE_ATOMICS */
#include <atomic_ops.h>
#endif /* DS_HAVE_ATOMICS */

#include <sys/epoll.h>
#ifndef DS_HAVE_UAPI_EPOLLEXCLUSIVE
#define EPOLLEXCLUSIVE (1u << 28)
#endif /* DS_HAVE_UAPI_EPOLLEXCLUSIVE */

#ifndef DS_HAVE_UAPI_SO_REUSEPORT
#define SO_REUSEPORT 15
#endif /* DS_HAVE_UAPI_SO_REUSEPORT */

