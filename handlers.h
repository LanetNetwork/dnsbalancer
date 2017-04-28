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

#include "types.h"

int ds_wrk_acpt_handler(struct ds_fe_sk* _fe_sk, struct ds_wrk_ctx* _data) __attribute__((warn_unused_result));
int ds_wrk_prep_handler(int _fd, struct ds_wrk_ctx* _data) __attribute__((warn_unused_result));
int ds_wrk_fwd_handler(int _fd, struct ds_wrk_ctx* _data) __attribute__((warn_unused_result));
int ds_wrk_obt_handler(struct ds_fwd_sk* _fwd_sk, struct ds_wrk_ctx* _data) __attribute__((warn_unused_result));
int ds_wrk_rep_handler(int _fd, struct ds_wrk_ctx* _data) __attribute__((warn_unused_result));
int ds_wrk_exit_handler(int _fd, struct ds_wrk_ctx* _data) __attribute__((warn_unused_result));
int ds_wrk_gc_handler(int _fd, struct ds_wrk_ctx* _data) __attribute__((warn_unused_result));
int ds_wrk_wdt_req_handler(int _fd, struct ds_wrk_ctx* _data) __attribute__((warn_unused_result));
int ds_wrk_wdt_rep_handler(int _fd, struct ds_wrk_ctx* _data) __attribute__((warn_unused_result));
int ds_wrk_tk_handler(int _fd, struct ds_wrk_ctx* _data) __attribute__((warn_unused_result));

