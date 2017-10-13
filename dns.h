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

bool ds_tsk_buf_to_pkt(struct ds_wrk_tsk* _tsk) __attribute__((warn_unused_result));
int ds_tsk_buf_parse(struct ds_wrk_ctx* _wrk_ctx,
					 struct ds_wrk_tsk* _tsk,
					 enum ds_pkt_type _pkt_type) __attribute__((warn_unused_result));
void ds_tsk_get_fwd(struct ds_wrk_tsk* _tsk, struct rb_table* _fwd_sk_set);

