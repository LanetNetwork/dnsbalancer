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

#include "pfcq.h"
#include "utils.h"

#include "dns.h"

bool ds_tsk_buf_to_pkt(struct ds_wrk_tsk* _tsk)
{
	if (unlikely(ldns_wire2pkt(&_tsk->pkt, (const uint8_t*)_tsk->buf, _tsk->buf_size) != LDNS_STATUS_OK))
		return false;

	return true;
}

int ds_tsk_buf_parse(struct ds_wrk_ctx* _wrk_ctx, struct ds_wrk_tsk* _tsk, enum ds_pkt_type _pkt_type)
{
	char* owner_str = NULL;
	ldns_rr* rr = NULL;
	ldns_rdf* owner = NULL;
	struct ds_fwd* fwd = NULL;

	rr = ldns_rr_list_rr(ldns_pkt_question(_tsk->pkt), 0);
	_tsk->rr_type = ldns_rr_get_type(rr);
	_tsk->rr_class = ldns_rr_get_class(rr);
	owner = ldns_rr_owner(rr);
	ldns_dname2canonical(owner);
	owner_str = ldns_rdf2str(owner);
	strncpy(_tsk->fqdn, owner_str, HOST_NAME_MAX);
	free(owner_str);

	switch (_pkt_type)
	{
		case DS_PKT_REQ:
			_tsk->orig_id = htons(ldns_pkt_id(_tsk->pkt));
			switch (_tsk->type)
			{
				case DS_TSK_REG:
					fwd = _tsk->fe_fwd->fwd;
					break;
				case DS_TSK_WDT:
					fwd = _tsk->fwd_sk->fwd;
					break;
				default:
					panic("Unknown task type");
					break;
			}
			_tsk->subst_id = htons(pfcq_counter_get_inc_mod(&fwd->c_q_id, UINT16_MAX + 1, 1));
			memcpy(_tsk->buf, &_tsk->subst_id, sizeof(uint16_t));
			pfcq_counter_init(&_tsk->epoch);
			pfcq_counter_set(&_tsk->epoch, pfcq_counter_get(&_wrk_ctx->ctx->epoch));
			break;
		case DS_PKT_REP:
			_tsk->subst_id = htons(ldns_pkt_id(_tsk->pkt));
			break;
		default:
			panic("Unknown packet type");
			break;
	}

	return 0;
}

void ds_tsk_get_fwd(struct ds_wrk_tsk* _tsk, struct rb_table* _fwd_sk_set)
{
	struct ds_fe_fwd* fe_fwd = NULL;
	struct rb_traverser iter;
	struct ds_fwd_sk* cur_fwd_sk = NULL;
	size_t tries = 0;
	size_t tip = 0;

	switch (_tsk->orig_fe_sk->fe->fwd_mode)
	{
		case DS_FWD_RR:
			while (likely(tries++ < _tsk->orig_fe_sk->fe->nfefwds))
			{
				int index = pfcq_counter_get_inc_mod(&_tsk->orig_fe_sk->fe->c_fwd,
											   _tsk->orig_fe_sk->fe->nfefwds, 0);
				fe_fwd = &_tsk->orig_fe_sk->fe->fe_fwds[index];
				if (likely(fe_fwd->fwd->alive))
					break;
			}
			break;
		case DS_FWD_STICKY:
			tip = (size_t)(ds_hash_address(&_tsk->addr) % _tsk->orig_fe_sk->fe->nfefwds);
			while (likely(tries++ < _tsk->orig_fe_sk->fe->nfefwds))
			{
				int index = tip++ % _tsk->orig_fe_sk->fe->nfefwds;
				fe_fwd = &_tsk->orig_fe_sk->fe->fe_fwds[index];
				if (likely(fe_fwd->fwd->alive))
					break;
			}
			break;
		default:
			panic("Unknown forwarding mode");
			break;
	}

	if (!fe_fwd)
		return;

	_tsk->fe_fwd = fe_fwd;

	rb_t_init(&iter, _fwd_sk_set);
	cur_fwd_sk = rb_t_first(&iter, _fwd_sk_set);
	do {
		if (cur_fwd_sk->fwd == _tsk->fe_fwd->fwd)
		{
			_tsk->fwd_sk = cur_fwd_sk;
			break;
		}
	} while (likely((cur_fwd_sk = rb_t_next(&iter)) != NULL));
	_tsk->fwd_sk_addr = _tsk->fwd_sk->fwd->addr;

	return;
}

