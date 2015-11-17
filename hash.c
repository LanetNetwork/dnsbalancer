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

#include <crc64speed.h>
#include <hash.h>
#include <pfcq.h>

db_prehash_t db_make_prehash(ldns_pkt* _packet, ldns_rr* _rr, int _forwarder_socket)
{
	db_prehash_t ret;
	ldns_rdf* owner = NULL;

	ret.packet_id = ldns_pkt_id(_packet);
	ret.rr_type = ldns_rr_get_type(_rr);
	ret.rr_class = ldns_rr_get_class(_rr);
	owner = ldns_rr_owner(_rr);
	ldns_dname2canonical(owner);
	ret.fqdn = ldns_rdf2str(owner);
	ret.forwarder_socket = _forwarder_socket;

	return ret;
}

void db_free_prehash(db_prehash_t* _prehash)
{
	if (_prehash->fqdn)
	{
		pfcq_zero(_prehash->fqdn, strlen(_prehash->fqdn));
		free(_prehash->fqdn);
		_prehash->fqdn = NULL;
	}

	return;
}

db_hash_t db_make_hash(db_prehash_t* _prehash)
{
	db_hash_t ret;

	ret.uniq = pfcq_mstring("%d%u%u%u%s",
			_prehash->forwarder_socket, _prehash->packet_id, _prehash->rr_type, _prehash->rr_class, _prehash->fqdn);
	ret.crc = crc64speed(0, (uint8_t*)ret.uniq, strlen(ret.uniq));

	return ret;
}

void db_free_hash(db_hash_t* _hash)
{
	pfcq_free(_hash->uniq);

	return;
}

unsigned short int db_compare_hashes(db_hash_t* _hash1, db_hash_t* _hash2)
{
	if (_hash1->crc == _hash2->crc &&
			likely(strcmp(_hash1->uniq, _hash2->uniq) == 0))
		return 1;
	else
		return 0;
}

