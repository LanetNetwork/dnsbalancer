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

#include <crc64.h>
#include <hash.h>
#include <pfcq.h>

db_hash_t db_make_hash(ldns_pkt* _packet, ldns_rr* _rr, int _forwarder_socket)
{
	db_hash_t ret;

	ldns_rdf* domain = ldns_rr_owner(_rr);
	char* fqdn = ldns_rdf2str(domain);
	ret.uniq = pfcq_mstring("%d%u%u%u%s",
			_forwarder_socket, ldns_pkt_id(_packet), ldns_rr_get_type(_rr), ldns_rr_get_class(_rr), fqdn);
	free(fqdn);
	ret.crc = crc64((uint8_t*)ret.uniq, strlen(ret.uniq));

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

