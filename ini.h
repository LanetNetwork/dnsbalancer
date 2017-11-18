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

#include <ini_config.h>

#define DS_CFG_PARTS_DELIM			"/"
#define DS_CFG_LIST_DELIM			","
#define DS_CFG_SUBLIST_DELIM		"|"
#define DS_CFG_SECTION_GENERAL		"general"
#define DS_CFG_KEY_WRKS				"wrks"
#define DS_CFG_DEFAULT_WRKS			(-1)
#define DS_CFG_KEY_REQ_TTL			"req_ttl"
#define DS_CFG_DEFAULT_REQ_TTL		5000
#define DS_CFG_KEY_GC_INTVL			"gc_intvl"
#define DS_CFG_DEFAULT_GC_INTVL		1000
#define DS_CFG_KEY_WDT_INTVL		"wdt_intvl"
#define DS_CFG_DEFAULT_WDT_INTVL	1000
#define DS_CFG_KEY_POLL_TIMEO		"poll_timeo"
#define DS_CFG_DEFAULT_POLL_TIMEO	100
#define DS_CFG_KEY_TYPE				"type"
#define DS_CFG_TYPE_FE				"fe"
#define DS_CFG_TYPE_FWD				"fwd"
#define DS_CFG_TYPE_ACT				"act"
#define DS_CFG_KEY_ADDR				"addr"
#define DS_CFG_KEY_REG_DSCP			"dscp"
#define DS_CFG_KEY_WDT_DSCP			"wdt_dscp"
#define DS_CFG_KEY_WDT_QUERY		"wdt_query"
#define DS_CFG_KEY_WDT_TRIES		"wdt_tries"
#define DS_CFG_DEFAULT_WDT_TRIES	3
#define DS_CFG_KEY_MAX_PKT_SIZE		"max_pkt_size"
#define	DS_CFG_DEFAULT_MAX_PKT_SIZE	512
#define DS_CFG_KEY_TK_INTVL			"tk_intvl"
#define DS_CFG_DEFAULT_TK_INTVL		1000
#define DS_CFG_KEY_ACTS				"acts"
#define DS_CFG_ACT_BALANCE			"balance"
#define DS_CFG_ACT_BALANCE_RR		"rr"
#define DS_CFG_ACT_BALANCE_STICKY	"sticky"

typedef struct collection_item ds_cfg_t;

ds_cfg_t* ds_cfg_open(const char*, const char*) __attribute__((warn_unused_result));
void ds_cfg_close(ds_cfg_t*);
uint64_t ds_cfg_get_u64(ds_cfg_t*, const char*, const char*, uint64_t) __attribute__((warn_unused_result));
int ds_cfg_get_int(ds_cfg_t*, const char*, const char*, int) __attribute__((warn_unused_result));
unsigned ds_cfg_get_uint(ds_cfg_t*, const char*, const char*, unsigned) __attribute__((warn_unused_result));
const char* ds_cfg_get_cstr(ds_cfg_t*, const char*, const char*) __attribute__((warn_unused_result));
const char* ds_cfg_try_get_cstr(ds_cfg_t*, const char*, const char*) __attribute__((warn_unused_result));
char** ds_cfg_get_keys(ds_cfg_t*, const char*, int*) __attribute__((warn_unused_result));
void ds_cfg_free_keys(char**);
char** ds_cfg_get_sections(ds_cfg_t*, int*) __attribute__((warn_unused_result));
void ds_cfg_free_sections(char**);

