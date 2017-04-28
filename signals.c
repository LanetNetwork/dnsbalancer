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

#include <signal.h>

#include "pfcq.h"

#include "signals.h"

volatile sig_atomic_t should_exit = 0;
volatile sig_atomic_t should_reload = 0;

void ds_sigall_handler(int _signo)
{
	switch (_signo)
	{
		case SIGINT:
		case SIGTERM:
			if (likely(!should_exit))
				should_exit = 1;
			break;
		case SIGUSR1:
			if (likely(!should_reload))
				should_reload = 1;
			break;
		default:
			break;
	}

	return;
}

