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

/*
 * TODO:
 * - ACLs
 * - TCP?
 * - weighted RR distribution
 * - JSON stats over HTTP
 * - HTTP RPC
 * - https://tools.ietf.org/html/rfc7871
 */

#include <getopt.h>
#include <signal.h>
#include <sys/signalfd.h>

#include "types.h"

#include "context.h"
#include "pfcq.h"
#include "utils.h"
#include "worker.h"

#define DS_APP_NAME		"dnsbalancer"
#define DS_APP_VERSION	"0.2.0"

static void help(void)
{
	message("Usage: dnsbalancer --help | --config=<path> [--daemonize] [--verbose] [--debug]");
	message("                   [--syslog]");
	message("");
	message("  --config=<path>    specifies configuration file to use (mandatory)");
	message("  --daemonize        enables daemonization (preferred way to run on server)");
	message("  --verbose          enables verbose output");
	message("  --debug            enables debug output");
	message("                     works only if compiled with MODE=DEBUG, otherwise does nothing");
	message("  --syslog           logs everything to syslog instead of /dev/stderr");
	message("  --help             shows this help and exits");
	message("  --version          shows program version and exits");
	message("");
	message("Typical usage:");
	message("dnsbalancer --config=/etc/dnsbalancer/dnsbalancer.conf --verbose --syslog");
}

int main(int _argc, char** _argv)
{
	int opts = 0;
	int daemonize = 0;
	int be_verbose = 0;
	int do_debug = 0;
	int use_syslog = 0;
	int sfd = -1;
	char* config_file = NULL;
	sigset_t ds_sigmask;
	struct ds_ctx* ctx = NULL;
	struct ds_ctx* ctx_next = NULL;

	struct option longopts[] = {
		{"config",		required_argument,	NULL,	'a'},
		{"daemonize",	no_argument,		NULL,	'b'},
		{"verbose",		no_argument,		NULL,	'c'},
		{"debug",		no_argument,		NULL,	'd'},
		{"syslog",		no_argument,		NULL,	'e'},
		{"help",		no_argument,		NULL,	'f'},
		{"version",		no_argument,		NULL,	'g'},
		{0, 0, 0, 0}
	};

	pfcq_zero(&ds_sigmask, sizeof(sigset_t));

	while ((opts = getopt_long(_argc, _argv, "abcdefg", longopts, NULL)) != -1)
	{
		switch (opts)
		{
			case 'a':
				config_file = pfcq_strdup(optarg);
				break;
			case 'b':
				daemonize = 1;
				break;
			case 'c':
				be_verbose = 1;
				break;
			case 'd':
				do_debug = 1;
				break;
			case 'e':
				use_syslog = 1;
				break;
			case 'f':
				help();
				stop_code(EX_OK, NULL);
				break;
			case 'g':
				stop_code(EX_OK, DS_APP_NAME " v" DS_APP_VERSION);
				break;
			default:
				stop_code(EX_USAGE, "Unknown option occurred");
				break;
		}
	}

	pfcq_debug_init(be_verbose, do_debug, use_syslog);

	if (unlikely(!config_file))
		stop("No config file specified");

	if (daemonize)
		if (unlikely(daemon(0, 0) != 0))
			panic("daemon");

	sigemptyset(&ds_sigmask);
	sigaddset(&ds_sigmask, SIGTERM);
	sigaddset(&ds_sigmask, SIGINT);
	sigaddset(&ds_sigmask, SIGUSR1);
	pthread_sigmask(SIG_BLOCK, &ds_sigmask, NULL);

	sfd = signalfd(-1, &ds_sigmask, 0);
	if (unlikely(sfd == -1))
		panic("signalfd");

	// context
	ctx = ds_ctx_load(config_file);

	while (true)
	{
		struct signalfd_siginfo si;
		ssize_t res = -1;

		pfcq_zero(&si, sizeof(struct signalfd_siginfo));

		res = ds_read(sfd, &si, sizeof(struct signalfd_siginfo));
		if (unlikely(res == -1 || res != sizeof(struct signalfd_siginfo)))
			panic("ds_read");

		switch (si.ssi_signo)
		{
			case SIGINT:
			case SIGTERM:
				ds_ctx_unload(ctx);
				goto out;
			case SIGUSR1:
				ctx_next = ds_ctx_load(config_file);

				ctx->ctx_next = ctx_next;
				ctx->redirect = true;

				ds_ctx_unload(ctx);

				ctx = ctx_next;

				continue;
			default:
				panic("Unknown signal");
		}
	}

out:
	ds_close(sfd);
	pthread_sigmask(SIG_UNBLOCK, &ds_sigmask, NULL);

	verbose("%s\n", "Ciao.");

	pfcq_free(config_file);

	pfcq_debug_done();

	stop_code(EX_OK, NULL);
}
