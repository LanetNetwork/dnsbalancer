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

int main(int _argc, char** _argv)
{
	int opts = 0;
	int daemonize = 0;
	int be_verbose = 0;
	int do_debug = 0;
	int use_syslog = 0;
	int sfd = -1;
	char* pid_file = NULL;
	char* config_file = NULL;
	sigset_t ds_newmask;
	sigset_t ds_oldmask;
	struct ds_ctx* ctx = NULL;
	struct ds_ctx* ctx_next = NULL;

	struct option longopts[] = {
		{"config",		required_argument,	NULL,	'a'},
		{"pid-file",	required_argument,	NULL,	'b'},
		{"daemonize",	no_argument,		NULL,	'c'},
		{"verbose",		no_argument,		NULL,	'd'},
		{"debug",		no_argument,		NULL,	'e'},
		{"syslog",		no_argument,		NULL,	'f'},
		{0, 0, 0, 0}
	};

	pfcq_zero(&ds_newmask, sizeof(sigset_t));
	pfcq_zero(&ds_oldmask, sizeof(sigset_t));

	while ((opts = getopt_long(_argc, _argv, "abcdef", longopts, NULL)) != -1)
	{
		switch (opts)
		{
			case 'a':
				config_file = pfcq_strdup(optarg);
				break;
			case 'b':
				pid_file = pfcq_strdup(optarg);
				break;
			case 'c':
				daemonize = 1;
				break;
			case 'd':
				be_verbose = 1;
				break;
			case 'e':
				do_debug = 1;
				break;
			case 'f':
				use_syslog = 1;
				break;
			default:
				stop("Unknown option occurred");
				break;
		}
	}

	pfcq_debug_init(be_verbose, do_debug, use_syslog);

	if (unlikely(!config_file))
		stop("No config file specified");

	if (daemonize)
		if (unlikely(daemon(0, 0) != 0))
			panic("daemon");

	if (pid_file)
	{
		FILE* pid_file_hd = fopen(pid_file, "w");
		if (unlikely(!pid_file_hd))
			panic("fopen");
		if (unlikely(fprintf(pid_file_hd, "%d", getpid()) < 0))
			panic("fprintf");
		if (unlikely(fclose(pid_file_hd) == EOF))
			panic("fclose");
	}

	sigemptyset(&ds_newmask);
	sigaddset(&ds_newmask, SIGTERM);
	sigaddset(&ds_newmask, SIGINT);
	sigaddset(&ds_newmask, SIGUSR1);
	pthread_sigmask(SIG_BLOCK, &ds_newmask, &ds_oldmask);

	sfd = signalfd(-1, &ds_newmask, 0);
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
	pthread_sigmask(SIG_UNBLOCK, &ds_newmask, NULL);

	verbose("%s\n", "Ciao.");

	if (pid_file)
	{
		if (unlikely(unlink(pid_file) == -1))
			panic("unlink");
		pfcq_free(pid_file);
	}

	pfcq_free(config_file);

	pfcq_debug_done();

	exit(EX_OK);
}

