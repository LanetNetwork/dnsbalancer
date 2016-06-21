/* vim: set tabstop=4:softtabstop=4:shiftwidth=4:noexpandtab */

/*
 * dnsbalancer - daemon to balance UDP DNS requests over DNS servers
 * Copyright (C) 2015-2016 Lanet Network
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

#include <bsd/bsd.h>
#include <getopt.h>
#include <libgen.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <unistd.h>

#include "global_context.h"
#include "local_context.h"
#include "stats.h"
#include "types.h"

#include "contrib/pfcq/pfcq.h"

#include "dnsbalancer.h"

volatile sig_atomic_t should_exit = 0;
volatile sig_atomic_t should_reload = 0;

static void __usage(char* _argv0)
{
	inform("Usage: %s --config=<filename> [--pid-file=<filename>] [--daemonize] [--verbose] [--debug] [--syslog]\n", basename(_argv0));
}

static void __version(void)
{
	inform("%s v%s\n", APP_NAME, APP_VERSION);
	inform("© %s, %s\n", APP_YEAR, APP_HOLDER);
	inform("Programmed by %s <%s>\n", APP_PROGRAMMER, APP_EMAIL);
}

static void sigall_handler(int _signo)
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

int main(int argc, char** argv, char** envp)
{
	struct db_global_context* g_ctx = NULL;
	struct db_local_context* l_ctx = NULL;
	int opts = 0;
	int daemonize = 0;
	int be_verbose = 0;
	int do_debug = 0;
	int use_syslog = 0;
	char* pid_file = NULL;
	char* config_file = NULL;
	struct sigaction db_sigaction;
	sigset_t db_newmask;
	sigset_t db_oldmask;

	struct option longopts[] = {
		{"config",		required_argument,	NULL, 'a'},
		{"pid-file", 	required_argument,	NULL, 'b'},
		{"daemonize",	no_argument,		NULL, 'c'},
		{"verbose",		no_argument,		NULL, 'd'},
		{"debug",		no_argument,		NULL, 'e'},
		{"syslog",		no_argument,		NULL, 'f'},
		{"help",		no_argument,		NULL, 'g'},
		{"version",		no_argument,		NULL, 'h'},
		{0, 0, 0, 0}
	};

	pfcq_zero(&db_sigaction, sizeof(struct sigaction));
	pfcq_zero(&db_newmask, sizeof(sigset_t));
	pfcq_zero(&db_oldmask, sizeof(sigset_t));

	while ((opts = getopt_long(argc, argv, "abcdef", longopts, NULL)) != -1)
		switch (opts)
		{
			case 'a':
				config_file = strdupa(optarg);
				break;
			case 'b':
				pid_file = strdupa(optarg);
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
			case 'g':
				__version();
				__usage(argv[0]);
				exit(EX_USAGE);
				break;
			case 'h':
				__version();
				exit(EX_USAGE);
				break;
			default:
				__usage(argv[0]);
				stop("Unknown option occurred.");
				break;
		}

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

	pfcq_debug_init(be_verbose, do_debug, use_syslog);

	if (unlikely(!config_file))
		stop("No config file specified");

	setproctitle_init(argc, argv, envp);

	for (;;)
	{
		g_ctx = db_global_context_load(config_file);
		l_ctx = db_local_context_load(config_file, g_ctx);

		db_sigaction.sa_handler = sigall_handler;
		if (unlikely(sigemptyset(&db_sigaction.sa_mask) != 0))
			panic("sigemptyset");
		db_sigaction.sa_flags = 0;
		if (unlikely(sigaction(SIGTERM, &db_sigaction, NULL) != 0))
			panic("sigaction");
		if (unlikely(sigaction(SIGINT, &db_sigaction, NULL) != 0))
			panic("sigaction");
		if (unlikely(sigaction(SIGUSR1, &db_sigaction, NULL) != 0))
			panic("sigaction");
		if (unlikely(sigemptyset(&db_newmask) != 0))
			panic("sigemptyset");
		if (unlikely(sigaddset(&db_newmask, SIGTERM) != 0))
			panic("sigaddset");
		if (unlikely(sigaddset(&db_newmask, SIGINT) != 0))
			panic("sigaddset");
		if (unlikely(sigaddset(&db_newmask, SIGUSR1) != 0))
			panic("sigaddset");
		if (unlikely(pthread_sigmask(SIG_BLOCK, &db_newmask, &db_oldmask) != 0))
			panic("pthread_sigmask");

		setproctitle("Serving %lu frontend(s)", l_ctx->frontends_count);

		db_stats_init(l_ctx);

		while (likely(!should_exit && !should_reload))
			sigsuspend(&db_oldmask);

		if (should_exit)
			verbose("%s\n", "Exit gracefully...");

		if (should_reload)
			verbose("%s\n", "Reload gracefully...");

		db_stats_done(l_ctx);

		db_local_context_unload(l_ctx);
		db_global_context_unload(g_ctx);

		if (unlikely(pthread_sigmask(SIG_UNBLOCK, &db_newmask, NULL) != 0))
			panic("pthread_sigmask");

		if (should_exit)
			break;

		if (should_reload)
			should_reload = 0;
	}

	verbose("%s\n", "Bye.");

	pfcq_debug_done();

	if (pid_file)
		if (unlikely(unlink(pid_file) == -1))
			panic("unlink");

	exit(EX_OK);
}

