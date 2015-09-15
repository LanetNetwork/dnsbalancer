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

#include <acl_local.h>
#include <bsd/unistd.h>
#include <crc64speed.h>
#include <getopt.h>
#include <hashitems.h>
#include <iniparser.h>
#include <ldns/ldns.h>
#include <local_context.h>
#include <pfcq.h>
#include <signal.h>
#include <stats.h>
#include <sys/epoll.h>
#ifndef MODE_DEBUG
#include <sys/resource.h>
#endif
#include <sysexits.h>

volatile sig_atomic_t should_exit = 0;

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

static void* db_gc(void* _data)
{
	if (unlikely(!_data))
		return NULL;
	db_global_context_t* ctx = _data;

	for (;;)
	{
		if (unlikely(should_exit))
			break;

		struct timespec current_time;
		if (unlikely(clock_gettime(CLOCK_REALTIME, &current_time) == -1))
			panic("clock_gettime");

		// Dead sockets cleaner
		struct db_item* current_item = NULL;
		struct db_item* tmp_item = NULL;
		for (size_t i = 0; i < ctx->db_hashlist.size; i++)
		{
			if (unlikely(pthread_mutex_lock(&ctx->db_hashlist.list[i].lock)))
				panic("pthread_mutex_lock");
			for (current_item = TAILQ_FIRST(&ctx->db_hashlist.list[i].items); current_item; current_item = tmp_item)
			{
				tmp_item = TAILQ_NEXT(current_item, tailq);
				int64_t diff_ns = __pfcq_timespec_diff_ns(current_item->ctime, current_time);
				if (unlikely(diff_ns >= (int64_t)ctx->db_hashlist.ttl))
					db_destroy_item_unsafe(&ctx->db_hashlist, i, current_item);
			}
			if (unlikely(pthread_mutex_unlock(&ctx->db_hashlist.list[i].lock)))
				panic("pthread_mutex_unlock");
		}

		pfcq_sleep(ctx->db_gc_interval);
	}

	pfpthq_dec(ctx->gc_pool);

	return NULL;
}

static void sigall_handler(int _signo)
{
	(void)_signo;

	if (likely(!should_exit))
		should_exit = 1;

	return;
}

int main(int argc, char** argv, char** envp)
{
	crc64speed_init();

	db_global_context_t* g_ctx = NULL;
	db_local_context_t* l_ctx = NULL;
	int opts = 0;
	int daemonize = 0;
	int be_verbose = 0;
	int do_debug = 0;
	int use_syslog = 0;
	char* pid_file = NULL;
	char* config_file = NULL;
	dictionary* config = NULL;
#ifndef MODE_DEBUG
	rlim_t limit;
	struct rlimit limits;
#endif
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

	g_ctx = pfcq_alloc(sizeof(db_global_context_t));

	config = iniparser_load(config_file);
	if (unlikely(!config))
		stop("Unable to load config file");

	g_ctx->db_hashlist.size = (size_t)iniparser_getint(config, DB_CONFIG_HASHLIST_SIZE_KEY, DB_DEFAULT_HASHLIST_SIZE);
	g_ctx->db_hashlist.list = pfcq_alloc(g_ctx->db_hashlist.size * sizeof(db_hashitem_t));
	for (size_t i = 0; i < g_ctx->db_hashlist.size; i++)
	{
		pfcq_zero(&g_ctx->db_hashlist.list[i], sizeof(db_hashitem_t));
		if (unlikely(pthread_mutex_init(&g_ctx->db_hashlist.list[i].lock, NULL)))
			panic("pthread_mutex_init");
		TAILQ_INIT(&g_ctx->db_hashlist.list[i].items);
	}

	g_ctx->db_hashlist.ttl = ((uint64_t)iniparser_getint(config, DB_CONFIG_HASHLIST_TTL_KEY, DB_DEFAULT_HASHLIST_TTL)) * 1000000ULL;
	if (unlikely(g_ctx->db_hashlist.ttl > INT64_MAX))
	{
		inform("Hashlist TTL must not exceed %ld ms.\n", INT64_MAX);
		stop("Are you OK?");
	}

	g_ctx->db_gc_interval = ((uint64_t)iniparser_getint(config, DB_CONFIG_GC_INTERVAL_KEY, DB_DEFAULT_GC_INTERVAL)) * 1000000ULL;

	iniparser_freedict(config);

	l_ctx = db_local_context_load(config_file, g_ctx);

	g_ctx->gc_pool = pfpthq_init("gc", 1);
	pfpthq_inc(g_ctx->gc_pool, &g_ctx->gc_id, "gc", db_gc, (void*)g_ctx);

	db_sigaction.sa_handler = sigall_handler;
	if (unlikely(sigemptyset(&db_sigaction.sa_mask) != 0))
		panic("sigemptyset");
	db_sigaction.sa_flags = 0;
	if (unlikely(sigaction(SIGTERM, &db_sigaction, NULL) != 0))
		panic("sigaction");
	if (unlikely(sigaction(SIGINT, &db_sigaction, NULL) != 0))
		panic("sigaction");
	if (unlikely(sigemptyset(&db_newmask) != 0))
		panic("sigemptyset");
	if (unlikely(sigaddset(&db_newmask, SIGTERM) != 0))
		panic("sigaddset");
	if (unlikely(sigaddset(&db_newmask, SIGINT) != 0))
		panic("sigaddset");
	if (unlikely(pthread_sigmask(SIG_BLOCK, &db_newmask, &db_oldmask) != 0))
		panic("pthread_sigmask");

	setproctitle_init(argc, argv, envp);
	setproctitle("Serving %u frontend(s)", l_ctx->frontends_count);

	db_stats_init(l_ctx);

	while (likely(!should_exit))
		sigsuspend(&db_oldmask);

	verbose("%s\n", "Got interrupt signal, attempting to exit gracefully...");

	db_stats_done();

	db_local_context_unload(l_ctx);
	pfpthq_wait(g_ctx->gc_pool);
	pfpthq_done(g_ctx->gc_pool);

	for (size_t i = 0; i < g_ctx->db_hashlist.size; i++)
	{
		while (likely(!TAILQ_EMPTY(&g_ctx->db_hashlist.list[i].items)))
		{
			struct db_item* current_item = TAILQ_FIRST(&g_ctx->db_hashlist.list[i].items);
			db_destroy_item_unsafe(&g_ctx->db_hashlist, i, current_item);
		}
		if (unlikely(pthread_mutex_destroy(&g_ctx->db_hashlist.list[i].lock)))
			panic("pthread_mutex_destroy");
	}
	pfcq_free(g_ctx->db_hashlist.list);

	pfcq_free(g_ctx);

	if (unlikely(pthread_sigmask(SIG_UNBLOCK, &db_newmask, NULL) != 0))
		panic("pthread_sigmask");

	verbose("%s\n", "Bye.");

	pfcq_debug_done();

	if (pid_file)
		if (unlikely(unlink(pid_file) == -1))
			panic("unlink");

	exit(EX_OK);
}

