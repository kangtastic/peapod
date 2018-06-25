/**
 * @file args.c
 * @brief Parse command-line arguments, set up the global program arguments data
 *        structure
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <string.h>
#include <unistd.h>
#include "args.h"
#include "defaults.h"
#include "log.h"

static void print_args(void);

/** @brief An optstring for @p getopt(3) */
static char *opts = ":hdp:c:tl::svno";

/**
 * @brief An array of <tt>struct option</tt> structures for @p getopt_long(3)
 */
static struct option long_opts[] = {
	{ "help", no_argument, NULL, 'h' },
	{ "daemon", no_argument, NULL, 'd' },
	{ "pid", required_argument, NULL, 'p' },
	{ "config", required_argument, NULL, 'c' },
	{ "test", no_argument, NULL, 't' },
	{ "log", optional_argument, NULL, 'l' },
	{ "syslog", no_argument, NULL, 's' },
	/* verbosity is not a long option */
	{ "quiet-script", no_argument, NULL, 'q' },
	{ "no-color", no_argument, NULL, 'n' },
	{ "oneshot", no_argument, NULL, 'o' },
	{ NULL, 0, NULL, 0 }
};

/**
 * @brief Program arguments data structure
 * @note Global
 */
struct args_t args;

/** @brief Log the global program arguments data structure */
static void print_args(void) {
	debuglow("\targs = {");
	debuglow("\t\thelp=%u", args.help);
	debuglow("\t\tdaemon=%u", args.daemon);
	debuglow("\t\tpidfile='%s'", args.pidfile);
	debuglow("\t\tconffile='%s'", args.conffile);
	debuglow("\t\ttest=%u", args.test);
	debuglow("\t\tlevel=%u", args.level);
	debuglow("\t\tlogfile='%s'", args.logfile);
	debuglow("\t\tsyslog=%u", args.syslog);
	debuglow("\t\tcolor=%u", args.color);
	debuglow("\t\tquiet=%u", args.quiet);
	debuglow("\t\toneshot=%u", args.oneshot);
	debuglow("\t}");
}

/**
 * @brief Validate and canonicalize a path
 *
 * @param path Path to validate
 * @param create Flag: Test creating nonexistent @p path, mode 0644?
 * @return A newly allocated C string containing the canonicalized path if
 *         successful, or @p NULL if unsuccessful
 * @note If successful, caller is responsible for <tt>free(3)</tt>ing the result
 * @see @p defaults.h
 */
char *args_canonpath(const char *path, uint8_t create)
{
	/* TODO: Break this function out of args.c */
	char *rpath = realpath(path, NULL);

	if (rpath == NULL && errno == ENOENT && create != 0) {
		/* Test creating path */
		int tmp_fd = open(path, O_RDWR | O_APPEND | O_CREAT,
				  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
		if (tmp_fd > 0) {
			if ((rpath = realpath(path, NULL)) != NULL) {
				close(tmp_fd);
				unlink(rpath);
			}
		}
	}

	if (rpath != NULL) {
		/* path exists/can be created and can be canonicalized */
		char *rpath_cpy = strdup(rpath);
		free(rpath);			/* cf. realpath(3) */
		rpath = rpath_cpy;
	}

	return rpath;
}

/**
 * @brief Parse command-line arguments and set up the global program arguments
 *        data structure
 * @param argc The number of command-line arguments
 * @param argv A vector of command-line arguments
 * @return 0 if successful, or -1 if unsuccessful
 */
int args_get(int argc, char* argv[]) {
	memset(&args, 0, sizeof(struct args_t));

	args.color = 1;

	int c;
	while ((c = getopt_long(argc, argv, opts, long_opts, NULL)) != -1) {
		switch (c) {
		case 'h':
			args.help = 1;
			break;
		case 'd':
			args.daemon = 1;
			args.syslog = 1;
			break;
		case 'p':
			args.daemon = 1;
			if ((args.pidfile = args_canonpath(optarg, 1)) == NULL)
				goto abort_path;
			break;
		case 'c':
			if ((args.conffile = args_canonpath(optarg, 1)) == NULL)
				goto abort_path;
			break;
		case 't':
			args.test = 1;
			break;
		case 'l':
			/* Normally a GNU getopt optional argument requires
			 * "-l<logfile>" or "--log=<logfile>". Also allow
			 * "-l <logfile>" and "--log <logfile>".
			 */
			if (optarg == NULL && optind < argc &&
			    argv[optind] != NULL && argv[optind][0] != '\0' &&
			    argv[optind][0] != '-')
				optarg = argv[optind++];
			if (optarg == NULL)
				optarg = PEAPOD_LOG_PATH;
			if ((args.logfile = args_canonpath(optarg, 1)) == NULL)
				goto abort_path;
			break;
		case 's':
			args.syslog = 1;
			break;
		case 'v':
			if (args.level < 3)
				++args.level;
			break;
		case 'q':
			args.quiet = 1;
			break;
		case 'n':
			args.color = 0;
			break;
		case 'o':
			args.oneshot = 1;
			break;
		case ':':
			cerr("option -%c lacks required argument\n", optopt);
			goto abort_mandatory;
			break;
		case '?':
			cerr("ignoring unrecognized option -%c\n", optopt);
			break;
abort_path:
			ceerr("cannot use path '%s': %s\n", optarg);
			cerr("option -%c has invalid path argument\n", c);
			/* fallthrough */
		default:
abort_mandatory:
			cerr("error parsing command line\n");
			return -1;
			break;
		}
	}

	if(optind < argc)
		cerr("ignoring leftover arguments\n");

	if (args.conffile == NULL &&
	    (args.conffile = args_canonpath(PEAPOD_CONF_PATH, 1)) == NULL) {
		ceerr("cannot use path '%s': %s\n", PEAPOD_CONF_PATH);
		cerr("a config file is required\n");
		return -1;
	}

	if (args.daemon == 1 && args.pidfile == NULL &&
	    (args.pidfile = args_canonpath(PEAPOD_PID_PATH, 1)) == NULL) {
		ceerr("cannot use path '%s': %s\n", PEAPOD_PID_PATH);
		cerr("a PID file is required to run as a daemon\n");
		return -1;
	}

	if (args.help == 1)
		return 0;

	args.level = LOG_NOTICE + args.level;
	print_args();

	return 0;
}
