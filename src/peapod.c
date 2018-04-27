#include "includes.h"

const char usage[] = {
"\n"
"%s - Proxy EAP Daemon\n"
"\n"
"Usage:\t%s\t[-d] [-p <pid file>] [-c <config file>] [-t]\n"
"\t\t[-l [<log file>]] [-s] [-vvv] [-n] [-h]\n"
"\n"
"Mandatory arguments for long options are mandatory for short options too.\n"
"\n"
"  -d, --daemon         run as daemon (disables console output, sets --syslog)\n"
"  -p, --pid=PATH       set PID file (default: %s)\n"
"\n"
"  -c, --config=PATH    set config file (default: %s)\n"
"  -t, --test           test config file and exit\n"
"\n"
"  -l, --log[=PATH]     output to a log file\n"
"                       (default if PATH not given: %s)\n"
"\n"
"  -s, --syslog         output to syslog\n"
"\n"
"  -v                   verbosity of output - can be specified up to 3 times\n"
"                       -v:   additionally output informational messages\n"
"                       -vv:  also output debug messages\n"
"                       -vvv: also output low-level debug messages such as data\n"
"                             structure views and EAPOL frame hexdumps to the\n"
"                             console and/or a log file (but not to syslog)\n"
"\n"
"  -q, --quiet-script   only output script execution notices with at least one -v\n"
"\n"
"  -n, --no-color       do not colorize console output\n"
"\n"
"  -o, --oneshot        do not restart proxy after certain errors occur\n"
"\n"
"  -h, --help           print this help and exit\n"
"\n"
};

static void help_exit(int status);
static void signal_handler(int sig);
int main(int argc, char *argv[]);

volatile sig_atomic_t sig_hup = 0;
volatile sig_atomic_t sig_int = 0;
volatile sig_atomic_t sig_usr1 = 0;
volatile sig_atomic_t sig_term = 0;

static char *clean_environ[] = { "PATH=" _PATH_STDPATH,	NULL };

struct iface_t *ifaces;

extern char **environ;
extern struct args_t args;

/**
 * Print usage information to stderr and exit.
 *
 * @status: The exit status to pass to the exit() system call.
 *
 * Returns nothing.
 */
static void help_exit(int status)
{
	cerr(usage, PEAPOD_PROGRAM, PEAPOD_PROGRAM, PEAPOD_PID_PATH,
	     PEAPOD_CONF_PATH, PEAPOD_LOG_PATH);
	exit(status);
}

/**
 * Increment signal counters upon receiving a signal. If more than one SIGINT
 * or SIGTERM has been received without being acted upon, abort the program.
 *
 * @sig: The signal number of the program's received signal.
 *
 * Returns nothing.
 */
static void signal_handler(int sig)
{
	switch (sig) {
	case SIGHUP:
		++sig_hup;
		break;
	case SIGINT:
		if (++sig_int > 1)
			abort();
		break;
	case SIGUSR1:
		++sig_usr1;
		break;
	case SIGTERM:
		if (++sig_term > 1)
			abort();
		break;
	default:
		break;
	}
}

/**
 * Close all open file descriptors except stdin, stdout, and stderr.
 *
 * Returns 0 if successful, or -1 if unsuccessful.
 */
int peapod_close_fds(void)
{
	for (int i = getdtablesize() - 1; i > 2; --i) {
		if (close(i) == -1 && errno != EBADF) {
			ecrit("couldn't close file descriptor %d: %s", i);
			return -1;
		}
	}
	return 0;
}

/**
 * Redirect stdin, stdout, and stderr to /dev/null.
 *
 * Returns 0 if successful, or -1 if unsuccessful.
 */
int peapod_redir_stdfds(void)
{
	int devnull = open("/dev/null", O_RDONLY, 0);
	if (devnull == -1) {
		ecrit("cannot open /dev/null readonly: %s");
		return -1;
	}
	if (dup2(devnull, STDIN_FILENO) == -1) {
		ecrit("cannot redirect stdin: %s");
		return -1;
	}
	close(devnull);

	devnull = open("/dev/null", O_WRONLY, 0);
	if (devnull == -1) {
		ecrit("cannot open /dev/null writeonly: %s");
		return -1;
	}
	if (dup2(devnull, STDOUT_FILENO) == -1) {
		ecrit("cannot redirect stdout: %s");
		return -1;
	}
	close(devnull);

	devnull = open("/dev/null", O_RDWR, 0);
	if (devnull == -1) {
		ecrit("cannot open /dev/null readwrite: %s");
		return -1;
	}
	if (dup2(devnull, STDERR_FILENO) == -1) {
		ecrit("cannot redirect stderr: %s");
		return -1;
	}
	close(devnull);

	return 0;
}

int main(int argc, char *argv[])
{

	struct sigaction sa;
	memset(&sa, 0, sizeof(struct sigaction));

	sigset_t sigmask;
	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGHUP);
	sigaddset(&sigmask, SIGINT);
	sigaddset(&sigmask, SIGUSR1);
	sigaddset(&sigmask, SIGTERM);
	if (sigprocmask(SIG_BLOCK, &sigmask, NULL) == -1) {
		cerr("cannot set signal mask");
		exit(EXIT_FAILURE);
	}

	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	if (args_get(argc, argv) == -1)
		help_exit(EXIT_FAILURE);

	if (args.help == 1)
		help_exit(EXIT_SUCCESS);

	if (args.test == 1) {
		args.level = LOG_WARNING;
		printf("test config file at '%s' and exit\n", args.conffile);
		ifaces = parse_config(args.conffile);
		printf("config file seems valid\n");
		exit(EXIT_SUCCESS);
	}

	if (log_init() == -1)
		help_exit(EXIT_FAILURE);

	ifaces = parse_config(args.conffile);

	uid_t uid = getuid();

	info("running as user %d", (int)uid);

	/* We'll probably die, but perhaps we have privileges */
	if (uid != 0)
		warning("not running as root");

	/* Sanitize the environment */
	environ = clean_environ;

	if (args.daemon == 1)
		daemonize(args.pidfile);

	debuglow("printing interface list");
	parser_print_ifaces(ifaces);

	proxy(ifaces);
}
