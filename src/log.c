#include "includes.h"

#define MSGSIZ 1024			/* Message body */
#define TMSIZ 64			/* Timestamp */

static void log_to_file(int level, FILE* out, const char *msg);

/* 5 on-screen characters */
static const char *levels[] = {
	"EMERG", "ALERT", "CRIT ",
	"ERROR", "WARN ", "NOTE ",
	"INFO ", "DEBUG", "DBGLO"
};

/* 5 colorized on-screen characters */
static const char *clevels[] = {
	"\x1b[1;4;91mEMERG\x1b[0m",	/* bold, underlined, light red */
	"\x1b[1;4;93mALERT\x1b[0m",	/* bold, underlined, light yellow */
	"\x1b[1;96mCRIT\x1b[0m ",	/* bold, light cyan */
	"\x1b[1;91mERROR\x1b[0m",	/* bold, light red */
	"\x1b[1;95mWARN\x1b[0m ",	/* bold, light magenta */
	"\x1b[1;94mNOTE\x1b[0m ",	/* bold, light blue */
	"\x1b[1;92mINFO\x1b[0m ",	/* bold, light green */
	"DEBUG",			/* default */
	"DBGLO"
};

extern struct args_t args;
FILE *log_fs;

/**
 * Depending on the value of @out, log to a file, stdout, or stderr.
 * Messages are timestamped if logging to stdout or stderr, and additionally
 * datestamped if logging to a file.
 *
 * @level: The syslog levels from LOG_EMERG (0) to LOG_DEBUG(7),
 *	   or our own LOG_DEBUGLOW(8) level.
 * @out: A file stream, or NULL to emit to stdout (if @level is below
 *	 LOG_WARNING) or stderr (otherwise).
 * @msg: A pointer to a C string containing a message to be logged.
 *
 * Returns nothing.
 */
static void log_to_file(int level, FILE* out, const char *msg)
{
	static char *fmt = "%s.%03ld %s %s\n";
	static char buf[TMSIZ];
	static struct timespec ts;

	timespec_get(&ts, TIME_UTC);

	if (out == NULL) {
		out = level < LOG_WARNING ? stderr : stdout;
		strftime(buf, TMSIZ, "%X", localtime(&ts.tv_sec));
		fprintf(out, fmt, buf, ts.tv_nsec / 1000000,
			args.color ? clevels[level] : levels[level], msg);
	} else {
		strftime(buf, TMSIZ, "%x %X", localtime(&ts.tv_sec));
		fprintf(out, fmt, buf, ts.tv_nsec / 1000000,
			levels[level], msg);
	}
	fflush(out);
}

/**
 * Initialize program's logging facilities.
 *
 * Returns nothing.
 */
int log_init(void)
{
	if (args.syslog == 1) {
		LOG_UPTO(LOG_DEBUG);	/* handle syslog decision ourselves */
		openlog(PROGRAM, LOG_PID, args.daemon ? LOG_DAEMON : LOG_USER);
	}

	log_fs = NULL;
	if (args.logfile != NULL) {
		log_fs = fopen(args.logfile, "a");
		if (log_fs != NULL)  {
			notice("logging to '%s'", args.logfile);
		} else {
			eerr("couldn't open log file '%s': %s", args.logfile);
			return -1;
		}
	}
	return 0;
}

/**
 * Prepare program's logging facilities when daemonizing.
 *
 * Returns nothing.
 */
int log_daemonize(void)
{
	if (peapod_close_fds() == -1)
		return -1;

	args.daemon = DAEMONIZED;	/* Disable console output */

	if (peapod_redir_stdfds() == -1)
		return -1;

	if (args.logfile != NULL) {
		log_fs = fopen(args.logfile, "a");
		if (log_fs == NULL) {
			eerr("cannot reopen log file '%s': %s", args.logfile);
			return -1;
		}
	}

	return 0;
}

/**
 * Log a message. Emit the same message to stdout/stderr, a log file, and/or
 * syslog, depending on the program arguments and the value of @level.
 *
 * @level: The level of the message, which may be the syslog levels from
 *	   LOG_EMERG (0) to LOG_DEBUG(7), or our own LOG_DEBUGLOW(8) level.
 * @file: The __FILE__ macro, i.e. the source file of the call to log_msg().
 * @line: The __LINE__ macro, i.e. the line in the file of the call to log_msg().
 * @fmt, ...: printf()-style format and variable arguments.
 */
__attribute__((format (printf, 4, 5)))
void log_msg(int level, const char *file, int line, const char *fmt, ...)
{
	if (level > args.level)
		return;

	static int len;
	static char buf[MSGSIZ];
	memset(buf, 0xff, MSGSIZ);

	if (line > 0) {
		len = snprintf(buf, MSGSIZ, "%s:%d | ", file, line);
	} else {
		len = 0;
		buf[0] = '\0';
	}

	va_list vlist;
	va_start(vlist, fmt);
	len += vsnprintf(buf + len,
			 (len + 3) < MSGSIZ ? MSGSIZ - (len + 3) : 0,
			 fmt,
			 vlist);
	va_end(vlist);

	if (args.daemon != DAEMONIZED)	/* Console output is still enabled */
		log_to_file(level, NULL, buf);

	if (log_fs != NULL)
		log_to_file(level, log_fs, buf);

	if (args.syslog == 1 && level != LOG_DEBUGLOW)
		syslog(level, "<%d> %s", level, buf);


	if (len > (MSGSIZ - 4)) {
		sprintf(buf + (MSGSIZ - 4), "...");
		warning("previous message too long; %d characters were lost",
			len - (MSGSIZ - 4));
	}
}
