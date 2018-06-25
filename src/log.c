/**
 * @file log.c
 * @brief Logging operations
 */
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include "args.h"
#include "defaults.h"
#include "log.h"
#include "peapod.h"

#define DAEMONIZED	2		/**< @brief Console output disabled */
#define MSGSIZ		1024		/**< @brief Log message buffer size */
#define TMSIZ		64		/**< @brief Timestamp buffer size */

static void log_to_file(const char *msg, int level, FILE* out);

/**
 * @name Log level descriptions
 * @{
 */
/**
 * @brief Five on-screen characters
 *
 * Used for emitting logs to syslog or to a log file.
 */
static const char *levels[] = {
	"EMERG", "ALERT", "CRIT ",
	"ERROR", "WARN ", "NOTE ",
	"INFO ", "DEBUG", "DBGLO"
};

/**
 * @brief Five colorized on-screen characters
 *
 * Used for emitting logs to the console (@p stdout / @p stderr).
 */
static const char *clevels[] = {
	"\x1b[1;4;91mEMERG\x1b[0m",	/* bold, underlined, light red */
	"\x1b[1;4;93mALERT\x1b[0m",	/* bold, underlined, light yellow */
	"\x1b[1;96mCRIT\x1b[0m ",	/* bold, light cyan */
	"\x1b[1;91mERROR\x1b[0m",	/* bold, light red */
	"\x1b[1;95mWARN\x1b[0m ",	/* bold, light magenta */
	"\x1b[1;94mNOTE\x1b[0m ",	/* bold, light blue */
	"\x1b[1;92mINFO\x1b[0m ",	/* bold, light green */
	"DEBUG",			/* default (not colorized) */
	"DBGLO"
};
/** @} */

FILE *log_fs;				/**< @brief Log file */
static char log_buf[MSGSIZ];		/**< @brief Log message buffer */
static char log_tm[TMSIZ];		/**< @brief Timestamp buffer */
extern struct args_t args;

/**
 * @brief Log a message to a file or to the console
 *
 * Messages are timestamped if logging to the console.
 * Messages are additionally datestamped if logging to a file.
 *
 * @param msg A message to be logged
 * @param level The level of the message
 * @param out File stream of log file, or @p NULL to emit to the console
 * @note @p level may be the @p syslog levels (@p LOG_EMERG to @p LOG_DEBUG,
 *       i.e. 0 to 7), or our own @p LOG_DEBUGLOW (8). <br />
 *       Output to console emits to @p stderr if @p level is below
 *       @p LOG_WARNING, and to @p stdout otherwise.
 */
static void log_to_file(const char *msg, int level, FILE* out)
{
	static struct timespec ts;
	const char *fmt;
	const char *desc;

	timespec_get(&ts, TIME_UTC);

	if (out == NULL) {
		out = level < LOG_WARNING ? stderr : stdout;
		fmt = "%X";
		desc = args.color ? clevels[level] : levels[level];
	} else {
		fmt = "%c";
		desc = levels[level];

	}

	strftime(log_tm, TMSIZ, fmt, localtime(&ts.tv_sec));
	fprintf(out, "%s.%.03ld %s %s\n",
		log_tm, ts.tv_nsec / 1000000, desc, msg);
	fflush(out);
}

/**
 * @brief Initialize logging
 * @return 0 if successful, or -1 if unsuccessful
 */
int log_init(void)
{
	log_fs = NULL;
	memset(log_buf, '\0', MSGSIZ);
	memset(log_tm, '\0', TMSIZ);

	if (args.syslog == 1) {
		/* handle syslog decision ourselves */
		setlogmask(LOG_UPTO(LOG_DEBUG));

		openlog(PEAPOD_PROGRAM, LOG_PID,
			args.daemon ? LOG_DAEMON : LOG_USER);
	}

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
 * @brief Prepare logging when daemonizing
 * @return 0 if successful, or -1 if unsuccessful
 */
int log_daemonize(void)
{
	if (peapod_close_fds() == -1)
		return -1;

	args.daemon = DAEMONIZED;	/* Disables console output */

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
 * @brief Log a message
 *
 * Depending on the program arguments and the value of @p level, the same
 * message is emitted to console (<tt>stdout</tt>/<tt>stderr</tt>), a log file,
 * and/or @p syslog.
 *
 * @param level The level of the message
 * @param file Ordinarily NULL
 * @param line Ordinarily 0
 * @param fmt, ... @p printf(3)-style format and variable arguments
 * @note @p level may be the @p syslog levels (@p LOG_EMERG to @p LOG_DEBUG,
 *       i.e. 0 to 7), or our own @p LOG_DEBUGLOW (8). <br />
 *       @p file and @p line are the @p \__FILE__ and @p \__LINE__ macros, i.e.
 *       the source file and the line in the source file of the call to
 *       @p log_msg(). They were used during development only in the @p lfoo()
 *       logging macros defined in @p log.h.
 */
__attribute__((format (printf, 4, 5)))
void log_msg(int level, const char *file, int line, const char *fmt, ...)
{
	if (level > args.level)
		return;

	static int len;

	if (line > 0) {
		len = snprintf(log_buf, MSGSIZ, "%s:%d | ", file, line);
	} else {
		len = 0;
		log_buf[0] = '\0';
	}

	va_list vlist;
	va_start(vlist, fmt);
	len += vsnprintf(log_buf + len,
			 (len + 3) < MSGSIZ ? MSGSIZ - (len + 3) : 0,
			 fmt,
			 vlist);
	va_end(vlist);

	if (len > (MSGSIZ - 4))
		sprintf(log_buf + (MSGSIZ - 4), "...");

	if (args.daemon != DAEMONIZED)	/* Console output is still enabled */
		log_to_file(log_buf, level, NULL);

	if (log_fs != NULL)
		log_to_file(log_buf, level, log_fs);

	if (args.syslog == 1 && level != LOG_DEBUGLOW)
		syslog(level, "<%d> %s", level, log_buf);


	if (len > (MSGSIZ - 4)) {
		warning("previous message too long; %d characters were lost",
			len - (MSGSIZ - 4));
	}
}
