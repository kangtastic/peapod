/**
 * @file log.h
 * @brief Function prototypes for @p log.c, global logging macros.
 */
#pragma once

#include <errno.h>
#include <syslog.h>

/**
 * @name A new log level less severe than @p LOG_DEBUG
 * The syslog levels range from @p LOG_EMERG to @p LOG_DEBUG (0 to 7).
 * Messages at this level aren't even emitted to syslog.
 * @{
 */
#define LOG_DEBUGLOW		8
/** @} */

/**
 * @name Function-like stderr output macros
 * Usage is like @p printf(3). Used during early program startup to print to
 * @p stderr, before logging is even fully initialized.
 * - @p ceerr() adds @p strerror(errno) as the last argument,
 *   i.e. @code ceerr("Error %d: %s", errno); @endcode is equivalent to
 *   @code cerr("Error %d: %s", errno, strerror(errno)); @endcode
 * @{
 */
#define cerr(...)		fprintf(stderr, __VA_ARGS__)
#define ceerr(...)		cerr(__VA_ARGS__, strerror(errno))
/** @} */

/**
 * @name Function-like logging macros
 * Usage is like @p printf(3).
 * - Names range from @p emerg() for logging with level @p LOG_EMERG to @p debug
 *   for @p LOG_DEBUG in addition to @p debuglow() for our own @p LOG_DEBUGLOW.
 * - The prefix '@p l' adds file and line number information to the message
 *   (however, those macros were only used during development).
 * - The prefix '@p e' adds @p strerror(errno) as the last argument, i.e.
 *   @code eerr("Error %d: %s", errno); @endcode is equivalent to
 *   @code err("Error %d: %s", errno, strerror(errno)); @endcode
 * - The suffix '@p die' also calls @p exit(3) with code @P EXIT_FAILURE.
 * @{
 */
#define emerg(...)		log_msg(LOG_EMERG, NULL, 0, __VA_ARGS__)
#define alert(...)		log_msg(LOG_ALERT, NULL, 0, __VA_ARGS__)
#define crit(...)		log_msg(LOG_CRIT, NULL, 0, __VA_ARGS__)
#define err(...)		log_msg(LOG_ERR, NULL, 0, __VA_ARGS__)
#define warning(...)		log_msg(LOG_WARNING, NULL, 0, __VA_ARGS__)
#define notice(...)		log_msg(LOG_NOTICE, NULL, 0, __VA_ARGS__)
#define info(...)		log_msg(LOG_INFO, NULL, 0, __VA_ARGS__)
#define debug(...)		log_msg(LOG_DEBUG, NULL, 0, __VA_ARGS__)
#define debuglow(...)		log_msg(LOG_DEBUGLOW, NULL, 0, __VA_ARGS__)

#define lemerg(...)		log_msg(LOG_EMERG, __FILE__, __LINE__, __VA_ARGS__)
#define lalert(...)		log_msg(LOG_ALERT, __FILE__, __LINE__, __VA_ARGS__)
#define lcrit(...)		log_msg(LOG_CRIT, __FILE__, __LINE__, __VA_ARGS__)
#define lerr(...)		log_msg(LOG_ERR, __FILE__, __LINE__, __VA_ARGS__)
#define lwarning(...)		log_msg(LOG_WARNING, __FILE__, __LINE__, __VA_ARGS__)
#define lnotice(...)		log_msg(LOG_NOTICE, __FILE__, __LINE__, __VA_ARGS__)
#define linfo(...)		log_msg(LOG_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define ldebug(...)		log_msg(LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)

#define ecrit(...)		crit(__VA_ARGS__, strerror(errno))
#define eerr(...)		err(__VA_ARGS__, strerror(errno))
#define ewarning(...)		warning(__VA_ARGS__, strerror(errno))
#define einfo(...)		info(__VA_ARGS__, strerror(errno))

#define critdie(...)		do { crit(__VA_ARGS__); exit(EXIT_FAILURE); } while (0)

#define ecritdie(...)		do { ecrit(__VA_ARGS__); exit(EXIT_FAILURE); } while (0)
/** @} */

int log_init(void);
int log_daemonize(void);
void log_msg(int level, const char *file, int line, const char *fmt, ...);
