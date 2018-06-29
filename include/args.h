/**
 * @file args.h
 * @brief Function prototypes for @p args.c, global program arguments data
 *        structure
 */
#pragma once
#include <stdint.h>

/**
 * @brief The program arguments data structure
 * @see @p defaults.h
 */
struct args_t {
	uint8_t help;		/**< @brief Flag: Was @p -h provided? */
	uint8_t daemon;		/**< @brief Flag: Was @p -d provided? */
	/**
	 * @brief A C string containing the path to the PID file
	 *
	 * Providing @p -d means that this will be set to @e something, because
	 * running as a daemon requires a PID file. May be the argument to
	 * @p -p. Defaults to @p PEAPOD_PID_PATH.
	 */
	char *pidfile;
	/**
	 * @brief A C string containing the path to the config file
	 *
	 * May be the argument to @p -c. Defaults to @c PEAPOD_CONF_PATH.
	 */
	char *conffile;
	uint8_t test;		/**< @brief Flag: Was @p -t provided? */
	/**
	 * @brief Logging level
	 *
	 * Defaults to @p LOG_NOTICE (5). Providing @p -v increments this up to
	 * @p LOG_DEBUGPKT (8).
	 *
	 * @see log.h
	 */
	uint8_t level;
	/**
	 * @brief The path to the log file
	 *
	 * Independently of whether logs are emitted to the console and/or
	 * @p syslog, controls whether logs are emitted to a log file. If @p -l
	 * is not provided, remains @p NULL, and a log file is not used.
	 * Otherwise, may be the optional argument to @p -l, or the default of
	 * @p PEAPOD_LOG_PATH.
	 */
	char *logfile;
	uint8_t syslog;		/**< @brief Flag: Was @p -s provided? */
	uint8_t quiet;		/**< @brief Flag: Was @p -q provided? */
	uint8_t color;		/**< @brief Flag: Was @p -C provided? */
	uint8_t oneshot;	/**< @brief Flag: Was @p -o provided? */
};

char *args_canonpath(const char *path, uint8_t create);
int args_get(int argc, char* argv[]);
