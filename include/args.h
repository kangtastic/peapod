/**
 * @file args.h
 * @brief Function prototypes for @p args.c, global program arguments data
 *        structure.
 */
#pragma once
#include <stdint.h>

/**
 * @brief The global program arguments data structure.
 * @see @p defaults.h
 */
struct args_t {
	uint8_t help;		/**< @brief Flag: @p -h was provided. */
	uint8_t daemon;		/**< @brief Flag: @p -d was provided. */
	/**
	 * @brief A C string containing the path to the PID file.
	 *
	 * Providing @p -d means that this will be set to @e something, because
	 * running as a daemon requires a PID file. May be the argument to
	 * @p -p. Defaults to @p PEAPOD_PID_PATH.
	 */
	char *pidfile;
	/**
	 * @brief A C string containing the path to the config file.
	 *
	 * May be the argument to @p -c. Defaults to @c PEAPOD_CONF_PATH.
	 */
	char *conffile;
	uint8_t test;		/**< @brief Flag: @p -t was provided. */
	/**
	 * @brief Logging level.
	 *
	 * Defaults to @p LOG_NOTICE (5). Providing @p -v increments this up to
	 * @p LOG_DEBUGPKT (8).
	 *
	 * @see log.h
	 */
	uint8_t level;
	/**
	 * @brief A C string containing the path to the log file.
	 *
	 * Independently of whether logs are emitted to the console and/or
	 * @p syslog, controls whether logs are emitted to a log file. If @p -l
	 * is not provided, remains @p NULL, and a log file is not used.
	 * Otherwise, may be the optional argument to @p -l, or the default of
	 * @p PEAPOD_LOG_PATH.
	 */
	char *logfile;
	uint8_t syslog;		/**< @brief Flag: @p -s was provided. */
	uint8_t quiet;		/**< @brief Flag: @p -q was provided. */
	uint8_t color;		/**< @brief Flag: @p -n was provided. */
	uint8_t oneshot;	/**< @brief Flag: @p -o was provided. */
};

char *args_canonpath(const char *path, int create);
int args_get(int argc, char* argv[]);
