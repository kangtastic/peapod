#pragma once

#define DAEMONIZED		2

/* output to console only (stderr), possibly with an errno explainer */
#define cerr(...)		fprintf(stderr, __VA_ARGS__)
#define ceerr(...)		cerr(__VA_ARGS__, strerror(errno))

/* syslog's built-in levels are LOG_EMERG (0) to LOG_DEBUG (7) */
#define LOG_DEBUGLOW		8

#define debuglow(...)		log_msg(LOG_DEBUGLOW, NULL, 0, __VA_ARGS__)
#define debug(...)		log_msg(LOG_DEBUG, NULL, 0, __VA_ARGS__)
#define info(...)		log_msg(LOG_INFO, NULL, 0, __VA_ARGS__)
#define notice(...)		log_msg(LOG_NOTICE, NULL, 0, __VA_ARGS__)
#define warning(...)		log_msg(LOG_WARNING, NULL, 0, __VA_ARGS__)
#define err(...)		log_msg(LOG_ERR, NULL, 0, __VA_ARGS__)
#define crit(...)		log_msg(LOG_CRIT, NULL, 0, __VA_ARGS__)
#define alert(...)		log_msg(LOG_ALERT, NULL, 0, __VA_ARGS__)
#define emerg(...)		log_msg(LOG_EMERG, NULL, 0, __VA_ARGS__)

/* log with an errno explainer */
#define einfo(...)		info(__VA_ARGS__, strerror(errno))
#define ewarning(...)		warning(__VA_ARGS__, strerror(errno))
#define eerr(...)		err(__VA_ARGS__, strerror(errno))
#define ecrit(...)		crit(__VA_ARGS__, strerror(errno))

/* log and die */
#define critdie(...)		do { crit(__VA_ARGS__); exit(EXIT_FAILURE); } while (0)

/* log with an errno explainer and die */
#define ecritdie(...)		do { ecrit(__VA_ARGS__); exit(EXIT_FAILURE); } while (0)

/* syslog debugging: include file and line number information */
#define ldebug(...)		log_msg(LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define linfo(...)		log_msg(LOG_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define lnotice(...)		log_msg(LOG_NOTICE, __FILE__, __LINE__, __VA_ARGS__)
#define lwarning(...)		log_msg(LOG_WARNING, __FILE__, __LINE__, __VA_ARGS__)
#define lerr(...)		log_msg(LOG_ERR, __FILE__, __LINE__, __VA_ARGS__)
#define lcrit(...)		log_msg(LOG_CRIT, __FILE__, __LINE__, __VA_ARGS__)
#define lalert(...)		log_msg(LOG_ALERT, __FILE__, __LINE__, __VA_ARGS__)
#define lemerg(...)		log_msg(LOG_EMERG, __FILE__, __LINE__, __VA_ARGS__)

int log_init(void);
int log_daemonize(void);
void log_msg(int level, const char *file, int line, const char *fmt, ...);
