#pragma once

struct args_t {
	uint8_t help;
	uint8_t daemon;
	char *pidfile;
	char *conffile;
	uint8_t test;
	uint8_t level;
	char *logfile;
	uint8_t syslog;
	uint8_t quiet;			/* A bit of a misnomer, really */
	uint8_t color;
	uint8_t oneshot;
};

int args_get(int argc, char* argv[]);
