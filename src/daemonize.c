#include "includes.h"

static void check_pidfile(const char *pidfile);
static char *getpwd(void);
static pid_t write_pidfile(const char *pidfile, pid_t pid);

extern struct args_t args;
extern char **environ;

/**
 * Exits if the process referenced by @pidfile is running.
 *
 * @pidfile: A pointer to a C string containing the path of a PID file.
 *
 * Returns nothing.
 */
static void check_pidfile(const char *pidfile)
{
	pid_t pid;
	FILE* fd = fopen(pidfile, "r");		/* unlocked file */
	if (fd != NULL) {
		if (fscanf(fd, "%d", &pid) == 1 && kill(pid, 0) == 0) {
			notice("already daemonized (PID %d)?", pid);
			fclose(fd);
			exit(EXIT_SUCCESS);
		}
		fclose(fd);
	}
}

/**
 * Gets the current working directory (like get_current_dir_name()).
 * The caller must free() the result.
 *
 * Returns a pointer to a C string with the current working directory if
 * successful, or a null pointer if unsuccessful.
 */
static char *getpwd(void)
{
	char *ret;
	char *pathmax = malloc(PATH_MAX);

	if (pathmax == NULL)
		ecritdie("cannot allocate buffer of size PATH_MAX: %s");

	if (getcwd(pathmax, PATH_MAX) == NULL) {
		err("cannot find value of environment variable PWD");
		return NULL;
	}

	ret = strdup(pathmax);
	free(pathmax);

	return ret;
}

/**
 * Writes a PID file. Attempts to do so atomically as per daemon(7).
 * Does not write PID file if the file referenced by @pidfile already exists,
 * and the process ID referenced by the file is in use by a running process.
 *
 * @pidfile: A pointer to a C string containing the path of a PID file.
 * @pid: A PID.
 *
 * Returns the PID written to the PID file if successful.
 */
static pid_t write_pidfile(const char *pidfile, pid_t pid)
{
	char buf[16] = { "" };
	pid_t tmp = pid;	/* PID we want to write/verify */

	int ifd = open(pidfile, O_SYNC | O_CREAT | O_RDWR, 0644);

	if (flock(ifd, LOCK_EX | LOCK_NB) == -1)
		ecritdie("cannot lock PID file: %s");

	/* Check existing PID */
	for(int rv, i = 0; i < (int)sizeof(buf); i++) {
		rv = read(ifd, &buf[i], 1);
		if (rv == -1) {
			ecritdie("cannot read PID file: %s");
		} else if (rv == 0) {
			buf[i] = '\0';
			break;
		}
	}
	buf[sizeof(buf) - 1] = '\0';
	pid = atoi(buf);

	if (pid != 0 && kill(pid, 0) == 0)
		ecritdie("found existing PID %d in PID file", pid);

	if (lseek(ifd, (off_t) 0, SEEK_SET) == -1)
		ecritdie("cannot rewind PID file: %s");

	pid = tmp;

	/* Write our PID */
	sprintf(buf, "%d\n", pid);

	if (write(ifd, buf, strlen(buf)) == -1)
		ecritdie("cannot write PID: %s");

	if (fsync(ifd) == -1)
		ecritdie("cannot sync PID file: %s");

	notice("wrote PID %d to '%s'", pid, pidfile);

	if (lseek(ifd, (off_t) 0, SEEK_SET) == -1)
		ecritdie("cannot rewind PID file: %s");


	/* Verify written PID */
	for(int rv, i = 0; i < (int)sizeof(buf); i++) {
		rv = read(ifd, &buf[i], 1);
		if (rv == -1) {
			ecritdie("cannot read PID file: %s");
		} else if (rv == 0) {
			buf[i] = '\0';
			break;
		}
	}
	buf[sizeof(buf) - 1] = '\0';
	pid = atoi(buf);

	if (close(ifd) == -1)
		ecritdie("cannot close PID file: %s");

	return pid;
}

/**
 * Daemonizes the program.
 * Attempts to do so in the manner described in daemon(7).
 * Forks twice, with the parent writing the PID of the second child to a PID
 * file before exiting. The daemon child also adds the PWD environment variable.
 *
 * @pidfile: A pointer to a C-string containing the path of a PID file.
 *
 * Returns nothing.
 */
void daemonize(const char *pidfile)
{
	check_pidfile(pidfile);

	if (getppid() == 1) {
		notice("already daemonized");
		exit(EXIT_SUCCESS);
	}

	/* Parent will write PID of (2nd) child and signal write completion. */
	int pipepc[2];			/* Parent writes, child reads */
	int pipecp[2];			/* Child writes, parent reads */
	if (pipe(pipepc) == -1 || pipe(pipecp) == -1)
		ecritdie("cannot create pipe: %s");

	pid_t pid;

	/* first fork */
	pid = fork();
	if (pid == -1) {
		ecritdie("cannot fork: %s");
	} else if (pid > 0) {
		/* Parent */
		close(pipepc[0]);
		close(pipecp[1]);
		if (read(pipecp[0], &pid, sizeof(pid)) != sizeof(pid))
			ecritdie("cannot read PID from child: %s");

		pid = write_pidfile(pidfile, pid);

		if (write(pipepc[1], &pid, sizeof(pid)) != sizeof(pid))
			ecritdie("cannot pipe PID back to child: %s");

		close(pipepc[1]);
		close(pipecp[0]);

		waitpid(-1, NULL, WNOHANG);	/* don't block waiting */
		debug("parent exiting");
		exit(EXIT_SUCCESS);
	}

	/* First child */
	close(pipepc[1]);
	close(pipecp[0]);

	if (setsid() == -1)
		ecritdie("setsid failed: %s");

	pid = fork();
	if (pid == -1) {
		ecritdie("cannot fork again: %s");
	} else if (pid > 0) {
		waitpid(-1, NULL, WNOHANG);	/* don't block waiting */
		debug("first child exiting");
		exit(EXIT_SUCCESS);
	}

	/* Second child (actual daemon process) */
	pid_t dpid = getpid();

	if (write(pipecp[1], &dpid, sizeof(dpid)) != sizeof(dpid))
		ecritdie("cannot pipe PID to parent: %s");

	if (read(pipepc[0], &pid, sizeof(pid)) != sizeof(pid))
		ecritdie("cannot read PID back from parent: %s");

	if (pid != dpid)
		ecritdie("got a PID of %d (not our own) from parent", pid);

	close(pipepc[0]);
	close(pipecp[1]);

	if (log_daemonize() == -1)
		exit(EXIT_FAILURE);

	umask(0);

	if (chdir(PEAPOD_ROOT_PATH) == -1)
		ecritdie("chdir to root directory '%s' failed: %s",
			 PEAPOD_ROOT_PATH);

	/* For script execution; even then there's no real reason for this */
	char *pwd = getpwd();
	int rv = setenv("PWD", pwd, 1);
	free(pwd);
	if (rv == -1)
		eerr("cannot set environment variable PWD: %s");

	notice("successfully daemonized");
}
