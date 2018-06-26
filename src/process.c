/**
 * @file process.c
 * @brief Process an EAPOL packet
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/wait.h>

#include "args.h"
#include "b64enc.h"
#include "log.h"
#include "packet.h"
#include "peapod.h"
#include "process.h"

static void script(struct peapod_packet packet, char *script);

extern struct args_t args;
extern char **environ;
extern uint8_t *mpdu_buf;
extern int mpdu_buf_size;

/**
 * @brief Execute a script
 *
 * The script is run with several environment variables set containing at least
 * the entire Base64-encoded Ethernet frame encapsulating an EAPOL packet at the
 * time of capture on an ingress interface, the entire frame that is being sent
 * (if applicable) on an egress interface (which may differ from the original in
 * its 802.1Q tag), and associated metadata extracted from @p packet.
 *
 * @param packet A <tt>struct peapod_packet</tt> representing an EAPOL packet
 * @param script Path of the script to be executed
 * @see The @p env.sh example script for a listing of the possible environment
 *      variables and their values
 */
static void script(struct peapod_packet packet, char *script)
{
	pid_t pid = fork();
	if (pid == -1) {
		warning("never mind, cannot fork for script execution");
		return;
	}
	else if (pid > 0) {
		int status;

		if (waitpid(-1, &status, 0) == -1)
			ewarning("cannot wait for script execution: %s");
		else if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
			warning("script did not exit cleanly (code %d)",
				WEXITSTATUS(status));
		else if (WIFSIGNALED(status))
			warning("script was terminated by a signal");

		return;
	}

	closelog();			/* Goodbye, syslog... */
	peapod_close_fds();		/* sockets/epoll/logfile */
	peapod_redir_stdfds();		/* stdin/out/err */

	char *argv[] = { script, NULL };

	/* Set up a bunch of environment variables for the script to use.
	 * TODO: Allocate and fill a new **environ to pass to execve(2)
	 *       as its *envp[] parameter instead of using setenv(3).
	 *       setenv(3) is, however, the lazier way ;)
	 */
	char buf[128] = { "" };

	snprintf(buf, sizeof(buf), "%d.%d",
		 (int)packet.tv.tv_sec, (int)packet.tv.tv_usec);
	setenv("PKT_TIME", buf, 1);

	setenv("PKT_DEST", iface_strmac(packet.h_dest), 1);
	setenv("PKT_SOURCE", iface_strmac(packet.h_source), 1);

	snprintf(buf, sizeof(buf), "%d", packet.type);
	setenv("PKT_TYPE", buf, 1);
	setenv("PKT_TYPE_DESC", packet_decode(packet.type, eapol_types), 1);

	if (packet.type == EAPOL_EAP) {
		struct eapol_mpdu *mpdu = (struct eapol_mpdu *)mpdu_buf;
		snprintf(buf, sizeof(buf), "%d", packet.code);
		setenv("PKT_CODE", buf, 1);
		setenv("PKT_CODE_DESC", packet_decode(packet.code,
						      eap_codes), 1);

		snprintf(buf, sizeof(buf), "%d", mpdu->eap.id);
		setenv("PKT_ID", buf, 1);

		if (packet.code == 1 || packet.code == 2) {
			snprintf(buf, sizeof(buf), "%d", mpdu->eap.type);
			setenv("PKT_REQRESP_TYPE", buf, 1);
			setenv("PKT_REQRESP_DESC",
			       packet_decode(mpdu->eap.type, eap_types), 1);
		}
	}

	snprintf(buf, sizeof(buf), "%d", (int)packet.len_orig);
	setenv("PKT_LENGTH_ORIG", buf, 1);

	char *b64buf = b64enc(packet_buf(packet, 1), packet.len_orig);
	setenv("PKT_ORIG", b64buf, 1);
	free(b64buf);

	setenv("PKT_IFACE_ORIG", packet.name_orig, 1);

	snprintf(buf, sizeof(buf), "%d", packet.iface_orig->mtu);
	setenv("PKT_IFACE_MTU_ORIG", buf, 1);

	if (packet.vlan_valid_orig == 1) {
		snprintf(buf, sizeof(buf), "%.08x",
			 ntohl(packet_tcitonl(packet.tci_orig)));
		setenv("PKT_DOT1Q_TCI_ORIG", buf + 4, 1);	/* TCI only */
	}

	snprintf(buf, sizeof(buf), "%d", (int)packet.len);
	setenv("PKT_LENGTH", buf, 1);

	b64buf = b64enc(packet_buf(packet, 0), packet.len);
	setenv("PKT", b64buf, 1);
	free(b64buf);

	setenv("PKT_IFACE", packet.name, 1);

	snprintf(buf, sizeof(buf), "%d", packet.iface->mtu);
	setenv("PKT_IFACE_MTU", buf, 1);

	if (packet.vlan_valid == 1) {
		snprintf(buf, sizeof(buf), "%.08x",
			 ntohl(packet_tcitonl(packet.tci)));
		setenv("PKT_DOT1Q_TCI", buf + 4, 1);		/* TCI only */
	}

	if (execve(script, argv, environ) == -1)
		exit(errno);	/* We failed and can't really signal why :) */
}

/**
 * @brief Determine if an EAPOL packet should be filtered (dropped)
 *
 * @p packet should contain enough information to determine whether an ingress
 * or egress filter should be applied.
 *
 * @param packet A <tt>struct peapod_packet</tt> representing an EAPOL packet
 * @return 1 if the EAPOL packet should be filtered, or 0 if not
 */
int process_filter(struct peapod_packet packet)
{
	static uint8_t phase;
	static struct filter_t *filter;
	static char *prefix, *desc;

	/* Basic sanity checks */
	if (packet.iface_orig == packet.iface &&
	    packet.iface->ingress != NULL &&
	    packet.iface->ingress->filter != NULL) {
		phase = PROCESS_INGRESS;
		filter = packet.iface->ingress->filter;
	} else if (packet.iface_orig != packet.iface &&
		   packet.iface->egress != NULL &&
		   packet.iface->egress->filter != NULL) {
		phase = PROCESS_EGRESS;
		filter = packet.iface->egress->filter;
	} else {
		return 0;
	}

	desc = NULL;

	/* Build log message */
	if (filter->type & (uint16_t)(1 << packet.type)) {
		prefix = "";
		desc = packet_decode(packet.type, eapol_types);
	} else if (packet.type == EAPOL_EAP &&
		   filter->code & (uint8_t)(1 << packet.code)) {
		prefix = "EAP-";
		desc = packet_decode(packet.code, eap_codes);
	}

	if (desc == NULL)
		return 0;

	/* Log filter application */
	if (phase == PROCESS_INGRESS) {
		info("filtered %s%s received on '%s'",
		     prefix, desc, packet.name_orig);
	} else {
		info("filtered %s%s received on '%s' from being sent on '%s'",
		     prefix, desc, packet.name_orig, packet.name);
	}

	return 1;
}

/**
 * @brief A wrapper for @p script()
 *
 * @p packet should contain enough information to determine whether an ingress
 * or egress script should be executed, upon which @p script() is called with
 * the appropriate parameters extracted from @p packet.
 *
 * @param packet A <tt>struct peapod_packet</tt> representing an EAPOL packet
 */
void process_script(struct peapod_packet packet)
{
	static uint8_t phase;
	static struct action_t *action;
	static char *prefix, *desc, *path;

	/* Basic sanity checks */
	if (packet.iface_orig == packet.iface &&
	    packet.iface->ingress != NULL &&
	    packet.iface->ingress->action != NULL) {
		phase = PROCESS_INGRESS;
		action = packet.iface->ingress->action;
	} else if (packet.iface_orig != packet.iface &&
		   packet.iface->egress != NULL &&
		   packet.iface->egress->action != NULL) {
		phase = PROCESS_EGRESS;
		action = packet.iface->egress->action;
	} else {
		return;
	}

	path = NULL;

	/* Build log message */
	if (packet.type <= EAPOL_ANNOUNCEMENT_REQ &&
	    action->type[packet.type] != NULL) {
		prefix = "";
		desc = packet_decode(packet.type, eapol_types);
		path = action->type[packet.type];
	} else if (packet.type == EAPOL_EAP &&
		   EAP_CODE_REQUEST <= packet.code &&
		   packet.code <= EAP_CODE_FAILURE &&
		   action->code[packet.code] != NULL) {
		prefix = "EAP-";
		desc = packet_decode(packet.code, eap_codes);
		path = action->code[packet.code];
	}

	if (path == NULL)
		return;

	/* Log script execution */
	if (phase == PROCESS_INGRESS)
		log_msg(args.quiet == 1 ? LOG_INFO : LOG_NOTICE, NULL, 0,
			"received %s%s on '%s'; executing '%s'",
			prefix, desc, packet.name, path);
	else if (phase == PROCESS_EGRESS)
		log_msg(args.quiet == 1 ? LOG_INFO : LOG_NOTICE, NULL, 0,
			"sending %s%s from '%s' on '%s'; executing '%s'",
			prefix, desc, packet.name_orig, packet.name, path);
	else
		return;

	script(packet, path);
}
