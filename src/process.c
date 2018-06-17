/**
 * @file process.c
 * @brief Process an EAPOL packet.
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

static int filter(struct filter_t *filter, char *name_orig,
		  char *name, __u8 type, __u8 code);
static void script(struct peapod_packet packet, char *script);

extern struct args_t args;
extern char **environ;
extern uint8_t *mpdu_buf;
extern int mpdu_buf_size;

/**
 * @brief Determine if an EAPOL packet should be filtered (dropped).
 *
 * @param filter A pointer to a <tt>struct filter_t</tt> structure containing
 *               filter bitmasks for EAPOL Packet Types and EAP Codes.
 * @param name_orig If not @p NULL, a C string containing the name of the
 *                  network interface on which an EAPOL packet was originally
 *                  captured.
 * @param name A C string containing the name of a network interface. If
 *             @p name_orig is not @p NULL, references the network interface on
 *             which an EAPOL Packet was originally captured. Otherwise,
 *             references the network interface on which the EAPOL packet will be
 *             sent.
 * @param type An EAPOL Packet Type.
 * @param code An EAP Code.
 *
 * @return 1 if the EAPOL packet should be filtered, or 0 otherwise.
 */
static int filter(struct filter_t *filter, char *name_orig,
		  char *name, __u8 type, __u8 code)
{
	if (filter->type & (uint16_t)(1 << type)) {
		if (name_orig == NULL)
			info("filtered %s packet entering on '%s'",
			     packet_decode(type, eapol_types), name);
		else
			info("filtered %s packet from '%s' leaving on '%s'",
			     packet_decode(type, eapol_types), name_orig, name);

		return 1;
	}

	if (type == EAPOL_EAP && filter->code & (uint8_t)(1 << code)) {
		if (name_orig == NULL)
			info("filtered EAP-%s entering on '%s'",
			     packet_decode(code, eap_codes), name);
		else
			info("filtered EAP-%s from '%s' leaving on '%s'",
			     packet_decode(code, eap_codes), name_orig, name);

		return 1;
	}
	return 0;
}

/**
 * @brief Execute a script.
 *
 * The script is run with several environment variables set containing at least
 * the entire Base64-encoded Ethernet frame encapsulating an EAPOL packet at the
 * time of capture on an ingress interface, the entire frame that is being sent
 * (if applicable) on an egress interface (which may differ from the original in
 * its 802.1Q tag), and associated metadata extracted from @p packet.
 *
 * @param packet A <tt>struct peapod_packet</tt> structure representing an EAPOL
 *               packet.
 * @param script A C string containing the path of the script to be executed.
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
		snprintf(buf, sizeof(buf), "%d", packet.code);
		setenv("PKT_CODE", buf, 1);
		setenv("PKT_CODE_DESC", packet_decode(packet.code,
						      eap_codes), 1);

		snprintf(buf, sizeof(buf), "%d", packet.mpdu->eap.id);
		setenv("PKT_ID", buf, 1);

		if (packet.code == 1 || packet.code == 2) {
			snprintf(buf, sizeof(buf), "%d", packet.mpdu->eap.type);
			setenv("PKT_REQRESP_TYPE", buf, 1);
			setenv("PKT_REQRESP_DESC",
			       packet_decode(packet.mpdu->eap.type,
					     eap_types), 1);
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
 * @brief A wrapper for @p filter().
 *
 * Calls @p filter() with the appropriate parameters extracted from @p packet
 * and @p iface.
 *
 * @param packet A <tt>struct peapod_packet</tt> structure representing an EAPOL
 *               packet.
 * @param iface A pointer to a <tt>struct iface_t</tt> structure representing a
 *              network interface.
 * @param dir A flag that specifies whether this function should look for an
 *            ingress or an egress filter mask on @p iface. It may be set to
 *            @p PROCESS_INGRESS or @p PROCESS_EGRESS.
 *
 * @return The result of the underlying call to @p filter() if there is an
 *         ingress or egress filter mask configured on @p iface, or 0 otherwise.
 */
int process_filter(struct peapod_packet packet,
		   struct iface_t *iface, uint8_t dir)
{
	if (dir == PROCESS_INGRESS && iface->ingress != NULL &&
	    iface->ingress->filter != NULL)
		return filter(iface->ingress->filter,
			      NULL, packet.name,
			      packet.type, packet.code);
	else if (dir == PROCESS_EGRESS && iface->egress != NULL &&
		 iface->egress->filter != NULL)
		return filter(iface->egress->filter,
			      packet.name_orig, packet.name,
			      packet.type, packet.code);

	return 0;
}

/**
 * @brief A wrapper for @p script().
 *
 * Calls @p script() with appropriate arguments extracted from @p packet and
 * @p action.
 *
 * @param packet A <tt>struct peapod_packet</tt> structure representing an EAPOL
 *               packet.
 * @param action A pointer to a <tt>struct action_t</tt> structure containing
 *               two arrays of C strings. The first array contains paths to
 *               scripts to be executed if the EAPOL packet represented by
 *               @p packet is of one of the nine defined EAPOL Packet Types.
 *               Similarly, the second array contains paths to scripts to be
 *               executed if the EAPOL packet is of Type EAPOL-EAP and the EAP
 *               packet it encapsulates is of one of the four defined EAP Codes.
 * @param dir A flag that represents whether @p packet has just been received or
 *            is about to be sent. It may be set to @p PROCESS_INGRESS or
 *            @p PROCESS_EGRESS.
 */
void process_script(struct peapod_packet packet,
		    struct action_t *action, uint8_t dir)
{
	char *prefix = NULL;		/* "" or "EAP-" */
	char *desc = NULL;		/* see struct decode_t */
	char *path = NULL;

	/* Sample outputs:
	 * "received EAPOL-EAP on 'eth1'; executing '...'"
	 * "sending EAP-Start from 'eth0' on 'eth1'; executing '...'"
	 */
	char *fmt_ingress = "received %s%s on '%%s'; executing '%%s'";
	char *fmt_egress = "sending %s%s from '%s' on '%%s'; executing '%%s'";

	char buf[128] = { "" };

	if (packet.type <= EAPOL_ANNOUNCEMENT_REQ &&
	    action->type[packet.type] != NULL) {
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

	if (dir == PROCESS_INGRESS)
		snprintf(buf, sizeof(buf), fmt_ingress, prefix, desc);
	else if (dir == PROCESS_EGRESS)
		snprintf(buf, sizeof(buf), fmt_egress, prefix, desc,
			 packet.name_orig);
	else
		return;

	if (args.quiet == 1)
		info(buf, packet.name, path);
	else
		notice(buf, packet.name, path);

	script(packet, path);
}
