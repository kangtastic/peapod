/**
 * @file process.c
 * @brief Process an EAPOL frame/packet.
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
extern uint8_t *pdu_buf;
extern int pdu_buf_size;

/**
 * @brief Determine if an EAPOL frame should be filtered (dropped).
 *
 * @param filter A pointer to a <tt>struct filter_t</tt> structure containing
 *               filter masks for EAPOL frame Types and EAP-Packet Codes.
 * @param name_orig If not @p NULL, a C string containing the name of the
 *                  network interface on which an EAPOL frame was originally
 *                  captured.
 * @param name A C string containing the name of a network interface. If
 *             @p name_orig is not @p NULL, references the network interface on
 *             which an EAPOL frame was originally captured. Otherwise,
 *             references the network interface on which the EAPOL frame will be
 *             sent.
 * @param type An EAPOL frame Type.
 * @param code An EAP-Packet Code.
 *
 * @return 1 if the frame should be filtered, or 0 otherwise.
 */
static int filter(struct filter_t *filter, char *name_orig,
		  char *name, __u8 type, __u8 code)
{
	if (filter->frame & (uint8_t)(1 << type)) {
		if (name_orig == NULL)
			info("filtered %s frame entering on '%s'",
			     packet_decode(type, eapol_types), name);
		else
			info("filtered %s frame from '%s' leaving on '%s'",
			     packet_decode(type, eapol_types), name_orig, name);

		return 1;
	}

	if (type == EAPOL_EAP_PACKET && filter->packet & (uint8_t)(1 << code)) {
		if (name_orig == NULL)
			info("filtered %s EAP-Packet entering on '%s'",
			     packet_decode(code, eap_codes), name);
		else
			info("filtered %s EAP-Packet from '%s' leaving on '%s'",
			     packet_decode(code, eap_codes), name_orig, name);

		return 1;
	}
	return 0;
}

/**
 * @brief Execute a script.
 *
 * The script is run with several environment variables set containing at least
 * the entire Base64-encoded frame at the time of capture on an ingress
 * interface, the entire frame that is being sent (if applicable) on an egress
 * interface (which may differ from the original in its 802.1Q tag), and
 * associated metadata extracted from @p packet.
 *
 * @param packet A <tt>struct peapod_packet</tt> structure representing an EAPOL
 *               frame.
 * @param script A C string containing the path of the script to be executed.
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

	closelog();			/* Goodbye, syslog */
	peapod_close_fds();		/* Goodbye, sockets/epoll/logfile */
	peapod_redir_stdfds();		/* Goodbye, stdin/out/err */

	char *argv[] = { script, NULL };

	/* Set up a bunch of environment variables for the script to use.
	 * setenv() is due to laziness. We ~could~ allocate and fill a new
	 * **environ (third argument to execve).
	 *
	 * Here follows a list of the possible variables and values as they
	 * would be reported by a tool like env. These are example values only
	 * only and will differ based on the contents of the frame and where it
	 * is in the process of being proxied. (Yes, the variables are named
	 * PKT_whatever, even though they're Ethernet frames. Even in the 802.1X
	 * spec, terminology is inexact.)
	 *
	 * PKT_TIME=unixtime.usecs		(Packet receipt timestamp)
	 *
	 * PKT_DEST=xx:xx:xx:xx:xx:xx
	 * PKT_SOURCE=xx:xx:xx:xx:xx:xx
	 *
	 * PKT_TYPE=0				(EAPOL frame type)
	 * PKT_TYPE_DESC=EAPOL-Encapsulated-ASF-Alert
	 *
	 * (If frame encapsulates an EAP-Packet)
	 * PKT_CODE=2
	 * PKT_CODE_DESC=Response
	 * PKT_ID=152				(Identifier)
	 *
	 * (If frame is EAP-Packet and Code is Request or Response, 1 or 2)
	 * PKT_REQRESP_TYPE=255
	 * PKT_REQRESP_DESC=Generic Token Card (GTC)
	 *
	 * (802.3 frame as captured on ingress interface)
	 * PKT_LENGTH_ORIG=64
	 * PKT_ORIG=AYDCAAADC...		(Base64 encoded)
	 * PKT_IFACE_ORIG=eth0
	 * PKT_IFACE_ORIG_MTU=1500
	 * (If frame came in with an 802.1Q tag)
	 * PKT_DOT1Q_ORIG=9000			(802.1Q Tag Control Information
	 *					 in hex, here VLAN 0 p 5)
	 *
	 * (Frame as sent on egress interface. If these values match those
	 * suffixed with _ORIG above, the frame is still on the ingress side.)
	 * PKT_LENGTH=60
	 * PKT=AYDCAAADC...
	 * PKT_IFACE=eth1
	 * PKT_IFACE_MTU=1500
	 * //PKT_TCI=				(Not in environment. In this
	 *					 example, eth1 is configured to
	 *					 strip tags from egress frames.)

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

	if (packet.type == EAPOL_EAP_PACKET) {
		snprintf(buf, sizeof(buf), "%d", packet.code);
		setenv("PKT_CODE", buf, 1);
		setenv("PKT_CODE_DESC", packet_decode(packet.code,
						      eap_codes), 1);

		snprintf(buf, sizeof(buf), "%d", packet.pdu->eap.id);
		setenv("PKT_ID", buf, 1);

		if (packet.code == 1 || packet.code == 2) {
			snprintf(buf, sizeof(buf), "%d", packet.pdu->eap.type);
			setenv("PKT_REQRESP_TYPE", buf, 1);
			setenv("PKT_REQRESP_DESC",
			       packet_decode(packet.pdu->eap.type,
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
		setenv("PKT_TCI_ORIG", buf + 4, 1);	/* cut TPID leave TCI */
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
		setenv("PKT_TCI", buf + 4, 1);		/* cut TPID leave TCI */
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
 *               frame.
 * @param iface A pointer to a <tt>struct iface_t</tt> structure representing a
 *              network interface.
 * @param dir A flag that specifies whether this function should look for an
 *            ingress or an egress filter mask on @p iface. It may be set to
 *            @p PROCESS_INGRESS or @p PROCESS_EGRESS.
 *
 * @return The result of the underlying call to @p filter() if there is an
 *         ingress or egress filter mask configured on @p iface, or 0 otherwise.
 */
int process_filter(struct peapod_packet packet, struct iface_t *iface, uint8_t dir)
{
	struct filter_t *fltr = NULL;
	if (dir == PROCESS_EGRESS &&
	    iface->egress != NULL && iface->egress->filter != NULL) {
		fltr = iface->egress->filter;
		return filter(fltr, packet.name_orig, packet.name,
			      packet.type, packet.code);
	}
	else if (iface->ingress != NULL && iface->ingress->filter != NULL) {
		fltr = iface->ingress->filter;
		return filter(fltr, NULL, packet.name,
			      packet.type, packet.code);
	}
	return 0;
}

/**
 * @brief A wrapper for @p script().
 *
 * Calls @p script() with appropriate arguments extracted from @p packet and
 * @p action.
 *
 * @param packet A <tt>struct peapod_packet</tt> structure representing an EAPOL
 *               frame.
 * @param action A pointer to a <tt>struct action_t</tt> structure containing
 *               two arrays of C strings. The first array contains paths to
 *               scripts that are executed if the EAPOL frame represented by
 *               @p packet is of one of the five defined frame Types. Similarly,
 *               the second array contains paths to scripts that are executed if
 *               the frame encapsulates an EAP-Packet of one of the four defined
 *               EAP-Packet Codes.
 * @param dir A flag that represents whether @p packet has just been received or
 *            is about to be sent. It may be set to @p PROCESS_INGRESS or
 *            @p PROCESS_EGRESS.
 */
void process_script(struct peapod_packet packet, struct action_t *action,
		    uint8_t dir)
{
	char *desc = NULL;		/* see struct decode_t */
	char *framepkt = NULL;		/* "frame" or "EAP-Packet" */
	char *path = NULL;

	/* Sample outputs:
	 * "received Success EAP-Packet on 'eth1'; executing '...'"
	 * "sending EAPOL-Start frame from 'eth0' on 'eth1'; executing '...'"
	 */
	char *fmt_ingress = "received %s %s on '%%s'; executing '%%s'";
	char *fmt_egress = "sending %s %s from '%s' on '%%s'; executing '%%s'";

	char buf[128] = { "" };

	if (action->frame[packet.type] != NULL) {
		desc = packet_decode(packet.type, eapol_types);
		framepkt = "frame";
		path = action->frame[packet.type];
	} else if (packet.type == EAPOL_EAP_PACKET &&
		   action->packet[packet.code] != NULL) {
		desc = packet_decode(packet.code, eap_codes);
		framepkt = "EAP-Packet";
		path = action->packet[packet.code];
	}

	if (path == NULL)
		return;

	if (dir == PROCESS_EGRESS)
		snprintf(buf, sizeof(buf), fmt_egress, desc, framepkt,
			 packet.name_orig);
	else
		snprintf(buf, sizeof(buf), fmt_ingress, desc, framepkt);

	if (args.quiet == 1)
		info(buf, packet.name, path);
	else
		notice(buf, packet.name, path);

	script(packet, path);
}
