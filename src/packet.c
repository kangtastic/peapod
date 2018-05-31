/**
 * @file packet.c
 * @brief EAPOL frame/packet operations
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include "args.h"
#include "log.h"
#include "packet.h"
#include "process.h"

static void dump(struct peapod_packet pkt);
static void decode(struct peapod_packet pkt);

/**
 * @name Main buffer for an EAPOL frame
 *
 * The size of this buffer is normally 1518 bytes given a 1500-byte MTU, to
 * accommodate the standard 1514-byte Ethernet frame size plus a 4-byte 802.1Q
 * tag. We use an @p iovec with @p recvmsg(2) to split off the destination and
 * source MAC addresses into their own fields of a <tt>struct peapod_packet</tt>
 * structure at the point of capture, reading only the EAPOL PDU (EtherType and
 * MTU, normally 1502 bytes) into bytes 16:, and obtaining any 802.1Q tag via
 * a @p PACKET_AUXDATA cmsg from the kernel. Bytes 0:15 may then serve as
 * scratch space for us to reconstruct the complete EAPOL frame.
 *
 * This allows us to do things like adding, modifying, or removing an 802.1Q tag
 * for a proxied frame on a per-egress-interface basis. We simply
 * reconstruct/modify the first 16 bytes of this buffer as needed, then call
 * @p write(2) on the socket file descriptor with the proper memory offset.
 * @{
 */

/** @brief Beginning of the main EAPOL frame buffer. */
static uint8_t *pkt_buf = NULL;

/**
 * @brief The EAPOL PDU. Global.
 *
 * Points to byte 16 of the main EAPOL frame buffer, and thereby to the EAPOL
 * EtherType (0x888e) followed by the (normally 1500-byte) MTU.
 */
uint8_t *pdu_buf = NULL;

/** @brief Normally 1518 bytes. */
static int pkt_buf_size = 0;
/** @brief Normally 1502 bytes. Global. */
int pdu_buf_size = 0;
/** @} */

/**
 * @brief A buffer for receiving a <tt>struct packet_auxdata_t</tt>
 *        (actually a <tt>struct tpacket_auxdata</tt>) from the kernel via
 *        @p recvmsg(2).
 * @see @p socket(7), "Socket options".
 */
static union {
	struct cmsghdr cmsg;
	uint8_t buf[CMSG_SPACE(sizeof(struct packet_auxdata_t))];
} cmsg_buf;

/** 
 * @brief A <tt>struct msghdr</tt> for @p recvmsg(2).
 * @see @p recvmsg(2).
 */
static struct msghdr msg = {
	.msg_name = NULL,
	.msg_namelen = 0,
	.msg_control = &cmsg_buf,
	.msg_controllen = sizeof(cmsg_buf),
	.msg_flags = 0
};

extern struct args_t args;

/**
 * @brief Log a hexadecimal dump of a <tt>struct peapod_packet</tt>.
 * @param packet A <tt>struct peapod_packet</tt> structure representing an
 *               EAPOL frame.
 */
static void dump(struct peapod_packet packet)
{
	if (args.level < LOG_DEBUGLOW)
		return;		/* Do less work if not low-level debugging. */

	char buf[51] = { "" };
	int l = 0;
	uint8_t *start = packet_buf(packet, packet.iface == packet.iface_orig ?
				    1 : 0);

	/* Sample output:
	 * fe:ed:fa:ce:ca:11 EAPOL-Start to PAE multicast MAC, prio 3
	 *   0x0000:  0180 c200 0003 feed face ca11 8100 6000
	 *   0x0010:  888e 0101 0000 0000 0000 0000 0000 0000
	 *   0x0020:  0000 0000 0000 0000 0000 0000 0000 0000
	 *   0x0030:  0000 0000 0000 0000 0000 0000 0000 0000
	 */
	for(int pos = 0; pos < packet.len; pos++) {
		if (pos % 16 == 0)
			l = snprintf(buf, sizeof(buf), "  0x%.04x:  ", pos);

		l += snprintf(buf + l, sizeof(buf) - l, "%.02x", start[pos]);

		if (pos % 2 == 1 && pos % 16 != 15)
			l += snprintf(buf + l, sizeof(buf) - l, " ");

		if (pos % 16 == 15 || pos + 1 == packet.len)
			debuglow("%s", buf);
	}
}

/**
 * @brief Log metadata for a <tt>struct peapod_packet</tt> in a
 *        <tt>tcpdump</tt>-like format.
 * @param packet A <tt>struct peapod_packet</tt> structure representing an
 *               EAPOL frame.
 */
static void decode(struct peapod_packet packet)
{
	char buf[192] = { "" };		/* need 181 */
	int l;

	struct eapolhdr *pdu = packet.pdu;

	/* "recv 1024 bytes on 'eth0': {source MAC} > {dest MAC}" */
	l = snprintf(buf, sizeof(buf), "%s %ld bytes on '%s'",
		     packet.name == packet.name_orig ? "recv" : "send",
		     packet.len, packet.name);
	l += snprintf(buf + l, sizeof(buf) - l, ": %s",
		      iface_strmac(packet.h_source));
	l += snprintf(buf + l, sizeof(buf) - l, " > %s",
		      iface_strmac(packet.h_dest));

	/* "..., vlan 0 (prio 6, dei unset)" */
	if (packet.vlan_valid == 1)
		l += snprintf(buf + l, sizeof(buf) - l,
			      ", vlan %d (prio %d, dei %sset)",
			      packet.tci.vid, packet.tci.pcp,
			      packet.tci.dei == 1 ? "" : "un");

	/* "..., EAP-Packet (0) v2", "..., EAPOL-Key (3) v1", */
	l += snprintf(buf + l, sizeof(buf) - l, ", %s (%d) v%d",
		     packet_decode(pdu->type, eapol_types),
		     pdu->type, pdu->proto_ver);

	/* "..., Response/Identity (1), id 123, len 456", "..., Success" */
	if (pdu->type == EAPOL_EAP_PACKET) {
		struct eap_packet *eap = &pdu->eap;	/* convenience */

		l += snprintf(buf + l, sizeof(buf) - l, ", %s",
			      packet_decode(eap->code, eap_codes));

		if (eap->code == EAP_PACKET_REQUEST ||
		    eap->code == EAP_PACKET_RESPONSE)
			l += snprintf(buf + l, sizeof(buf) - l, "/%s (%d)",
				      packet_decode(eap->type, eap_types),
				      eap->type);

		l += snprintf(buf + l, sizeof(buf) - l, ", id %d, len %d",
			      eap->id, ntohs(eap->len));
	} else if (pdu->type == EAPOL_KEY) {
		struct eapol_key *key = &pdu->key;

		/* "..., type RC4-128 (1)" */
		l += snprintf(buf + l, sizeof(buf) - l, ", type %s-%d (%d)",
			     packet_decode(key->desc_type, eapol_key_types),
			     ntohs(key->key_len) * 8, key->desc_type);

		/* "..., index 64, unicast" */
		l += snprintf(buf + l, sizeof(buf) - l, ", index %d (%scast)",
			     key->key_index & 0x7f,
			     key->key_index & 0x80 ? "uni" : "broad");
	}

	debug("%s", buf);
}

/**
 * @brief Allocate the main buffer for the EAPOL frame.
 * 
 * The size of the buffer is determined according to the highest MTU of the
 * network interfaces used by the program.
 *
 * @param ifaces A pointer to a list of <tt>struct iface_t</tt> structures
 *               representing network interfaces.
 */
void packet_init(struct iface_t *ifaces)
{
	int high_mtu = 0;
	struct iface_t *high_mtu_iface = NULL;
	for (struct iface_t *i = ifaces; i != NULL; i = i->next) {
		if (high_mtu < i->mtu) {
			high_mtu = i->mtu;
			high_mtu_iface = i;
		}
	}
	debug("highest MTU was %d, interface '%s'",
	      high_mtu, high_mtu_iface->name);

	pkt_buf_size = (ETH_ALEN * 2) +		/* 12, dest/src hwaddrs */
		       sizeof(uint32_t) +	/* 4, (possibly) a VLAN tag */
		       sizeof(uint16_t) +	/* 2, EtherType/size */
		       high_mtu;

	pkt_buf = malloc(pkt_buf_size);		/* 1518 if MTU is 1500 */
	if (pkt_buf == NULL)
		ecritdie("cannot allocate main packet buffer: %s");

	pdu_buf = pkt_buf + (ETH_ALEN * 2) + sizeof(uint32_t);	/* + 16 */
	pdu_buf_size = sizeof(uint16_t) + high_mtu;		/* EtherType */
}

/**
 * @brief Return a pointer to a raw EAPOL frame.
 *
 * Rewrites the first 16 bytes of the main packet buffer. The result shall point
 * to the beginning of a raw EAPOL frame that is either:
 * -# the original frame, including the VLAN tag, as it appeared when it was
 *    captured on the ingress interface, or
 * -# the processed frame, possibly with original VLAN tag removed or tag fields
 *    changed according to interface egress suboptions, that should be sent out
 *    on a given egress interface.
 *
 * The result may then be used by the caller to (hex)dump, Base64-encode, and/or
 * send the frame.
 *
 * @param packet A <tt>struct peapod_packet</tt> structure representing an
 *               EAPOL frame.
 * @param orig A flag that determines whether the result points to the original
 *             frame as seen on the ingress interface, or to a processed frame
 *             that should be sent on an egress interface.
 * @return A pointer to the beginning of a complete EAPOL frame.
 */
uint8_t *packet_buf(struct peapod_packet packet, uint8_t orig) {
	uint8_t vlan_valid;
	struct tci_t tci;
	if (orig == 1) {
		vlan_valid = packet.vlan_valid_orig;
		tci = packet.tci_orig;
	} else {
		vlan_valid = packet.vlan_valid;
		tci = packet.tci;
	}

	if (vlan_valid) {
		uint32_t dot1q = packet_tcitonl(tci);
		memcpy(pdu_buf - (ETH_ALEN * 2) - sizeof(uint32_t),
		       packet.h_dest, ETH_ALEN);
		memcpy(pdu_buf - ETH_ALEN - sizeof(uint32_t),
		       packet.h_source, ETH_ALEN);
		memcpy(pdu_buf - sizeof(uint32_t), &dot1q, sizeof(uint32_t));

		return pdu_buf - (ETH_ALEN * 2) - sizeof(uint32_t);  /* -16 */
	} else {
		memcpy(pdu_buf - (ETH_ALEN * 2), packet.h_dest, ETH_ALEN);
		memcpy(pdu_buf - ETH_ALEN, packet.h_source, ETH_ALEN);

		return pdu_buf - (ETH_ALEN * 2);  /* -12 */
	}
}

/**
 * @brief Convert a <tt>struct tci_t</tt> to a 4-byte 802.1Q tag.
 * @param tci A <tt>struct tci_t</tt> structure representing the fields of an
 *            802.1Q tag.
 * @return An unsigned 32-bit integer in network order.
 */
uint32_t packet_tcitonl(struct tci_t tci)
{
	uint32_t ret = ETH_P_8021Q;
	ret = (ret << 4) | ((tci.pcp & 0x07) << 1) | (tci.dei & 0x01);
	ret =  (ret << 12) | (tci.vid & 0x0fff);
	return htonl(ret);
}

/**
 * @brief Decode a byte in an EAPOL frame to a C string.
 *
 * The byte may be one of the following:
 * -# the Type field of an EAPOL frame,
 * -# if the EAPOL frame encapsulates an EAP-Packet, the Code field of the
 *    EAP-Packet, or
 * -# if the EAP-Packet encapsulates an EAP-Request or EAP-Response, the Type
 *    field of the EAP-Request or EAP-Response.
 *
 * @param val The value of the relevant byte to decode.
 * @param decode A pointer to a <tt>struct decode_t</tt> structure matching
 *               field values with descriptions.
 * @return A C string containing a description, or "Unknown" if the value does
 *         not have a corresponding description in @p decode.
 */
char* packet_decode(uint8_t val, const struct decode_t *decode)
{
	char *ret = "Unknown";
	while (decode->desc != NULL) {
		if (val == decode->val) {
			ret = decode->desc;
			break;
		}
		++decode;
	}
	return ret;
}

/**
 * @brief Send an EAPOL frame on a network interface.
 *
 * Also executes an egress script if @p iface->egress->action is a
 * <tt>struct action_t</tt> structure.
 *
 * @param packet A <tt>struct peapod_packet</tt> structure representing an
 *               EAPOL frame.
 * @param iface A pointer to a <tt>struct iface_t</tt> structure representing a
 *              network interface.
 * @return The number of bytes successfully sent.
 */
int packet_send(struct peapod_packet packet, struct iface_t *iface)
{
/*	A raw socket on a 1500 MTU iface lets us send 1514 arbitrary bytes, for
	dest and src hwaddrs, EtherType, and MTU-sized payload. How do we bring
	that up to those same 1514 bytes + 4-byte 802.1Q tag = 1518 bytes?

	Didn't work - sent 1514 bytes, wouldn't insert VLAN tag:
		sendmsg() with a 1514-byte iovec, and a PACKET_AUXDATA cmsg with
		tp_status set to TP_STATUS_SEND_REQUEST, tp_vlan_tpid and
		tp_vlan_tci set appropriately

	Didn't work - failed outright, strerror(errno) gives "Message too long":
		sendmsg() and writev() with a 1518-byte iovec

	/!\ OMG /!\ Did work /!\ WTF /!\:
		write() with the 802.1Q tag at bytes 12:15, 1518 total, e.g.

		int mtu = 1500;
		uint8_t *buf = malloc(mtu + 18);

		uint32_t dot1q = htonl(0x8100fffe);	// vlan 4094, p 7, DEI

		memset(buf, 0xff, 12);			// dest and src hwaddrs
		memcpy(buf + 12, &dot1q, 4);
		memset(buf + 16, 0xff, 1502);		// EtherType/size + MTU

		ssize_t len = write(iface->skt, buf, buf_size);	// len == 1518!

		Excellent! Looks like regular old write() is the way to go.

	P.S. Didn't work: write() with QinQ at bytes 12:19. >;]
*/
	packet.iface = iface;
	packet.name = iface->name;

	if (iface->egress != NULL && iface->egress->tci != NULL) {
		struct tci_t *iface_tci = iface->egress->tci;

		if (iface_tci->pcp == TCI_NO_DOT1Q) {
			packet.vlan_valid = 0;

			memset(&packet.tci, 0, sizeof(packet.tci));
		} else {
			packet.vlan_valid = 1;

			if (iface_tci->pcp != TCI_UNTOUCHED)
				packet.tci.pcp = iface_tci->pcp;
			if (iface_tci->dei != TCI_UNTOUCHED)
				packet.tci.dei = iface_tci->dei;
			if (iface_tci->vid != TCI_UNTOUCHED_16)
				packet.tci.vid = iface_tci->vid;
		}
	}

	uint8_t *start = packet_buf(packet, 0);

	if (packet.vlan_valid == 1 && packet.vlan_valid_orig == 0)
		packet.len += sizeof(uint32_t);
	else if (packet.vlan_valid == 0 && packet.vlan_valid_orig == 1)
		packet.len -= sizeof(uint32_t);

	/* Execute script on egress */
	if (iface->egress != NULL && iface->egress->action != NULL)
		process_script(packet, iface->egress->action,
			       PROCESS_EGRESS);

	ssize_t len = write(iface->skt, start, packet.len);

	if (len == -1) {
		ecrit("cannot send, interface '%s':%s", iface->name);
		return -1;
	}
	else if (len != packet.len) {
		crit("sent %d bytes (expected %d), interface '%s'; "
		     "did this originally enter on a higher MTU interface?",
		     len, packet.len);
		return -1;
	}

	decode(packet);
	dump(packet);

	++iface->send_ctr;

	return 0;
}

/**
 * @brief Receive an EAPOL frame on a network interface.
 *
 * If the @p len and @p len_orig members of the result were set to at least 60,
 * several of the other members contain frame, packet, and EAP metadata.
 *
 * @return A <tt>struct peapod_packet</tt> structure representing an EAPOL
 *         frame, in which at least the @p len and @p len_orig members are set
 *         to the same value. That value shall be one of the following:
 *         -# the number of bytes successfully received (at least 60),
 *         -# -1 if an error occurred,
 *         -# -2 if fewer than 60 bytes were received (which would mean that the
 *            frame, including the 4-byte FCS, was smaller than the minimum
 *            Ethernet frame size of 64 bytes), or
 *         -# -3 if the frame was too big to fit in the main buffer for the
 *            EAPOL frame (which would mean that the MTU was ignored).
 */
struct peapod_packet packet_recvmsg(struct iface_t *iface) {
	struct peapod_packet ret;
	memset(&ret, 0, sizeof(ret));

	struct iovec iov[3] = {
		{ ret.h_dest, ETH_ALEN },
		{ ret.h_source, ETH_ALEN },
		{ pdu_buf, pdu_buf_size }
	};

	msg.msg_iov = iov;
	msg.msg_iovlen = 3;

	// ret.len = recvmsg(iface->skt, &msg, MSG_TRUNC);	DO NOT WANT
	ret.len = recvmsg(iface->skt, &msg, 0);

	if (ret.len == -1) {
		return ret;
	} else if (ret.len < 60) {	/* 64 bytes on the wire including FCS */
		ret.len = -2;
		return ret;
	/* Not passing MSG_TRUNC to recvmsg; we won't ever get here.

	} else if (ret.len > (ETH_ALEN * 2) + pdu_buf_size) {

		ret.len = -3;
		return ret;

	 */
	}

	if (ioctl(iface->skt, SIOCGSTAMP, &ret.tv) == -1) {
		eerr("cannot receive packet timestamp, interface '%s':%s",
		     iface->name);
		if (gettimeofday(&ret.tv, NULL) == -1)
			eerr("cannot even set the timestamp ourselves: ");
		else
			warning("had to set the timestamp ourselves");
	}

	ret.iface = iface;
	ret.name = iface->name;
	ret.pdu = (struct eapolhdr *)pdu_buf;

	/* Reconstruct and copy VLAN tag to result if found */
	for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	     cmsg != NULL;
	     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_type != PACKET_AUXDATA)
			continue;

		struct packet_auxdata_t *aux = (void *)CMSG_DATA(cmsg);

		debuglow("received a PACKET_AUXDATA cmsg:");
		debuglow("\taux=%p {", aux);
		debuglow("\t  tp_status=0x%.08x (TP_STATUS_VLAN_VALID=%s)",
			 aux->tp_status, aux->tp_status & TP_STATUS_VLAN_VALID ?
			 "y" : "n");
		debuglow("\t  tp_len=%d", aux->tp_len);
		debuglow("\t  tp_snaplen=%d", aux->tp_snaplen);
		debuglow("\t  tp_mac=0x%x", aux->tp_mac);
		debuglow("\t  tp_net=0x%x", aux->tp_net);
		debuglow("\t  tp_vlan_tci=0x%.04x", aux->tp_vlan_tci);
		debuglow("\t  tp_vlan_tpid=0x%.04x", aux->tp_vlan_tpid);
		debuglow("\t}");

		/* Looks like the non-hack alternative to MSG_TRUNC */
		if (ret.len < aux->tp_len) {
			ret.len = -3;
			return ret;
		}

		if (aux->tp_status & TP_STATUS_VLAN_VALID &&
		    aux->tp_vlan_tpid == ETH_P_8021Q) {
			/* Decode to a tci_t */
			uint32_t dot1q;				/* convenience */
			dot1q = aux->tp_vlan_tci;		/* not htons() */
			ret.tci.pcp = (dot1q & 0xe000) >> 13;
			ret.tci.dei = (dot1q & 0x1000) >> 12;
			ret.tci.vid = dot1q & 0x0fff;

			ret.len += 4;
			ret.vlan_valid = 1;
		}
		break;
	}

	ret.iface_orig = ret.iface;
	ret.name_orig = ret.name;
	ret.len_orig = ret.len;
	ret.vlan_valid_orig = ret.vlan_valid;
	ret.tci_orig = ret.tci;

	ret.type = ret.pdu->type;
	if (ret.type == EAPOL_EAP_PACKET)
		ret.code = ret.pdu->eap.code;

	decode(ret);
	dump(ret);

	return ret;
}
