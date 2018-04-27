#include "includes.h"

static void dump(struct peapod_packet pkt);
static void decode(struct peapod_packet pkt);

static uint8_t *pkt_buf = NULL;	/* Will allocate 16 bytes in front as scratch */
uint8_t *pdu_buf = NULL;	/* global, EtherType + MTU (normal size 1502) */
static int pkt_buf_size = 0;	/* normal size 1518 */
int pdu_buf_size = 0;		/* global */

static union {
	struct cmsghdr cmsg;
	uint8_t buf[CMSG_SPACE(sizeof(struct packet_auxdata_t))];
} cmsg_buf;

static struct msghdr msg = {
	.msg_name = NULL,
	.msg_namelen = 0,
	.msg_control = &cmsg_buf,
	.msg_controllen = sizeof(cmsg_buf),
	.msg_flags = 0
};

extern struct args_t args;

/**
 * Print a hexadecimal dump of a struct peapod_packet.
 *
 * @packet: A struct peapod_packet structure representing an EAPOL frame.
 *
 * Returns nothing.
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
 * Print metadata for a struct peapod_packet in a tcpdump-like format.
 *
 * @packet: A struct peapod_packet structure representing an EAPOL frame.
 *
 * Returns nothing.
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
 * Allocate the main packet buffer according to the highest MTU of the network
 * interfaces which the program is using.
 *
 * @ifaces: A pointer to a list of struct iface_t structures representing
 *          network interfaces.
 *
 * Returns nothing.
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
 * Return a pointer to a raw EAPOL frame.
 * Rewrites the first 16 bytes of the main packet buffer. The returned frame
 * may have a VLAN tag at the appropriate position, according to metadata
 * contained in @packet and the value of @orig.
 *
 * The contents of the buffer, to the beginning of which the result points, will
 * be either a) the frame, including the VLAN tag, as it appeared when it was
 * captured on the ingress interface, or b) the processed frame, possibly with
 * original VLAN tag removed or tag fields changed according to interface egress
 * suboptions, that should be sent out on a given egress interface.
 *
 * After calling this function, it is safe for the caller to read, starting from
 * the result, packet.len or packet.len_orig bytes.
 *
 * @packet: A struct peapod_packet structure representing an EAPOL frame.
 * @orig: A flag that determines whether the result points to the original frame
 *        as seen on the ingress interface, or to the "cooked" frame that should
 *        be sent on an egress interface.
 *
 * Returns a pointer to the beginning of a raw EAPOL frame, somewhere within the
 * boundaries of the main packet buffer.
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
 * Convert a struct tci_t whose members contain the values of the three
 * fields in an 802.1Q tag to an unsigned 32-bit integer in network order.
 *
 * @tci: A struct tci_t structure representing the fields of an 802.1Q tag.
 *
 * Returns an unsigned 32-bit integer in network order.
 */
uint32_t packet_tcitonl(struct tci_t tci)
{
	uint32_t ret = ETH_P_8021Q;
	ret = (ret << 4) | ((tci.pcp & 0x07) << 1) | (tci.dei & 0x01);
	ret =  (ret << 12) | (tci.vid & 0x0fff);
	return htonl(ret);
}

/**
 * Retrieve the description of the Type field of an EAPOL frame, the Code field
 * of an EAP-Packet Code, or the Type field of an EAP-Request/-Response Packet.
 *
 * @val: The value of the relevant field to decode.
 * @decode: A pointer to a struct decode_t structure matching field values with
 *          descriptions.
 *
 * Returns a C string containing a description, or "Unknown" if the value
 * does not have a corresponding description in @decode.
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
 * Send an EAPOL frame on a network interface.
 * Also executes an egress script if one is defined in @iface for the Type of
 * the EAPOL frame, or if the frame Type was EAP-Packet (0), the Code of the
 * encapsulated EAP-Packet.
 *
 * @packet: A struct peapod_packet structure representing an EAPOL frame.
 * @iface: A pointer to a struct iface_t structure representing a network
 *         interface.
 *
 * Returns the number of bytes successfully sent. The success or failure of
 * the script execution is neither tracked nor reported.
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

	return 0;
}

/**
 * Receive an EAPOL frame on a network interface.
 *
 * @iface: A pointer to a struct iface_t structure representing a network
 *         interface.
 *
 * Returns a struct peapod_packet structure representing an EAPOL frame, in
 * which at least the len and len_orig members are set. These may be set to the
 * number of bytes successfully received (at least 60), to -1 if an error
 * occurred, to -2 if fewer than 60 bytes were received (which would mean that
 * the frame, including the 4-byte FCS, was smaller than the minimum Ethernet
 * frame size of 64 bytes), or to -3 if the frame was too big to fit in the main
 * packet buffer.
 *
 * If the len and len_orig members of the result were set to at least 60,
 * several of the other members contain frame, packet, and EAP metadata.
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
