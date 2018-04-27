#pragma once

/* Same as struct tpacket_auxdata from <linux/if_packet.h>, but define it
 * ourselves, as tp_vlan_tpid is called tp_padding in Linux <3.14.
 */
struct packet_auxdata_t {
	__u32 tp_status;
	__u32 tp_len;
	__u32 tp_snaplen;
	__u16 tp_mac;
	__u16 tp_net;
	__u16 tp_vlan_tci;
	__u16 tp_vlan_tpid;
};

/* EAP-Packet (EAP Packet) format (RFC 3748 §4) */
struct eap_packet {
	__u8 code;			/* Packet code */
	__u8 id;			/* Identifier */
	__be16 len;			/* Length */
	__u8 type;			/* Type of Request or Response */
	// __u8 type_data[];		/* Payload (variable length) */
}__attribute__((packed));

/* EAPOL-Key (Key Descriptor) format (IEEE Std 802.1X-2001 §7.6) */
struct eapol_key {
	__u8 desc_type;			/* Descriptor type */
	__be16 key_len;			/* Key length */
	__be64 replay_ctr;		/* Replay counter */
	__u8 key_iv[16];		/* Key initialization vector */
	__u8 key_index;			/* Key index */
	__u8 key_sig[16];		/* Key signature */
	// __u8 key[];			/* Key (variable length) */
}__attribute__((packed));

/* 802.3 EAPOL frame format (IEEE Std 802.1X-2001 §7.2 */
struct eapolhdr {
	__be16 ether_type;		/* PAE Ethernet Type */
	__u8 proto_ver;			/* EAPOL protocol version */
	__u8 type;			/* Frame type */
	__be16 pkt_body_len;		/* Length of following packet */
	union {
		struct eap_packet eap;	/* EAP-Packet */
		struct eapol_key key;	/* EAPOL-Key */
		// struct eapol_eaa eaa;/* EAPOL-Encapsulated-ASF-Alert */
	}__attribute__((packed));
}__attribute__((packed));

/* The EAPOL PDU, with some metadata already extracted */
struct peapod_packet {
	struct timeval tv;
	struct iface_t *iface;
	struct iface_t *iface_orig;
	char *name;
	char *name_orig;
	ssize_t len;
	ssize_t len_orig;
	uint8_t h_dest[ETH_ALEN];
	uint8_t h_source[ETH_ALEN];
	uint8_t vlan_valid;		/* flag */
	uint8_t vlan_valid_orig;
	struct tci_t tci;
	struct tci_t tci_orig;		/* TCI of original 802.1Q header */
	uint8_t type;			/* EAPOL frame Type */
	uint8_t code;			/* EAP-Packet Code */
	struct eapolhdr *pdu;		/* Begins: 0x88 0x8e */
};

struct decode_t {
	uint8_t val;			/* Value */
	char *desc;			/* Description */
};

/* EAPOL frame Type (IEEE Std 802.1X-2001 §7.5.4) */
#define EAPOL_EAP_PACKET		0
#define EAPOL_START			1
#define EAPOL_LOGOFF			2
#define EAPOL_KEY			3
#define EAPOL_ENCAP_ASF_ALERT		4

static const struct decode_t eapol_types[] = {
	{ EAPOL_EAP_PACKET,		"EAP-Packet" },
	{ EAPOL_START,			"EAPOL-Start" },
	{ EAPOL_LOGOFF,			"EAPOL-Logoff" },
	{ EAPOL_KEY,			"EAPOL-Key" },
	{ EAPOL_ENCAP_ASF_ALERT,	"EAPOL-Encapsulated-ASF-Alert" },
	{ 0, NULL }
};

/* EAP-Packet Code (RFC 2284 §2.2 - yes yes, superseded by RFC 3748) */
#define EAP_PACKET_REQUEST		1
#define EAP_PACKET_RESPONSE		2
#define EAP_PACKET_SUCCESS		3
#define EAP_PACKET_FAILURE		4

static const struct decode_t eap_codes[] = {
	{ EAP_PACKET_REQUEST,		"Request" },
	{ EAP_PACKET_RESPONSE,		"Response" },
	{ EAP_PACKET_SUCCESS,		"Success" },
	{ EAP_PACKET_FAILURE,		"Failure" },
	{ 0, NULL }
};

/* For EAP-Packet Codes 1 and 2, Request/Response, Type (RFC 3748 §5) */
#define EAP_TYPE_IDENTITY		1
#define EAP_TYPE_NOTIFICATION		2
#define EAP_TYPE_NAK			3
#define EAP_TYPE_MD5_CHALLENGE		4
#define EAP_TYPE_OTP			5
#define EAP_TYPE_GTC			6
#define EAP_TYPE_TLS			13	/* RFC 2716 §4.1 */
#define EAP_TYPE_SIM			18	/* RFC 4186 §8.1 */
#define EAP_TYPE_TTLS			21	/* RFC 5281 §9.1 */
#define EAP_TYPE_AKA_OLD		23	/* RFC 4187 §8.1 */
#define EAP_TYPE_PEAP			25	/* draft-josefsson-pppext-eap-tls-eap-06.txt §3.1 */
#define EAP_TYPE_MS_CHAP_V2		26	/* draft-kamath-pppext-eap-mschapv2-02.txt §2 */
#define EAP_TYPE_MS_CHAP_V2_OLD		29	/* draft-dpotter-pppext-eap-mschap-01.txt §4.1 */
#define EAP_TYPE_FAST			43	/* RFC 4851 §4.1 */
#define EAP_TYPE_IKEV2			49	/* RFC 5106 §8 */
#define EAP_TYPE_EXPANDED_TYPES		254
#define EAP_TYPE_EXPERIMENTAL_USE	255

static const struct decode_t eap_types[] = {
	/* Descriptions as stated in the relevant RFCs */
	{ EAP_TYPE_IDENTITY,		"Identity" },
	{ EAP_TYPE_NOTIFICATION,	"Notification" },
	{ EAP_TYPE_NAK,			"Nak (Response only)" },
	{ EAP_TYPE_MD5_CHALLENGE,	"MD5-Challenge" },
	{ EAP_TYPE_OTP,			"One Time Password (OTP)" },
	{ EAP_TYPE_GTC,			"Generic Token Card (GTC)" },
	{ EAP_TYPE_TLS,			"EAP TLS" },
	{ EAP_TYPE_SIM,			"EAP-SIM" },
	{ EAP_TYPE_TTLS,		"EAP-TTLS" },
	{ EAP_TYPE_AKA_OLD,		"EAP-AKA" },
	{ EAP_TYPE_PEAP,		"PEAP" },
	{ EAP_TYPE_MS_CHAP_V2,		"EAP MS-CHAP-V2" },
	{ EAP_TYPE_MS_CHAP_V2_OLD,	"EAP MS-CHAP V2" },
	{ EAP_TYPE_FAST,		"EAP-FAST" },
	{ EAP_TYPE_IKEV2,		"EAP-IKEv2"},
	{ EAP_TYPE_EXPANDED_TYPES,	"Expanded Types" },
	{ EAP_TYPE_EXPERIMENTAL_USE,	"Experimental use" },
	{ 0, NULL }
};

/* For EAPOL frame Type 3, EAPOL-Key, Key Descriptor Type */
#define EAPOL_KEY_TYPE_RC4		1	/* IEEE Std 802.1X-2001 §7.6.1 */

static const struct decode_t eapol_key_types[] = {
	{ EAPOL_KEY_TYPE_RC4,		"RC4" },
	{ 0, NULL }
};

void packet_init(struct iface_t *ifaces);
uint8_t *packet_buf(struct peapod_packet packet, uint8_t orig);
char* packet_decode(uint8_t val, const struct decode_t *decode);
uint32_t packet_tcitonl(struct tci_t tci);
int packet_send(struct peapod_packet packet, struct iface_t *iface);
struct peapod_packet packet_recvmsg(struct iface_t *iface);
