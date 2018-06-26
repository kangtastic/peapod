/**
 * @file packet.h
 * @brief Function prototypes for @p packet.c, EAPOL/EAP data structures
 */
#pragma once

#include <stdlib.h>
#include <linux/types.h>
#include "parser.h"

/**
 * @name EAPOL Packet Types
 * @see IEEE Std 802.1X-2010 §11.3.2
 * @{
 */
#define EAPOL_EAP			0
#define EAPOL_START			1
#define EAPOL_LOGOFF			2
#define EAPOL_KEY			3
#define EAPOL_ENCAPSULATED_ASF_ALERT	4
#define EAPOL_MKA			5
#define EAPOL_ANNOUNCEMENT_GENERIC	6
#define EAPOL_ANNOUNCEMENT_SPECIFIC	7
#define EAPOL_ANNOUNCEMENT_REQ		8
/** @} */

/**
 * @name EAP Code
 * @note RFC 2284 has been superseded by RFC 3748 and its successors,
 *       but the numeric Code values can only be found in the former.
 * @see RFC 2284 §2.2
 * @{
 */
#define EAP_CODE_REQUEST		1
#define EAP_CODE_RESPONSE		2
#define EAP_CODE_SUCCESS		3
#define EAP_CODE_FAILURE		4
/** @} */

/**
 * @name EAP-Request/Response Type
 *
 * These apply if the EAP packet has Code of either Request or Response.
 *
 * @see RFC 3748 §5 for the initial Types (1-6, 254-255)
 * @{
 */
#define EAP_TYPE_IDENTITY		1
#define EAP_TYPE_NOTIFICATION		2
#define EAP_TYPE_NAK			3
#define EAP_TYPE_MD5_CHALLENGE		4
#define EAP_TYPE_OTP			5
#define EAP_TYPE_GTC			6
#define EAP_TYPE_TLS			13	/**< @see RFC 2716 §4.1 */
#define EAP_TYPE_SIM			18	/**< @see RFC 4186 §8.1 */
#define EAP_TYPE_TTLS			21	/**< @see RFC 5281 §9.1 */
#define EAP_TYPE_AKA_OLD		23	/**< @see RFC 4187 §8.1 */
#define EAP_TYPE_PEAP			25	/**< @see draft-josefsson-pppext-eap-tls-eap-06.txt §3.1 */
#define EAP_TYPE_MS_CHAP_V2		26	/**< @see draft-kamath-pppext-eap-mschapv2-02.txt §2 */
#define EAP_TYPE_MS_CHAP_V2_OLD		29	/**< @see draft-dpotter-pppext-eap-mschap-01.txt §4.1 */
#define EAP_TYPE_FAST			43	/**< @see RFC 4851 §4.1 */
#define EAP_TYPE_IKEV2			49	/**< @see RFC 5106 §8 */
#define EAP_TYPE_EXPANDED_TYPES		254
#define EAP_TYPE_EXPERIMENTAL_USE	255
/** @} */

/**
 * @name EAPOL-Key Descriptor Type
 * @see IEEE Std 802.1X-2010 §11.9
 * @{
 */
#define EAPOL_KEY_TYPE_RC4		1	/**< @note Deprecated */
#define EAPOL_KEY_TYPE_IEEE_80211	2	/**< @see IEEE Std 802.11 */
/** @} */

/**
 * @brief A redefinition of <tt>struct tpacket_auxdata</tt> from
 *        <tt><linux/if_packet.h></tt>.
 *
 * We request a <tt>struct tpacket_auxdata</tt> from the kernel but interpret
 * it as a <tt>struct packet_auxdata_t</tt> to (theoretically) allow compilation
 * on earlier versions of Linux, as the @p tp_vlan_tpid member is called
 * @p tp_padding in Linux <3.14.
 *
 * @see packet(7)
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

/**
 * @brief EAPOL-EAP (EAP Packet) format.
 * @see RFC 3748 §4
 */
struct eapol_eap {
	__u8 code;			/**< @brief Packet Code */
	__u8 id;			/**< @brief Identifier */
	__be16 len;			/**< @brief Length */
	__u8 type;			/**< @brief Type (if Request or Response) */
	//__u8 type_data[];		/**< @brief EAP Packet (variable length) */
}__attribute__((packed));

/**
 * @brief EAPOL-Key (Key Descriptor) format.
 * @note Should only be used with RC4 key descriptors (now deprecated); however,
 *       the @p desc_type field is valid for all key descriptor types.
 * @see IEEE Std 802.1X-2001 §7.6
 * @see IEEE Std 802.1X-2010 §11.9
 */
struct eapol_key {
	__u8 desc_type;			/**< @brief Descriptor Type */
	__be16 key_len;			/**< @brief Key Length */
	__be64 replay_ctr;		/**< @brief Replay Counter */
	__u8 key_iv[16];		/**< @brief Key Initialization Vector */
	__u8 key_index;			/**< @brief Key Index */
	__u8 key_sig[16];		/**< @brief Key Signature */
	//__u8 key[];			/**< @brief Key (variable length) */
}__attribute__((packed));

/**
 * @brief EAPOL MAC Protocol Data Unit (MPDU) format.
 * @see IEEE Std 802.1X-2010 §11.3
 */
struct eapol_mpdu {
	__be16 ether_type;		/**< @brief PAE Ethernet Type */
	__u8 proto_ver;			/**< @brief Protocol Version */
	__u8 type;			/**< @brief Packet Type */
	__be16 pkt_body_len;		/**< @brief Packet Body Length */
	/** @brief Packet Body */
	union {
		struct eapol_eap eap;	/* EAPOL-EAP */
		struct eapol_key key;	/* EAPOL-Key */
		/* other EAPOL Packet Types are not decoded */
	}__attribute__((packed));
}__attribute__((packed));

/** @brief Represents an EAPOL packet with some metadata already extracted. */
struct peapod_packet {
	struct timeval tv;		/**< @brief Packet timestamp */
	struct iface_t *iface;		/**< @brief Current interface */
	struct iface_t *iface_orig;	/**< @brief Interface on which packet was originally received */
	ssize_t len;			/**< @brief Current length */
	ssize_t len_orig;		/**< @brief Original length */
	uint8_t h_dest[ETH_ALEN];	/**< @brief Destination MAC address */
	uint8_t h_source[ETH_ALEN];	/**< @brief Source MAC address */
	uint8_t vlan_valid;		/**< @brief Flag: VLAN (802.1Q) tag currently present? */
	uint8_t vlan_valid_orig;	/**< @brief Flag: VLAN (802.1Q) tag originally present? */
	struct tci_t tci;		/**< @brief Current 802.1Q Tag Control Information */
	struct tci_t tci_orig;		/**< @brief Original 802.1Q Tag Control Information */
	uint8_t type;			/**< @brief EAPOL Packet Type */
	uint8_t code;			/**< @brief EAP Code */
};

/**
 * @brief Matches a single-byte value with a description.
 *
 * The value in question may be an EAPOL Packet Type, EAP Code,
 * or EAP-Request/Reponse Type.
 */
struct decode_t {
	uint8_t val;			/**< @brief Value */
	char *desc;			/**< @brief Description */
};

/**
 * @brief EAPOL Packet Type descriptions.
 * @see IEEE Std 802.1X-2010 §11.3.2
 */
static const struct decode_t eapol_types[] = {
	{ EAPOL_EAP,			"EAPOL-EAP" },
	{ EAPOL_START,			"EAPOL-Start" },
	{ EAPOL_LOGOFF,			"EAPOL-Logoff" },
	{ EAPOL_KEY,			"EAPOL-Key" },
	{ EAPOL_ENCAPSULATED_ASF_ALERT,	"EAPOL-Encapsulated-ASF-Alert" },
	{ EAPOL_MKA,			"EAPOL-MKA" },
	{ EAPOL_ANNOUNCEMENT_GENERIC,	"EAPOL-Announcement (Generic)" },
	{ EAPOL_ANNOUNCEMENT_SPECIFIC,	"EAPOL-Announcement (Specific)" },
	{ EAPOL_ANNOUNCEMENT_REQ,	"EAPOL-Announcement-Req" },
	{ 0, NULL }
};

/**
 * @brief EAP Code descriptions.
 * @see RFC 2284 §2.2
 */
static const struct decode_t eap_codes[] = {
	{ EAP_CODE_REQUEST,		"Request" },
	{ EAP_CODE_RESPONSE,		"Response" },
	{ EAP_CODE_SUCCESS,		"Success" },
	{ EAP_CODE_FAILURE,		"Failure" },
	{ 0, NULL }
};

/**
 * @brief EAP-Request/Response Type descriptions.
 *
 * The text of the descriptions is as stated in the relevant RFCs.
 */
static const struct decode_t eap_types[] = {
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

/**
 * @brief Descriptions for EAPOL-Key Descriptor Type.
 * @see IEEE Std 802.1X-2010 §11.9
 */
static const struct decode_t eapol_key_types[] = {
	{ EAPOL_KEY_TYPE_RC4,		"RC4" },
	{ EAPOL_KEY_TYPE_IEEE_80211,	"IEEE 802.11" },
	{ 0, NULL }
};

void packet_init(struct iface_t *ifaces);
uint8_t *packet_buf(struct peapod_packet packet, uint8_t orig);
char* packet_decode(uint8_t val, const struct decode_t *decode);
uint32_t packet_tcitonl(struct tci_t tci);
int packet_send(struct peapod_packet packet, struct iface_t *iface);
struct peapod_packet packet_recvmsg(struct iface_t *iface);
