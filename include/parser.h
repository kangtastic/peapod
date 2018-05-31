/**
 * @file parser.h
 * @brief Function prototypes for @p parser.y, config-related magic numbers and
 *        data structures.
 * @note @p parser.y is not documented with Doxygen.
 */
#pragma once

#include <stdint.h>
#include <net/if.h>
#include <linux/if_ether.h>

/**
 * @name Magic number definitions
 * @{
 */
#define IFACE_SET_MAC			0xff
#define TCI_NO_DOT1Q			0xef
#define TCI_UNTOUCHED			0xff
#define TCI_UNTOUCHED_16		0xffff
/** @} */

/**
 * @brief 802.1X Tag Control Information.
 *
 * Represents the three variable fields in a 4-byte 802.1X VLAN tag.
 */
struct tci_t {
	uint8_t pcp;			/**< @brief Priority Code Point. */
	uint8_t dei;			/**< @brief Drop Eligible Indicator. */
	uint16_t vid;			/**< @brief Identifier. */
};

/**
 * @brief Masks for filtering on EAPOL frame Type or EAP-Packet Code.
 *
 * EAPOL frame Types range from 0-4, and EAP-Packet Codes range from 1-4. Filter
 * the current frame/packet if the corresponding bit in each byte is set.
 * Direction is derived from whether a given instance of
 * <tt>struct filter_t</tt> is pointed to in a <tt>struct ingress_t</tt> or a
 * <tt>struct egress_t</tt>.
 */
struct filter_t {
	uint8_t frame;			/**< @brief Filter on EAPOL frame Type. */
	uint8_t packet;			/**< @brief Filter on EAP-Packet Code. */
};

/**
 * @brief Scripts to execute on EAPOL frame Type or EAP-Packet Code.
 *
 * @p frame and @p packet are arrays of C strings containing the path to an
 * executable script, or @p NULL. Similarly to <tt>struct filter_t</tt>, execute
 * a script if the Type or Code of the current frame/packet corresponds to the
 * index of a C string in each array. Direction is derived from whether a given
 * instance of <tt>struct action_t</tt> is pointed to in a
 * <tt>struct ingress_t</tt> or a <tt>struct egress_t</tt>.
 *
 * Because EAP-Packet Codes only range from 1-4, packet[0] is always NULL.
 */
struct action_t {
	char *frame[5];			/**< @brief Run script on EAPOL frame Type. */
	char *packet[5];		/**< @brief Run script on EAP-Packet Code. */
};

/** @brief Behavior during the ingress phase for an interface. */
struct ingress_t {
	/**
	 * @brief Linux's name for a network interface.
	 * 
	 * When that interface receives an EAPOL frame for the first time, the
	 * current interface's MAC address will be changed to match the source
	 * MAC address in that frame, and this field will be cleared.
	 *
	 * @note If this is set, the parent <tt>struct iface_t</tt>'s @p set_mac
	 *       member won't be.
	 */
	char set_mac[IFNAMSIZ];
	struct filter_t *filter;	/**< @brief Filter on ingress. */
	struct action_t *action;	/**< @brief Run script on ingress. */
};

/** @brief Behavior during the egress phase for an interface. */
struct egress_t {
	struct tci_t *tci;		/**< @brief Add/edit/remove VLAN tag on egress. */
	struct filter_t *filter;	/**< @brief Filter on egress. */
	struct action_t *action;	/**< @brief Run script on egress. */
};

/**
 * @brief Represents a network interface and its associated config.
 *
 * Also a node in a singly linked list of <tt>struct iface_t</tt> structures.
 */
struct iface_t {
	char name[IFNAMSIZ];		/**< @brief Linux's name for the interface. */
	int index;			/**< @brief Interface index. */
	int mtu;			/**< @brief Maximum Transmission Unit. */
	int skt;			/**< @brief Raw socket bound to the interface. */
	int recv_ctr;			/**< @brief Number of EAPOL frames received. */
	int send_ctr;			/**< @brief Number of EAPOL frames sent. */
	struct ingress_t *ingress;	/**< @brief Ingress options. */
	struct egress_t *egress;	/**< @brief Egress options. */
	uint8_t promisc;		/**< @brief Flag: Set promiscuous mode on @p skt. */
	/**
	 * @brief @p A MAC address, plus a flag.
	 *
	 * During program startup, the MAC address of the network interface
	 * represented by the current instance of <tt>struct iface_t</tt> will
	 * be changed to match the first @p ETH_ALEN bytes of this field, and
	 * the final byte will be cleared.
	 *
	 * @note If this is set, a child <tt>struct ingress_t</tt>'s @p set_mac
	 * member won't be, and its final byte will be @p IFACE_SET_MAC.
	 */
	u_char set_mac[ETH_ALEN + 1];
	struct iface_t *next;		/**< @brief The next node. */
};

struct iface_t *parse_config(const char* path);
void parser_print_ifaces(struct iface_t *list);
