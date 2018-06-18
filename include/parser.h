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
 * @brief 802.1Q VLAN Tag Control Information.
 *
 * Stores the three variable fields in a 4-byte 802.1Q VLAN tag.
 */
struct tci_t {
	uint8_t pcp;			/**< @brief Priority Code Point. */
	uint8_t dei;			/**< @brief Drop Eligible Indicator. */
	uint16_t vid;			/**< @brief Identifier. */
};

/**
 * @brief Bitmasks for filtering on EAPOL Packet Type or EAP Code.
 *
 * EAPOL Packet Types range from 0-8 (requires 2 bytes); EAP Codes range from
 * 1-4. Whether an instance of <tt>struct filter_t</tt> stores ingress or egress
 * filters depends on whether its parent is a <tt>struct ingress_t</tt> or a
 * <tt>struct egress_t</tt>.
 */
struct filter_t {
	uint16_t type;			/**< @brief Filter on EAPOL Packet Type. */
	uint8_t code;			/**< @brief Filter on EAP Code. */
};

/**
 * @brief Scripts to execute on EAPOL Packet Type or EAP Code.
 *
 * @p type and @p code are arrays of C strings containing either the path to an
 * executable script or @p NULL. Whether an instance of
 * <tt>struct action_t</tt> stores ingress or egress scripts depends on whether
 * its parent is a <tt>struct ingress_t</tt> or a <tt>struct egress_t</tt>.
 *
 * @note EAP Codes only range from 1-4, so @p packet[0] is always @p NULL.
 */
struct action_t {
	char *type[9];			/**< @brief Run script on EAPOL Packet Type. */
	char *code[5];			/**< @brief Run script on EAP Code. */
};

/** @brief Behavior during the ingress phase for an interface. */
struct ingress_t {
	/**
	 * @brief Network interface name.
	 * 
	 * When the named interface receives an EAPOL packet for the first time,
	 * the current interface's MAC address will be changed to match the
	 * packet's source MAC address, and this field will be cleared.
	 *
	 * @note If this is set, the @p set_mac member of a parent
	 *       <tt>struct iface_t</tt> will be unset.
	 */
	char set_mac[IFNAMSIZ];
	struct action_t *action;	/**< @brief Run script on ingress. */	
	struct filter_t *filter;	/**< @brief Filter on ingress. */
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
	char name[IFNAMSIZ];		/**< @brief Network interface name. */
	int index;			/**< @brief Interface index. */
	int mtu;			/**< @brief Maximum Transmission Unit. */
	int skt;			/**< @brief Raw socket bound to the interface. */
	int recv_ctr;			/**< @brief Number of EAPOL packets received. */
	int send_ctr;			/**< @brief Number of EAPOL packets sent. */
	struct ingress_t *ingress;	/**< @brief Ingress options. */
	struct egress_t *egress;	/**< @brief Egress options. */
	uint8_t promisc;		/**< @brief Flag: Set promiscuous mode on @p skt. */
	/**
	 * @brief @p A MAC address, plus a magic number.
	 *
	 * During program startup, the MAC address of the network interface
	 * represented by the current instance of <tt>struct iface_t</tt> will
	 * be changed to match the first @p ETH_ALEN bytes of this field, and
	 * the final byte will be cleared.
	 *
	 * @note If this is set, its final byte will be set to
	 *       <tt>IFACE_SET_MAC<tt>, and the @p set_mac member of a child
	 *       <tt>struct ingress_t</tt> will be unset.
	 */
	u_char set_mac[ETH_ALEN + 1];
	struct iface_t *next;		/**< @brief Next node. */
};

struct iface_t *parse_config(const char* path);
void parser_print_ifaces(struct iface_t *list);
