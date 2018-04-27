/**
 * A little bit of a misnomer, as the struct definitions are used
 * throughout the program.
 */
#pragma once

#define u8tob_fmt			"%c%c%c%c%c%c%c%c"
#define u8tob(u8)			(u8 & 0x80 ? '1' : '0'), \
					(u8 & 0x40 ? '1' : '0'), \
					(u8 & 0x20 ? '1' : '0'), \
					(u8 & 0x10 ? '1' : '0'), \
					(u8 & 0x08 ? '1' : '0'), \
					(u8 & 0x04 ? '1' : '0'), \
					(u8 & 0x02 ? '1' : '0'), \
					(u8 & 0x01 ? '1' : '0')

#define IFACE_SET_MAC			0xff
#define TCI_NO_DOT1Q			0xef
#define TCI_UNTOUCHED			0xff
#define TCI_UNTOUCHED_16		0xffff

struct filter_t {
	uint8_t frame;			/* flags: filter on EAPOL frame type */
	uint8_t packet;			/* flags: filter on EAP packet code */
};

struct action_t {
	char *frame[5];			/* EAPOL frame Types range from 0-4 */
	char *packet[5];		/* but 1-4 for EAP packet Codes */
};

struct ingress_t {
	char set_mac[IFNAMSIZ];		/* should exclude iface.set_mac */
	struct filter_t *filter;
	struct action_t *action;
};

struct tci_t {				/* 802.1x Tag Control Information */
	uint8_t pcp;			/* Priority Code Point */
	uint8_t dei;			/* Drop Eligible Indicator */
	uint16_t vid;			/* VLAN ID */
};

struct egress_t {
	struct tci_t *tci;
	struct filter_t *filter;
	struct action_t *action;
};

struct iface_t {
	char name[IFNAMSIZ];		/* OS's name for iface */
	int index;			/* OS's index for iface */
	int mtu;
	int skt;			/* socket bound to interface */
	struct ingress_t *ingress;
	struct egress_t *egress;
	uint8_t promisc;		/* flag: set iface promiscuous mode */
	u_char set_mac[ETH_ALEN + 1];	/* exclude ingress.set_mac */
	struct iface_t *next;
};

struct iface_t *parse_config(const char* path);
void parser_print_ifaces(struct iface_t *list);
