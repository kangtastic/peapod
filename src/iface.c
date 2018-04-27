#include "includes.h"

static int validate(struct iface_t *iface);
static int epoll_register(int epfd, struct iface_t *iface);
static u_char *get_mac(struct iface_t *iface);
static int sockopt(struct iface_t *iface);
static inline void set_ifreq(char *name);

/* PAE Group Address (IEEE Std 802.1X-2001 §7.8) */
static const unsigned char pae_group_addr[ETH_ALEN] = {
	0x01, 0x80, 0xc2, 0x00, 0x00, 0x03
};

/**
 * Scenario: Create a socket with ETH_P_PAE as the @protocol. Set the
 * PACKET_AUXDATA option on the socket. Receive tpacket_auxdata structures
 * with readmsg() that contain 802.1Q tag info.
 *
 * Just kidding! ETH_P_PAE means no tpacket_auxdata structures. Thanks, Linux!
 *
 * Providing our own bpf filter, however, works fine. Note that the filter
 * checks bytes 12:13 - *after* Linux strips out the tag. That's actually nice.
 */
static struct sock_filter eapol_sock_filter[] = {
	{ 0x28, 0, 0, 0x0000000c },	// (000) ldh	[12]
	{ 0x15, 0, 1, 0x0000888e },	// (001) jeq	#0x888e	jt 2	jf 3
	{ 0x6, 0, 0, 0xbef001ed },	// (002) ret	#<decently big nonzero>
	{ 0x6, 0, 0, 0x00000000 }	// (003) ret	#0
};
static const struct sock_fprog eapol_fprog = {
	.len = 4,
	.filter = eapol_sock_filter
};

static struct ifreq ifr;

/**
 * Validate a network interface by running some basic checks on it.
 * Also sets the 'mtu' field in @iface to the interface's current MTU.
 *
 * @iface: A pointer to a struct iface_t structure representing a network
 *         interface.
 *
 * Returns 0 if successful, or -1 if unsuccessful.
 */
static int validate(struct iface_t *iface)
{
	/* Unnecessary, but do it anyway so as to not depend upon iface->skt. */
	int skt = socket(AF_INET, SOCK_DGRAM, 0);
	if (skt == -1) {
		eerr("cannot create socket to check state, interface '%s': %s",
		     iface->name);
		return -1;
	}

	set_ifreq(iface->name);
	if (ioctl(skt, SIOCGIFFLAGS, &ifr) == -1) {
		eerr("cannot read flags, interface '%s': %s", iface->name);
		close(skt);
		return -1;
	}

	if ((ifr.ifr_flags & IFF_UP) == 0) {
		err("not up, interface '%s'", iface->name);
		close(skt);
		return -1;
	}

	if (ioctl(skt, SIOCGIFMTU, &ifr) == -1) {
		ecrit("cannot read MTU, interface '%s': %s", iface->name);
		close(skt);
		return -1;
	}
	iface->mtu = ifr.ifr_mtu;

	close(skt);

	return 0;
}

/**
 * Registers the 'skt' member of @iface with an epoll instance.
 * Set as the event data a pointer to the same struct iface_t structure
 * as that pointed to by the @iface argument.
 *
 * @epfd: A file descriptor for an epoll instance.
 * @iface: A pointer to a struct iface_t structure representing a network
 *         interface.
 *
 * Returns 0 if successful, or -1 if unsuccessful.
 */
static int epoll_register(int epfd, struct iface_t *iface)
{
	struct epoll_event event;
	event.events = EPOLLIN;
	event.data.ptr = iface;

	if (epoll_ctl(epfd, EPOLL_CTL_ADD, iface->skt, &event) == -1) {
		eerr("cannot register socket with epoll: %s");
		return -1;
	}

	return 0;
}

/**
 * Query the kernel for the MAC address of a network interface. For this
 * function to succeed, the interface must be an Ethernet interface.
 *
 * @iface: A pointer to a struct iface_t structure representing a network
 *         interface.
 *
 * Returns a pointer to a static buffer containing ETH_ALEN bytes if successful,
 * or a null pointer if unsuccessful.
 */
static u_char *get_mac(struct iface_t *iface)
{
	static u_char buf[ETH_ALEN];

	set_ifreq(iface->name);

	/* Unnecessary, but do it anyway so as to not depend upon iface->skt. */
	int skt = socket(AF_INET, SOCK_DGRAM, 0);
	if (skt == -1) {
		eerr("cannot create socket to get MAC, interface '%s': %s",
		     iface->name);
		return NULL;
	}

	if (ioctl(skt, SIOCGIFHWADDR, &ifr) == -1) {
		eerr("cannot read MAC, interface '%s': %s", iface->name);
		close(skt);
		return NULL;
	}

	if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
		err("not Ethernet, interface '%s'", iface->name);
		close(skt);
		return NULL;
	}

	memcpy(buf, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	close(skt);

	return buf;
}


/**
 * Set socket options for the 'skt' member of a struct iface_t structure.
 * Attaches a bpf filter for the 802.1X EtherType, sets multicast or
 * promiscuous mode, and requests a PACKET_AUXDATA cmsg from the kernel.
 *
 * @iface: A pointer to a struct iface_t structure representing a network
 *         interface.
 *
 * Returns 0 if successful, or -1 if unsuccessful.
 */
static int sockopt(struct iface_t *iface)
{
	if (setsockopt(iface->skt, SOL_SOCKET, SO_ATTACH_FILTER,
		       &eapol_fprog, sizeof(eapol_fprog)) == -1) {
		eerr("cannot attach filter on socket, interface '%s': %s",
		     iface->name);
		return -1;
	}

	struct packet_mreq mreq;
	memset(&mreq, 0, sizeof(mreq));
	mreq.mr_ifindex = iface->index;

	if (iface->promisc == 1) {
		mreq.mr_type = PACKET_MR_PROMISC;
	} else {
		mreq.mr_type = PACKET_MR_MULTICAST;
		mreq.mr_alen = ETH_ALEN;
		memcpy(&mreq.mr_address, &pae_group_addr, ETH_ALEN);
	}

	if (setsockopt(iface->skt, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
		       &mreq, sizeof(mreq)) == -1) {
		eerr("cannot set %s mode, interface '%s': %s",
		     iface->promisc == 1 ? "promiscuous" : "multicast",
		     iface->name);
		return -1;
	}

	/**
	 * On Linux, a read on a "raw" socket returns a buffer with any VLAN tag
	 * stripped, but the tag is recoverable in a control message inside a
	 * struct tpacket_auxdata. Ask for it here.
	 */
	int tmp = 1;
	if (setsockopt(iface->skt, SOL_PACKET,
		       PACKET_AUXDATA, &tmp, sizeof(tmp)) == -1)
		einfo("there will be no 802.1Q info on interface '%s': %s",
		      iface->name);	/* Shouldn't happen on recent Linuxes. */

	return 0;
}

/**
 * Prepare the static ifreq structure for use with other functions in this file.
 *
 * @name: A C string containing Linux's name for a network interface.
 *
 * Returns nothing.
 */
static inline void set_ifreq(char *name)
{
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, name, IFNAMSIZ);
}

/**
 * Create raw sockets for interfaces in a list and add them to an epoll
 * instance. Also set interface MAC if 'set-mac' was specified in the config
 * file as an iface suboption, but not if it was specified as an ingress suboption.
 *
 * @ifaces: A pointer to a list of struct iface_t structures representing
 *          network interfaces.
 * @epfd: A file descriptor for an epoll instance.
 *
 * Returns the number of interfaces for which these steps were successful.
 */
int iface_init(struct iface_t *ifaces, int epfd)
{
	int ret = 0;

	struct sockaddr_ll sll;
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ALL);

	for (struct iface_t *i = ifaces; i != NULL; i = i->next) {
		debug("initialize interface '%s', index %d", i->name, i->index);

		if (i->skt != 0)
			close(i->skt);

		if (validate(i) == -1 || get_mac(i) == NULL)
			continue;

		if (i->set_mac[ETH_ALEN] == 0xff) {
			int result = iface_set_mac(i, NULL) == -1;
			memset(i->set_mac, 0, ETH_ALEN + 1);	/* oneshot */
			if (result == -1)
				warning("continuing; won't attempt that again");
		}

		i->skt = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
		if (i->skt == -1) {
			eerr("cannot create raw socket, interface '%s': %s",
			     i->name);
			continue;
		}

		sll.sll_ifindex = i->index;
		sll.sll_pkttype = PACKET_HOST | PACKET_MULTICAST;
		if (bind(i->skt, (struct sockaddr *)&sll, sizeof(sll)) == -1) {
			eerr("cannot bind raw socket, interface '%s': %s",
			     i->name);
			goto close_socket;
		}
		debug("bound socket %d to interface", i->skt);

		if (sockopt(i) == -1 || epoll_register(epfd, i) == -1)
			goto close_socket;	/* error messages in function */
		debug("socket registered with epoll");

		++ret;
		continue;
close_socket:
		close(i->skt);
	}
	return ret;
}

/**
 * Find the number of struct iface_t structures in a list of them.
 *
 * @iface: A pointer to a struct iface_t structure representing a network
 *         interface.
 *
 * Returns the number of structures in the list.
 */
int iface_count(struct iface_t *ifaces)
{
	int ret;
	for (ret = 0; ifaces != NULL; ifaces = ifaces->next)
		++ret;
	return ret;
}

/**
 * Set the MAC address of a network interface from a buffer of ETH_ALEN
 * bytes, or from the set-mac member of a struct iface_t structure.
 * Brings the interface down and back up while doing so.
 *
 * @iface: A pointer to a struct iface_t structure representing a network
 *         interface.
 * @source: A pointer to a buffer containing ETH_ALEN bytes representing a MAC
 *          address, or NULL to use the set_mac member of @iface.
 *
 * Returns 0 if successful, or -1 if unsuccessful.
 */
int iface_set_mac(struct iface_t *iface, u_char *source)
{
	u_char *new_mac = source != NULL ? source : iface->set_mac;
	if (new_mac == NULL) {
		err("cannot determine MAC to set, interface '%s'",
		      iface->name);
		return -1;
	}

	u_char *cur_mac = get_mac(iface);
	if (cur_mac == NULL) {
		err("cannot determine current MAC, interface '%s'",
		      iface->name);
		return -1;
	}

	if (memcmp(new_mac, cur_mac, ETH_ALEN) == 0)
		return 0;

	set_ifreq(iface->name);

	/* Unnecessary, but do it anyway so as to not depend upon iface->skt. */
	int skt = socket(AF_INET, SOCK_DGRAM, 0);
	if (skt == -1) {
		eerr("cannot create socket to set MAC, interface '%s': %s",
		     iface->name);
		return -1;
	}

	if (ioctl(skt, SIOCGIFFLAGS, &ifr) == -1) {
		eerr("cannot read flags, interface '%s': %s", iface->name);
		close(skt);
		return -1;
	}

	ifr.ifr_flags &= ~IFF_UP;
	if (ioctl(skt, SIOCSIFFLAGS, &ifr) == -1) {
		eerr("cannot bring down, interface '%s': %s", iface->name);
		close(skt);
		return -1;
	}

	memcpy(ifr.ifr_hwaddr.sa_data, new_mac, ETH_ALEN);
	ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
	if (ioctl(skt, SIOCSIFHWADDR, &ifr) == -1) {
		eerr("cannot set MAC, interface '%s': %s", iface->name);
		close(skt);
		return -1;
	}

	ifr.ifr_flags |= IFF_UP;
	if (ioctl(skt, SIOCSIFFLAGS, &ifr) == -1) {
		eerr("cannot bring up, interface '%s': %s", iface->name);
		close(skt);
		return -1;
	}

	if (ioctl(skt, SIOCGIFHWADDR, &ifr) == -1 ||
	    memcmp(ifr.ifr_hwaddr.sa_data, new_mac, ETH_ALEN) != 0) {
		err("cannot verify MAC, interface '%s'", iface->name);
		close(skt);
		return -1;
	}

	close(skt);

	info("set MAC to %s, interface '%s'",
	     iface_strmac(new_mac), iface->name);

	return 0;
}

/**
 * Convert a MAC address to a string (like ether_ntoa(3)).
 *
 * @mac: A pointer to a buffer containing ETH_ALEN bytes representing a MAC
 *       address.
 *
 * Returns a pointer to a static buffer containing the MAC address as a
 * C string in colon-delimited format.
 */
char *iface_strmac(u_char *mac)
{
	static char buf[19];
	snprintf(buf, sizeof(buf), "%.02x:%.02x:%.02x:%.02x:%.02x:%.02x",
	        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return buf;
}
