/**
 * @file iface.c
 * @brief Network interface and socket setup.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include "iface.h"
#include "log.h"

static int validate(struct iface_t *iface);
static int epoll_register(int epfd, struct iface_t *iface);
static u_char *get_mac(struct iface_t *iface);
static int sockopt(struct iface_t *iface);
static inline void set_ifreq(char *name);

/**
 * @brief EAPOL Multicast Group MAC Addresses.
 * @see IEEE Std 802.1X-2010 §11.1.1
 */
static const u_char eapol_grp_mac[3][ETH_ALEN] = {
	{ 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00 },		/* Bridge */
	{ 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 },		/* Port Access Entity */
	{ 0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e }		/* LLDP */
};

/**
 * @name BPF filter for EAPOL packets
 *
 * Scenario - Create a socket with @p ETH_P_PAE as the protocol. Set the
 * @p PACKET_AUXDATA option on the socket. Receive @p tpacket_auxdata structures
 * with @p recvmsg(2) that contain 802.1Q tag info.
 *
 * <i>Just kidding!</i> @p ETH_P_PAE means no @p tpacket_auxdata structures.
 * Thanks, Linux!
 *
 * Providing our own @p bpf filter, however, works fine. Note that the filter
 * checks bytes 12:13 - @a after Linux strips out the tag. That's actually nice.
 *
 * @see @p socket(7), "Socket options"
 * @see @p bpf(2)
 * @{
 */

/**
 * @brief A simple @p bpf filter for EAPOL packets.
 *
 * The <tt>tcpdump</tt>-style @p bpf assembly equivalent is:
 * @code
 * (000) ldh	[12]
 * (001) jeq	#0x888e				jt 2	jf 3
 * (002) ret	#<decently big nonzero>
 * (003) ret	#0
 * @endcode
 */
static struct sock_filter eapol_sock_filter[] = {
	{ 0x28, 0, 0, 0x0000000c }, 
	{ 0x15, 0, 1, 0x0000888e }, 
	{ 0x6, 0, 0, 0xbef001ed }, 
	{ 0x6, 0, 0, 0x00000000 }
};

/** @brief The complete @p bpf filter program provided to @p setsockopt(3). */
static const struct sock_fprog eapol_fprog = {
	.len = 4,
	.filter = eapol_sock_filter
};
/**@}*/

/**
 * @brief A <tt>struct ifreq</tt> for @p ioctl on sockets.
 * @see @p netdevice(7)
 */
static struct ifreq ifr;

/**
 * @brief Check that a network interface is up and get its MTU.
 *
 * Also sets the @p mtu field of @p iface to the interface's current MTU.
 * 
 * @param iface A pointer to a <tt>struct iface_t</tt> structure representing a
 *              network interface.
 * @return 0 if successful, or -1 if unsuccessful.
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
 * @brief Register the @p skt field of @p iface with an @p epoll instance.
 *
 * As the event data, provide @p iface itself, so we know on which interface an
 * @p EPOLLIN event occurred.
 *
 * @param epfd A file descriptor for an @p epoll instance.
 * @param iface A pointer to a <tt>struct iface_t</tt> structure representing a
 *              network interface.
 * @return 0 if successful, or -1 if unsuccessful.
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
 * @brief Query the kernel for the MAC address of a network interface.
 *
 * @param iface A pointer to a <tt>struct iface_t</tt> structure representing a
 *              network interface.
 * @return A pointer to a static buffer containing @p ETH_ALEN bytes if
 *         successful, or @p NULL if unsuccessful.
 * @note For this to succeed, the interface must be an Ethernet interface.
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
 * @brief Set socket options for the @p skt field of a struct iface_t structure.
 *
 * Attaches a @p bpf filter for the 802.1X EtherType, sets multicast or
 * promiscuous mode, and requests a @p PACKET_AUXDATA cmsg from the kernel.
 *
 * @param iface A pointer to a <tt>struct iface_t</tt> structure representing a
 *              network interface.
 * @return 0 if successful, or -1 if unsuccessful.
 * @see @p cmsg(3)
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
		if (setsockopt(iface->skt, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
			       &mreq, sizeof(mreq)) == -1) {
			eerr("cannot set promiscuous mode, interface '%s': %s",
			     iface->name);
			return -1;
		}
	} else {
		mreq.mr_type = PACKET_MR_MULTICAST;
		mreq.mr_alen = ETH_ALEN;
		for (int i = 0; i < 3; i++) {
			memcpy(&mreq.mr_address, &eapol_grp_mac[i], ETH_ALEN);
			if (setsockopt(iface->skt, SOL_PACKET,
				       PACKET_ADD_MEMBERSHIP,
				       &mreq, sizeof(mreq)) == -1) {
				eerr("cannot add multicast group MAC %s, interface '%s': %s",
				     iface_strmac((u_char *)&eapol_grp_mac[i]),
				     iface->name);
				return -1;
			}
		}
	}

	/* On Linux, a read on a "raw" socket returns a buffer with any VLAN tag
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
 * @brief Prepare the static <tt>struct ifreq</tt> structure.
 * @param name A C string containing Linux's name for a network interface.
 * @see @p netdevice(7)
 */
static inline void set_ifreq(char *name)
{
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, name, IFNAMSIZ);
}

/**
 * @brief Create raw sockets for interfaces in a list and add them to an
 *        @p epoll instance.
 *
 * Also set interface MAC if @p set-mac was specified in the config file as an
 * @p iface suboption, but not if it was specified as an @p ingress suboption.
 *
 * @param ifaces A pointer to a list of <tt>struct iface_t</tt> structures
 *               representing network interfaces.
 * @param epfd A file descriptor for an @p epoll instance.
 * @return The number of interfaces for which these steps were successful.
 */
int iface_init(struct iface_t *ifaces, int epfd)
{
	int ret = 0;

	struct sockaddr_ll sll;
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ALL);

	for (struct iface_t *i = ifaces; i != NULL; i = i->next) {
		if (i->skt != 0)
			close(i->skt);

		if (validate(i) == -1 || get_mac(i) == NULL)
			continue;

		if (i->set_mac[ETH_ALEN] == IFACE_SET_MAC) {
			if (iface_set_mac(i, i->set_mac) == -1)
				warning("won't try to set MAC again, "
					"interface '%s'", i->name);
			memset(i->set_mac, 0, ETH_ALEN + 1);	/* oneshot */
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

		if (sockopt(i) == -1 || epoll_register(epfd, i) == -1)
			goto close_socket;	/* error messages in function */
		debug("initialized interface '%s', index %d, socket %d",
		      i->name, i->index, i->skt);

		++ret;
		continue;
close_socket:
		close(i->skt);
	}
	return ret;
}

/**
 * @brief Count the number of struct iface_t structures in a list.
 *
 * @param ifaces A pointer to a list of <tt>struct iface_t</tt> structures
 *               representing network interfaces.
 * @return The number of structures in the list.
 */
int iface_count(struct iface_t *ifaces)
{
	int ret;
	for (ret = 0; ifaces != NULL; ifaces = ifaces->next)
		++ret;
	return ret;
}

/**
 * @brief Set the MAC address of a network interface.
 * @param iface A pointer to a <tt>struct iface_t</tt> structure representing a
 *              network interface.
 * @param source A pointer to @p ETH_ALEN bytes containing a MAC address.
 * @return 0 if successful, or -1 if unsuccessful.
 * @note Brings the interface down and back up, invalidating all sockets on it.
 */
int iface_set_mac(struct iface_t *iface, u_char *source)
{
	if (source == NULL) {
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

	if (memcmp(source, cur_mac, ETH_ALEN) == 0)
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

	memcpy(ifr.ifr_hwaddr.sa_data, source, ETH_ALEN);
	ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
	if (ioctl(skt, SIOCSIFHWADDR, &ifr) == -1) {
		eerr("cannot set MAC to %s, interface '%s': %s",
		     iface_strmac(source), iface->name);
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
	    memcmp(ifr.ifr_hwaddr.sa_data, source, ETH_ALEN) != 0) {
		err("cannot verify MAC is %s, interface '%s'",
		    iface_strmac(source), iface->name);
		close(skt);
		return -1;
	}

	close(skt);

	info("set MAC to %s, interface '%s'",
	     iface_strmac(source), iface->name);

	return 0;
}

/**
 * @brief Convert a MAC address to a string.
 * @param mac A pointer to a buffer containing @p ETH_ALEN bytes representing a
 *            MAC address.
 * @return A C string in a static buffer containing the human-readable,
 *         colon-delimited MAC address.
 * @note Like @p ether_ntoa(3). Returns a static buffer whose contents change
 *       with each call to this function.
 * @see @p ether_ntoa(3)
 */
char *iface_strmac(u_char *mac)
{
	static char buf[19];
	snprintf(buf, sizeof(buf), "%.02x:%.02x:%.02x:%.02x:%.02x:%.02x",
	        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return buf;
}
