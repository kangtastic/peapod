/**
 * @file proxy.c
 * @brief Main event loop, related operations
 */
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/epoll.h>
#include "args.h"
#include "log.h"
#include "packet.h"
#include "process.h"

static void check_signals(void);
static int create_epoll(void);
static void spurious_event(char *name, uint32_t events);

extern volatile sig_atomic_t sig_hup;
extern volatile sig_atomic_t sig_int;
extern volatile sig_atomic_t sig_usr1;
extern volatile sig_atomic_t sig_term;

extern struct args_t args;

/** @brief Check and set signal counters */
static void check_signals(void) {
	if (sig_hup > 0) {
		notice("received SIGHUP");
		--sig_hup;
	}
	if (sig_int > 0) {
		warning("exiting on SIGINT");
		--sig_int;
		exit(EXIT_SUCCESS);
	}
	if (sig_usr1 > 0) {
		notice("received SIGUSR1");
		--sig_usr1;
	}
	if (sig_term > 0) {
		warning("exiting on SIGTERM");
		--sig_term;
		exit(EXIT_SUCCESS);	/* well, it's a "normal shutdown" */
	}
}

/**
 * @brief Create an @p epoll instance
 * @return 0 if successful, -1 if unsuccessful
 */
static int create_epoll(void)
{
	int ret = epoll_create(1);
	if (ret == -1)
		ecritdie("cannot create epoll instance: %s\n");

	return ret;
}

/**
 * @brief Log an error on receiving a spurious @p epoll event
 * @param name The name of a network interface
 * @param events The @p events field of a <tt>struct epoll_event</tt>
 * @see @p epoll(4)
 */
static void spurious_event(char *name, uint32_t events)
{
	char *desc;

	switch (events) {
	case EPOLLERR:
		desc = ", EPOLLERR - is interface up?";
		break;
	case EPOLLHUP:
		desc = ", EPOLLHUP";
		break;
	default:
		desc = "";
		break;
	}

	err("unexpected socket event (0x%x%s), interface '%s'",
	    events, desc, name);
}

/**
 * @brief Main event loop
 *
 * The loop flow approximates the following:
 * -# <b>Ingress phase</b>: Receive an EAPOL packet (@p packet) on a configured
 *    interface (@p iface). <br />
 *    @p packet is an Ethernet frame containing an EAPOL MPDU and @p iface is a
 *    network interface configured in the config file.
 *     - If @p packet is the first EAPOL packet to be received on @p iface, and
 *       any @e other interfaces are configured to have their MAC address set
 *       from the source MAC address of such a packet:
 *         - Set each such interface's MAC address.
 *         - Drop @p packet entirely and restart the loop.
 *     - If @p iface has an ingress script defined matching the EAPOL Packet
 *       Type or EAP Code of @p packet, execute the ingress script.
 *     - If @p iface has an ingress filter defined matching @p packet, apply
 *       the ingress filter (i.e. drop @p packet entirely and restart the loop).
 * -# <b>Egress phase</b>: Proxy @packet to other configured interfaces ("egress
 *    interfaces"). <br />
 *    For each egress interface (@p eiface):
 *     - Make a local copy of @p packet (@p epacket).
 *     - If @p eiface has a dot1q option defined, add/change/remove the 802.1Q
 *       VLAN tag in @p epacket.
 *     - If @p eiface has an egress filter defined matching @p epacket, apply
 *       the egress filter. <br />
 *       This means dropping @p epacket entirely on @p eiface and moving on to
 *       proxying @p packet on the next egress interface.
 *     - If @p eiface has an egress script defined matching @p epacket, execute
 *       the egress script.
 *     - Send @p epacket on @p eiface.
 * -# Restart the loop.
 *
 * @param ifaces Pointer to a list of <tt>struct iface_t</tt> structures
 *               representing network interfaces
 */
void proxy(struct iface_t *ifaces)
{
	sigset_t sigcurrent;
	sigprocmask(SIG_SETMASK, NULL, &sigcurrent);
	sigset_t sigempty;
	sigemptyset(&sigempty);

	struct timespec ts = { (time_t)10, 0 };

	int epfd = create_epoll();		/* epoll file descriptor */
	struct epoll_event event;		/* One event at a time */

	int num_ifaces = iface_count(ifaces);
	int rdy_ifaces = iface_init(ifaces, epfd);

	info("%d interfaces are ready", rdy_ifaces);

	packet_init(ifaces);

	uint8_t ignore_epollerr = 0;		/* flag */

	notice("starting proxy");

	struct iface_t *iface;
	struct peapod_packet pkt;

	while (1) {
		/* Begin ingress phase */
		if (num_ifaces != rdy_ifaces)
			ecritdie("some interfaces are not ready");

		if (epoll_pwait(epfd, &event, 1, -1, &sigempty) == -1) {
			if (errno == EINTR)
				check_signals();
			else
				ecritdie("cannot wait for epoll events: %s");
		}

		iface = event.data.ptr;		/* Received an EAPOL packet */

		if (!(event.events & EPOLLIN)) {
			/* Bringing down an interface invalidates its sockets */
			if (ignore_epollerr == 1 && event.events & EPOLLERR)
				goto proxy_ignore_epollerr;

			/* We're here for some other reason */
			spurious_event(iface->name, event.events);
			goto proxy_error;
		}

		debug("got an EPOLLIN event, interface '%s'",iface->name);

		pkt = packet_recvmsg(iface);

		if (pkt.len == -1) {
			ecrit("cannot receive, interface '%s': %s",
			      iface->name);
			goto proxy_error;
		} else if (pkt.len == -2 || pkt.len == -3) {
			/* Runt frames might not be a huge deal, but drop them
			 * anyway. Giant frames were too big to fit in the
			 * packet buffer.
			 */
			warning("dropping %s frame, interface '%s'",
				pkt.len == -2 ? "runt" : "giant",
				iface->name);
			continue;
		}

		++iface->recv_ctr;

		/* Set MAC of another interface to source address of first
		 * Ethernet frame with EAPOL MPDU entering on current interface.
		 */
		for (struct iface_t *i = ifaces;
		     i != NULL && iface->recv_ctr == 1;
		     i = i->next) {
			if (i->set_mac_from != iface->index)
				continue;

			/* If iface_set_mac() gets as far as bringing interface
			 * down, proxy loop will restart unless -o was passed
			 */
			i->set_mac_from = 0;  /* oneshot */
			if (iface_set_mac(i, pkt.h_source) == 0) {
				ignore_epollerr = 1;
				/* Emit this in place of an error */
				notice("set MAC, interface '%s', restarting",
				       i->name);
			} else {
				warning("won't try to autoset MAC again, "
					"interface %s", i->name);
			}
		}

		process_script(pkt);

		if (process_filter(pkt) == 1)
			continue;

		/* Begin egress phase */
		for (struct iface_t *i = ifaces; i != NULL; i = i->next) {
			if (i == iface)
				continue;

			if (process_filter(pkt) == 1)
				continue;		/* "approximates" ;) */

			/* Hand off 802.1Q tag editing and egress script
			 * execution to packet_send().
			 */
			if (packet_send(pkt, i) == -1)
				goto proxy_error;
		}

		continue;

proxy_error:
		if (args.oneshot != 1) {
proxy_ignore_epollerr:
			sigprocmask(SIG_SETMASK, &sigempty, &sigcurrent);
			check_signals();
			ignore_epollerr = 0;		/* oneshot */
			close(epfd);

			notice("restarting proxy in 10 seconds");
			nanosleep(&ts, NULL);

			check_signals();
			epfd = create_epoll();
			rdy_ifaces = iface_init(ifaces, epfd);
			sigprocmask(SIG_BLOCK, &sigcurrent, NULL);

			notice("starting proxy");
		} else {
			notice("exiting on error, goodbye");
			exit(EXIT_FAILURE);
		}
	}
}
