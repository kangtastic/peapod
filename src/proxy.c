/**
 * @file proxy.c
 * @brief Main event loop, related operations.
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

/** @brief Check and set signal counters. */
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
 * @brief Create an @p epoll instance.
 * @return 0 if successful, -1 if unsuccessful.
 */
static int create_epoll(void)
{
	int ret = epoll_create(1);
	if (ret == -1)
		ecritdie("cannot create epoll instance: %s\n");

	return ret;
}

/**
 * @brief Log an error on receiving a spurious @p epoll event.
 *
 * @param name A C string containing the name of a network interface.
 * @param events The events member of a <tt>struct epoll_event</tt>.
 *
 * @see @p epoll(4).
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
 * @brief Main event loop.
 *
 * Broadly, the loop flow is something like the following:
 * -# Receive an EAPOL frame on an interface. (Let's call the frame @p frame,
 *    the interface @p iface, and this part of the flow the "ingress" phase.)
 * -# If @p frame is the first frame received on @p iface:
 *	- Check if another interface is configured to have its MAC address set
 *	  from such a frame.
 *	- If so, set the other interface's MAC address to the source MAC address
 *	  contained in @p frame, drop @p frame entirely, and restart the loop.
 * -# Execute ingress script, if configured on @p iface.
 * -# Apply ingress filter, if configured on @p iface.
 *	- Filtering here means dropping @p frame entirely and restarting the
 *	  loop.
 * -# Proxy @frame to other interfaces. (Let's call this part of the flow the
 *   "egress" phase, and the other interfaces "egress interfaces".) Do the
 *   following for each:
 *	- Make a local copy of @p frame.
 *	- Add/change/remove 802.1Q tag in the copy.
 *	- Apply egress filter, if configured on the current egress interface.
 *		- Filtering here means only that the copy won't be sent out
 *		  on/the remaining steps are skipped for the current egress
 *		  interface; other egress interfaces are unaffected.
 *	- Execute egress script, if configured on the current egress interface.
 *	- Send the copy.
 * -# Restart the loop.
 *
 * @param ifaces A pointer to a list of <tt>struct iface_t</tt> structures
 *               representing network interfaces.
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
		if (num_ifaces != rdy_ifaces)
			ecritdie("some interfaces are not ready");

		if (epoll_pwait(epfd, &event, 1, -1, &sigempty) == -1) {
			if (errno == EINTR)
				check_signals();
			else
				ecritdie("cannot wait for epoll events: %s");
		}

		iface = event.data.ptr;

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
		 * frame entering on current interface.
		 */
		for (struct iface_t *i = ifaces;
		     i != NULL && iface->recv_ctr == 1;
		     i = i->next) {
			if (i == iface || i->ingress == NULL ||
			    i->ingress->set_mac[0] == '\0' ||
			    (strcmp(i->ingress->set_mac, iface->name) != 0))
				continue;

			memset(i->ingress->set_mac, 0, IFNAMSIZ);  /* oneshot */

			if (iface_set_mac(i, pkt.h_source) == -1) {
				warning("won't try to set MAC again, "
					"interface %s", i->name);
				continue;
			}

			ignore_epollerr = 1;

			/* Emit this in place of an error */
			notice("set MAC, interface '%s', restarting", i->name);
		}

		if (iface->ingress != NULL && iface->ingress->action != NULL)
			process_script(pkt, iface->ingress->action,
				       PROCESS_INGRESS);

		if (process_filter(pkt, iface, PROCESS_INGRESS) == 1)
			continue;


		for (struct iface_t *i = ifaces; i != NULL; i = i->next) {
			if (i == iface || process_filter(pkt, i,
							 PROCESS_EGRESS) == 1)
				continue;

			/* Running a script on egress is in packet_send(); this
			 * is because some fields in the peapod_packet and the
			 * first 16 bytes of the packet buffer are modified by
			 * it, so that what gets sent can have different 802.1Q
			 * tags between interfaces.
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
