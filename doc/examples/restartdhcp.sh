#!/bin/bash
# Filename: restartdhcp.sh
# Description: Example script for peapod - EAPOL Proxy Daemon
#
# When run by peapod as the result of receiving EAP-Success on a
# specific ingress interface, restart the system's DHCP client (dhclient
# in this example) on that interface. Exit with different nonzero exit
# codes upon encountering errors; peapod will report them to the user.

# Interface with running dhclient instance
DHCL_IFACE="eth0"                           # to EAPOL authenticator

# Ensure script was triggered by EAP-Success on the correct (ingress) interface
if [ $PKT_CODE -ne 3 ] ||                   # cf. RFC 2284 §2.2
   [ "$PKT_IFACE_ORIG" != "$DHCL_IFACE" ] ||
   [ "$PKT_IFACE_ORIG" != "$PKT_IFACE" ]; then
    exit
fi

# Find the cmdline arguments of the relevant instance of dhclient
# NOTE: Assumes no spaces exist in its cmdline. If this is not the case,
#       consider using e.g. python to parse /proc/<pid>/cmdline directly.
#       Unfortunately, bash doesn't handle a NUL field separator very well.
DHCL_PROC=$(pgrep -a dhclient | grep "$PKT_IFACE_ORIG" | grep -v -- -6)
if [ -z "$DHCL_PROC" ]; then
    exit 1                                  # no instance on interface
elif [ $(echo "$DHCL_PROC" | wc -l) -ne 1 ]; then
    exit 3                                  # multiple instances
fi

DHCL=$(echo "$DHCL_PROC" | awk '{print $2}')
DHCL_PID=$(echo "$DHCL_PROC" | awk '{print $1}')
DHCL_ARGS=$(echo "$DHCL_PROC" | awk '{for(i=3;i<$NF;i++) printf $i " "; print $NF}')

# Release existing DHCP lease
# Invoke new dhclient with same cmdline arguments as the instance we want to
# kill, but also pass -r. Existing instance will release its lease and exit.
if kill -0 $DHCL_PID; then
    if ! $DHCL -r $DHCL_ARGS; then          # cf. debian's ifdown(8)
        exit $(($?+128))                    # convention: exit code + 128
    fi
else
    exit 7                                  # bad PID
fi

TIMEOUT=3                                   # 3 seconds should be "plenty" :)
while kill -0 $DHCL_PID; do
    if [ $TIMEOUT -eq 0 ]; then
        kill -9 $DHCL_PID                   # send SIGKILL
    else
        TIMEOUT=$((TIMEOUT-1))
        sleep 1
    fi
done

# Restart dhclient with the same cmdline arguments it had originally
# Passing -nw (nowait) to immediately daemonize dhclient and prevent it, and
# peapod in turn, from hanging while it waits for a lease.
if ! echo "$DHCL_ARGS" | grep -q -- -nw; then
    DHCL_ARGS="-nw $DHCL_ARGS"
fi
if ! $DHCL $DHCL_ARGS; then
    exit $(($?+128))
fi
