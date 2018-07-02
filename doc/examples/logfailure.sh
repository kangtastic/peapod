#!/bin/bash
# Filename: logfailure.sh
# Description: Example script for peapod - EAPOL Proxy Daemon
#
# When run by peapod as it handles an EAP-Failure,
# log the failed EAPOL authentication.
#
# See peapod.conf(5), "SCRIPTS" and env.sh for more on
# environment variables available to scripts.

# Output file
FAIL_LOG="/tmp/eapfailure.log"

# Ensure script was triggered by EAP-Failure
if [ $PKT_CODE -ne 4 ]; then
    exit
fi

# Sample entry in output file:
#
#    Mon, 01 Jan 2018 00:00:00 +0000 xx:xx:xx:xx:xx:xx > xx:xx:xx:xx:xx:xx
TIMESTAMP=$(date -d "@$(echo "$PKT_TIME" | awk -F. '{print $1;}')" -R)
echo "$TIMESTAMP $PKT_SOURCE > $PKT_DEST" >> "$FAIL_LOG"
