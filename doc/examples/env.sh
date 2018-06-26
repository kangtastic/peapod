#!/bin/bash
# Filename: env.sh
# Description: Example script for peapod - Proxy EAP Daemon
#
# When run by peapod, determine the environment variables available, as these
# depend upon the type of EAPOL packet and where it is in the process of being
# proxied. Users writing their own scripts may find this information useful.
#
# A listing of possible variables and example values follows.
#
### ALWAYS AVAILABLE ###
# - Timestamp.
# PKT_TIME=1514764800.000000                        (Format: unixtime.microsecs)
#
# - Destination and source MAC addresses.
# PKT_DEST=xx:xx:xx:xx:xx:xx                        (hexdigit pairs)
# PKT_SOURCE=xx:xx:xx:xx:xx:xx
#
# - EAPOL Packet Type and description.
# PKT_TYPE=4                                        (number from 0 to 8)
# PKT_TYPE_DESC=EAPOL-Encapsulated-ASF-Alert
#
# - Packet as received on ingress interface.
# PKT_IFACE_ORIG=eth0                       (name of ingress interface)
# PKT_IFACE_ORIG_MTU=1500
# PKT_LENGTH_ORIG=64
# PKT_ORIG=AYDCAADD...                      (raw Base64-encoded Ethernet frame)
#
# - Packet as it is currently.
# NOTE: Same values as ..._ORIG in ingress phase. In egress phase, $PKT_IFACE
#       is the current egress interface and a 802.1Q VLAN tag may have been
#       modified, removed, or added.
# PKT_IFACE=eth1                            (name of current interface)
# PKT_IFACE_MTU=1500
# PKT_LENGTH=60                             (may differ from _ORIG if dot1q set)
# PKT=AYDCAADD...                           (raw Base64-encoded Ethernet frame)
#
### CONDITIONALLY AVAILABLE ###
# - EAP Code, description, and EAP Identifier.
# Condition: EAPOL Packet Type is EAPOL-EAP ($PKT_TYPE is 0).
# PKT_CODE=2                                        (number from 1 to 4)
# PKT_CODE_DESC=Response
# PKT_ID=152                                        (number from 1 to 255)
#
# - EAP-Request/EAP-Response Type and description.
# Condition: EAPOL Packet Type is EAPOL-EAP and EAP packet contains EAP-Request
#            or EAP-Response ($PKT_TYPE is 0, $PKT_CODE is 1 or 2).
# PKT_REQRESP_TYPE=6                                (Number from 1 to 255)
# PKT_REQRESP_DESC=Generic Token Card (GTC)
#
# - 802.1Q Tag Control Information.
# Raw 802.1Q TCI in hex, i.e. last 2 bytes of 4-byte 802.1Q VLAN tag containing
# PCP, DEI, and VID fields.
# Condition: Packet was received tagged.
# PKT_DOT1Q_TCI_ORIG=c000           (four hexdigits; PCP=6, DEI=0, VID=0 here)
# Condition: In ingress phase, same condition as ..._ORIG; also has same value.
#            In egress phase, packet is about to be sent tagged on current
#            egress interface.
# PKT_DOT1Q_TCI=9000                (four hexdigits)

# Output file
OUTPUT="/tmp/peapodenv.txt"

# Sample entry in output file:
#
#    /path/to/env.sh eth0 EAPOL-Start 2018-01-01 00:00:00.437820723+00:00
#
#    PKT_TIME=1514764800.069263
#    PKT_DEST=01:80:c2:00:00:03
#    PKT_SOURCE=f0:92:1c:01:23:45
#        ...
#    PKT_IFACE_ORIG=eth0
#    PKT_IFACE=eth0
#        ...
#    PKT=AYDCAADD...
#    PKT_DOT1Q_TCI_ORIG=e000
#    PKT_DOT1Q_TCI=e000
#
# This is enough to determine that about midnight UTC on January 1, 2018, a
# device manufactured by Hewlett Packard tried to initiate an EAPOL session.
# The EAPOL packet it sent was tagged with priority 7 and received on eth0,
# but has not yet been proxied to other interfaces.
echo "$0 $PKT_IFACE $PKT_TYPE_DESC $(date --rfc-3339=ns)" >> "$OUTPUT"
echo >> "$OUTPUT"
env >> "$OUTPUT"
