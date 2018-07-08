#!/bin/bash
# Filename: pcap.sh
# Description: Example script for peapod - EAPOL Proxy Daemon
#
# When run by peapod as it proxies an EAPOL packet, write the Ethernet
# frame containing the packet, as originally received, to a .pcap file.
#
# Requires the xxd(1) utility.

# Output file
PCAP="/tmp/peapod.pcap"

# Create output file if nonexistent, writing .pcap file header
# Byte order is big-endian
# c.f. https://wiki.wireshark.org/Development/LibpcapFileFormat
if [ ! -f "$PCAP" ]; then
    for NUM in 0xa1b2c3d4 0x0002 0x0004 0x00000000 \
               0x00000000 0x0000ffff 0x00000001; do
        echo "$NUM" | xxd -r >> "$PCAP"
    done
fi

# Append frame timestamp (secs/usecs), length (saved/actual)
printf '0x%.08x' $(echo "$PKT_TIME" | awk -F. '{print $1;}') | xxd -r >> "$PCAP"
printf '0x%.08x' $(echo "$PKT_TIME" | awk -F. '{print $2;}') | xxd -r >> "$PCAP"
printf '0x%.08x' "$PKT_LENGTH_ORIG" | xxd -r >> "$PCAP"
printf '0x%.08x' "$PKT_LENGTH_ORIG" | xxd -r >> "$PCAP"

# Append raw frame as originally received on ingress interface
echo "$PKT_ORIG" | base64 -d >> "$PCAP"
