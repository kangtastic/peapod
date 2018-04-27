#!/bin/bash

PCAP=/tmp/peapod.pcap

# cf. https://wiki.wireshark.org/Development/LibpcapFileFormat
if [ ! -f $PCAP ]; then
	for s in 0xa1b2c3d4 0x0002 0x0004 0x00000000 \
		 0x00000000 0x0000ffff 0x00000001; do
		echo $s | xxd -r >> $PCAP
	done
fi

printf '0x%.08x' $(echo $PKT_TIME | awk -F. '{ print $1; }') | xxd -r >> $PCAP
printf '0x%.08x' $(echo $PKT_TIME | awk -F. '{ print $2; }') | xxd -r >> $PCAP
printf '0x%.08x' $PKT_LENGTH_ORIG | xxd -r >> $PCAP
printf '0x%.08x' $PKT_LENGTH_ORIG | xxd -r >> $PCAP

echo $PKT_ORIG | base64 -d >> $PCAP
