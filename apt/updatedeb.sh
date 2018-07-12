#!/bin/bash
# Filename: updatedeb.sh
# Description: Updates the apt repository.
#              Should be run within the apt/ subdirectory in the gh-pages branch
#                  after running builddeb.sh in the debian branch.
# NOTE: To avoid warnings from apt regarding a weak hash algorithm (SHA1) for
#       the Release file, include the following in ~/.gpg/gpg.conf:
#
#           cert-digest-algo SHA256
#           digest-algo SHA256

GPGKEY=7B611AC6
NAME=peapod
ARCH=$(dpkg --print-architecture)
DEBS=$PWD/../..
DEST=$PWD/$ARCH

mkdir -p $DEST

for f in $DEBS/${NAME}_*_$ARCH.deb; do
	if ! cmp -s $f $DEST/$(basename $f); then
		cp $DEBS/${NAME}_*_$ARCH.deb $DEST
	fi
done

dpkg-scanpackages -m $ARCH /dev/null | tee $ARCH/Packages | gzip -9c > $ARCH/Packages.gz

apt-ftparchive release $ARCH /dev/null > $ARCH/Release

gpg --detach-sign --armor --local-user $GPGKEY --yes --output $ARCH/Release.gpg $ARCH/Release

