#!/bin/bash
# Filename: updaterpm.sh
# Description: Updates the RPM repository.
#              Should be run within the rpm/ subdirectory in the gh-pages branch
#                  after running buildrpm.sh in the redhat branch.
# NOTE: It may be a good idea to include the following in ~/.gpg/gpg.conf so that
#       gpg doesn't use the SHA1 hash algorithm:
#
#           cert-digest-algo SHA256
#           digest-algo SHA256

set +e

GPGKEY=7B611AC6
NAME=peapod
ARCH=$(uname -m)
RPMS=~/rpmbuild/RPMS/$ARCH
DEST=$PWD/$ARCH

mkdir -p $DEST

for f in $RPMS/$NAME-*.$ARCH.rpm; do
	if ! cmp -s $f $DEST/$(basename $f); then
		cp $RPMS/$NAME-*.$ARCH.rpm $DEST
	fi
done

if [ -d $ARCH/repodata ]; then
	createrepo --update $ARCH
else
	createrepo $ARCH
fi

gpg --detach-sign --armor --local-user $GPGKEY --yes $ARCH/repodata/repomd.xml
