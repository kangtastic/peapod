#!/bin/bash
# Filename: buildrpm.sh
# Description: Builds .rpm and .src.rpm packages in the user home directory.
#
# Usage: buildrpm.sh [sign]

VERSION=$(grep -P 'Version:' peapod.spec | awk '{print $2}')
SRCNAME="peapod-$VERSION"
SRCTGZ="$SRCNAME.tar.gz"

mkdir -p ~/rpmbuild/SOURCES

rm -rf ~/rpmbuild/BUILD/SRCNAME ~/rpmbuild/SOURCES/$SRCTGZ

# [ ! -f ~/rpmbuild/SOURCES/$SRCTGZ ] && \
tar --transform "s,^,$SRCNAME/," -cvf ~/rpmbuild/SOURCES/$SRCTGZ doc include src Doxyfile LICENSE Makefile README.md peapod.service.in .gitignore

rpmbuild -bs peapod.spec
rpmbuild -bb peapod.spec

if [ "$1" = "sign" ]; then
	RELEASE=$(grep -P 'Release:' peapod.spec | grep -Po '\d(?=%)')
	ARCH=$(uname -m)
	rpm --addsign ~/rpmbuild/RPMS/$ARCH/$SRCNAME-$RELEASE.*.$ARCH.rpm
	rpm --addsign ~/rpmbuild/SRPMS/$SRCNAME-$RELEASE.*.src.rpm
fi

