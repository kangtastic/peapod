#!/bin/bash
# Filename: buildrpm.sh
# Description: Builds .rpm and .src.rpm packages in the user home directory.
#
# Usage: buildrpm.sh [sign]

NAME=peapod
VERSION=$(grep -P 'Version:' peapod.spec | awk '{print $2}')
RELEASE=$(grep -P 'Release:' peapod.spec | awk '{print $2}')
ARCH=$(uname -m)
SRCNAME=$NAME-$VERSION
SRCTGZ=$SRCNAME.tar.gz

mkdir -p ~/rpmbuild/SOURCES

rm -rf ~/rpmbuild/BUILD/SRCNAME ~/rpmbuild/SOURCES/$SRCTGZ

# [ ! -f ~/rpmbuild/SOURCES/$SRCTGZ ] && \
tar --transform "s,^,$SRCNAME/," -cvf ~/rpmbuild/SOURCES/$SRCTGZ doc include src Doxyfile LICENSE Makefile README.md peapod.service.in .gitignore

rpmbuild -bs peapod.spec
rpmbuild -bb peapod.spec

if [ "$1" = "sign" ]; then
	for f in ~/rpmbuild/RPMS/$ARCH/$NAME*-$VERSION-$RELEASE.$ARCH.rpm ~/rpmbuild/SRPMS/$NAME-$VERSION-$RELEASE.src.rpm; do
		rpm --addsign $f
		rpmlint $f
	done
fi

