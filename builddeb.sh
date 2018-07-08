#!/bin/bash
# Filename: builddeb.sh
# Description: Builds a .deb package in the parent directory.
#              Cleans the build once finished.
#              Arguments passed to this script are passed through to debuild;
#                  end users can pass -us -uc to build an unsigned package.
VERSION=$(head -1 debian/changelog | awk -F'(' '{print $2}' | awk -F'-' '{print $1}')

tar Jcf ../peapod_$VERSION.orig.tar.xz doc include src Doxyfile LICENSE Makefile README.md peapod.service.in builddeb.sh

debuild "$@"

debian/rules clean
