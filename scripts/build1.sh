#!/usr/bin/env sh

set -e

target=$1

updatef=$BROOT/$target/.build-update

if [ -f $updatef ] && [ $(date -r $updatef +%s) -ge $ROOTTIME ]
then
  exit 0
fi

make -C $ROOTDIR/$target deps DEPS_ARG=
make -C $ROOTDIR/$target DEPS_ARG=

touch $updatef
