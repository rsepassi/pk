#!/usr/bin/env sh

# Depends on: sh cc cp find mkdir rm basename

set -e

rm -rf $PWD/build/bootstrap

echo "Building make"
# ==============================================================================
# MAKE
# ==============================================================================
bdir="$PWD/build/bootstrap/make"
cflags="
-I$bdir/include
-Ivendor/make/src
-Ivendor/make/src/lib
-DHAVE_CONFIG_H
-DLIBDIR=\"\"
-DLOCALEDIR=\"\"
-DINCLUDEDIR=\"\"
"
srcs=$(find vendor/make/src -name '*.c')

mkdir -p $bdir
for f in $srcs
do
  cc -c $cflags -o $bdir/$(basename $f).o $f
done
cc -o $bdir/make $bdir/*.o -lc
# ==============================================================================
echo "Built make"


echo "Building yash"
# ==============================================================================
# YASH
# ==============================================================================
bdir="$PWD/build/bootstrap/yash"
cflags="
-I$bdir/include
-Ivendor/yash/src
"
srcs=$(find vendor/yash/src -name '*.c')

mkdir -p $bdir/include
cp vendor/yash/src/platform/config-linux.h $bdir/include/config.h
cp vendor/yash/src/platform/signum-linux.h $bdir/include/signum.h

for f in $srcs
do
  cc -c $cflags -o $bdir/$(basename $f).o $f
done
cc -o $bdir/yash $bdir/*.o -lc
# ==============================================================================
echo "Built yash"

echo "Building make+yash"
# ==============================================================================
# YASH + MAKE
# ==============================================================================
rm -rf build/x86_64-linux-musl
$PWD/build/bootstrap/make/make --silent -j \
  SHELL=$PWD/build/bootstrap/yash/yash \
  vendor/yash OPT=2
$PWD/build/bootstrap/make/make --silent -j \
  SHELL=$PWD/build/bootstrap/yash/yash \
  vendor/make OPT=2

mkdir build/bootstrap/out
cp build/x86_64-linux-musl/vendor/yash/bin/yash build/bootstrap/out/
cp build/x86_64-linux-musl/vendor/make/bin/make build/bootstrap/out/
# ==============================================================================
echo "Built make+yash"

# $PWD/build/bootstrap/out/make --silent -j SHELL=$PWD/build/bootstrap/out/yash
