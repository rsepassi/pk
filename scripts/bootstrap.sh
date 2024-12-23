#!/usr/bin/env sh

# Depends on: sh cc cp mv find mkdir rm basename

set -e

rm -rf $PWD/build/bootstrap
mkdir -p $PWD/build/bootstrap/bin

echo "Building make"
# ==============================================================================
# MAKE
# ==============================================================================
bdir="$PWD/build/bootstrap/make"
cflags="
-Ivendor/make/src
-Ivendor/make/src/lib
-DHAVE_CONFIG_H
-DLIBDIR=\"\"
-DLOCALEDIR=\"\"
-DINCLUDEDIR=\"\"
"
srcs=$(find vendor/make/src -name '*.c')

mkdir -p $bdir
cc -o $bdir/make $cflags $srcs -lc
mv $bdir/make $PWD/build/bootstrap/bin/
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

cc -o $bdir/yash $cflags $srcs -lc
mv $bdir/yash $PWD/build/bootstrap/bin/
# ==============================================================================
echo "Built yash"

echo "Building pkg-config"
# ==============================================================================
# PKG-CONFIG
# ==============================================================================
bdir="$PWD/build/bootstrap/pkgconfig"
cflags="
-DNDEBUG
"
srcs=lib/pkgconfig/src/pkg-config.c
mkdir -p $bdir
cc -o $bdir/pkg-config $cflags $srcs -lc
mv $bdir/pkg-config $PWD/build/bootstrap/bin/
# ==============================================================================
echo "Built pkg-config"

# echo "Building make+yash"
# # ==============================================================================
# # YASH + MAKE
# # ==============================================================================
# rm -rf build/x86_64-linux-musl
# $PWD/build/bootstrap/make/make --silent -j \
#   SHELL=$PWD/build/bootstrap/yash/yash \
#   vendor/yash OPT=2
# $PWD/build/bootstrap/make/make --silent -j \
#   SHELL=$PWD/build/bootstrap/yash/yash \
#   vendor/make OPT=2
# 
# mkdir build/bootstrap/out
# cp build/x86_64-linux-musl/vendor/yash/bin/yash build/bootstrap/out/
# cp build/x86_64-linux-musl/vendor/make/bin/make build/bootstrap/out/
# # ==============================================================================
# echo "Built make+yash"

# $PWD/build/bootstrap/out/make --silent -j SHELL=$PWD/build/bootstrap/out/yash
