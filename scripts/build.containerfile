# podman build -f scripts/build.containerfile -t pkbuild
# podman run -it -v $PWD:/root/pk pkbuild
# cd /root/pk; make clean; make --silent -j CCLD=clang-17
# ./build/cli/bin/cli

FROM alpine:3.20
RUN apk add make pkgconf clang17 llvm17 lld compiler-rt
