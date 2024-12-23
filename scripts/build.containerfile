# podman build -f scripts/build.containerfile -t pkbuild
# podman run -it -v $PWD:/root/pk pkbuild
# make clean; make --silent -j
# ./build/cli/bin/cli

FROM alpine:3.21
RUN apk add clang19 clang19-extra-tools llvm19 lld
WORKDIR /root/pk
