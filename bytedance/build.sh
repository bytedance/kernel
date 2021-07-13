#!/bin/bash
set -e

if test "$1" = "--docker"; then
    # Do docker build
    build=$(mktemp -d /var/tmp/linux-build.XXXXXX)
    for rel in jessie stretch; do
        mkdir $build/$rel
        docker run -ti --rm -v $build/$rel:/linux -v $(realpath $(dirname $0)/..):/linux/src \
            cloud-sys.byted.org:5000/kernel-compile:$rel \
            bash -c "cd /linux/src; git clean -dfx; ./bytedance/build.sh -j $(nproc)"
    done
    if test -e output; then rm -rf output; fi
    mv $build output
    exit 0
fi

ARCH=$(arch)
TAG_PATTERN='v5.4.*-*-velinux*'
v=$(git describe --dirty --match $TAG_PATTERN --tags | cut -c 2-)
r=$(git describe --tags --match "$TAG_PATTERN" --abbrev=0 | cut -c 2-)
t="Debian $v $(date)"

if [ $ARCH == "x86_64" ]; then
    ARCH_STR="amd64"
    cp config.x86_64 .config
elif [ $ARCH == "aarch64" ]; then
    ARCH_STR="arm64"
    cp config.aarch64 .config
fi

make -C tools/bpf/bpftool
make deb-pkg BUILD_TOOLS=1 KDEB_PKGVERSION=$v KERNELRELEASE=$r-$ARCH_STR LOCALVERSION=_$v KBUILD_BUILD_TIMESTAMP="$t" "$@"
