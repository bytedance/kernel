#!/bin/bash
set -x
set -e

declare -A archs=(
	["x86_64"]="amd64"
	["aarch64"]="arm64"
)

arch=${archs[$(uname -m)]}
if [ -z $arch ]; then
	echo "Unknown arch: $(uname -m)"
	exit 1
fi

pattern="v[0-9].[0-9]*.[0-9]*.bsk.[0-9]*"
version=$(git describe --dirty --tags --match "$pattern" | cut -c 2-)
if [ -z $version ]; then
	echo "Unknown tag pattern: "$pattern""
	exit 1
fi

timestamp="Debian $version $(date)"
cp config.$(uname -m) .config

if ! lsb_release -c | grep -q jessie; then
	CFLAGS="-Werror"
fi

make deb-pkg					\
     BUILD_TOOLS=y				\
     KDEB_PKGVERSION=$version			\
     KERNELRELEASE=$version-$arch		\
     LOCALVERSION=_$version			\
     KBUILD_BUILD_TIMESTAMP="$timestamp"	\
     KBUILD_BUILD_USER="STE-Kernel"		\
     KBUILD_BUILD_HOST="ByteDance"		\
     DPKG_FLAGS="-sn"				\
     CFLAGS_KERNEL="$CFLAGS"			\
     CFLAGS_MODULE="$CFLAGS"			\
     "$@"
