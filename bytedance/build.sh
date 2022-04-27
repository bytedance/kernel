#!/bin/bash
set -x
set -e

declare -A distributions=( ["8"]="jessie" ["9"]="stretch" ["10"]="buster" ["jessie"]="jessie" ["stretch"]="stretch" ["buster"]="buster" )
declare -A archs=( ["x86_64"]="amd64" ["aarch64"]="arm64" )

function usage {
	echo "$0 [-d jessie|stretch|buster|8|9|10] [-o OUTPUT] [-p PATTERN]"
	echo ""
	echo "Build Linux kernel based on distribution of the current machine or specified by the option of -d"
	echo ""
	echo "OPTIONS:"
	echo "      -d distribution. The valid parameter is 'jessie'(aka '8') or 'stretch'(aka '9') or 'buster'(aka '10')"
	echo "      -o output. The location to store deb packages (defaults to current directory)."
	echo "      -p specify a tag (git) pattern to search for a specific tag to build kernel. Defaults to v[0-9].[0-9]*.[0-9]*.bsk.[0-9]*"
	echo "      -h help"
	echo ""
}

while getopts ":d:hj:o:p:" opt
do
	case $opt in
		o) output=$OPTARG
			;;
		d) distribution=$OPTARG
			;;
		h) usage
			exit
			;;
		j)
			# Ignore
			;;
		p) pattern=$OPTARG
			;;
		\?) echo "Unknown option: -$OPTARG" >&2
			usage
			exit 1
			;;
	esac

	if [ "$opt" != "d" ]; then
		parameter="$parameter -$opt $OPTARG"
	fi
done

if [ ! -z $(uname -m) ]; then
	arch=${archs[$(uname -m)]}
fi

if [ -z $arch ]; then
	echo "Unknown arch: $(uname -m)"
	exit 1
fi

toplevel=$(git rev-parse --show-toplevel)

if [ ! -z $distribution ]; then
	declare -A docker_suffix=( ["amd64"]="" ["arm64"]="-aarch64" )

	image=${distributions[$distribution]}
	if [ -z $image ]; then
		usage
		exit 1
	fi

	tmp=$(mktemp -d /var/tmp/linux-build.XXXXXX)
	build="$tmp/$image"
	trap "rm -rf $tmp" SIGHUP SIGINT SIGQUIT SIGTERM ERR EXIT
	mkdir $build

	# Do docker build
	docker run --network=host -ti --rm -v $build:/linux -v $toplevel:/linux/src			\
	       gaea-hub.byted.org/kernel-compile/kernel-compile:$image${docker_suffix[$arch]}-latest	\
	       bash -c "apt install rsync -y;								\
			cd /linux/src/$(git rev-parse --show-prefix);					\
			$0 $parameter"

	output="$toplevel/$output/$image"
	if test -e $output; then
		rm -rf $output
	fi
	mkdir -p $output
	mv $tmp/$image/*.deb $output
	exit 0
fi

pattern=${pattern:="v[0-9].[0-9]*.[0-9]*.bsk.[0-9]*"}
version=$(git describe --dirty --tags --match $pattern | cut -c 2-)
if [ -z $version ]; then
	echo "Unknown tag pattern: $pattern"
	exit 1
fi

timestamp="Debian $version $(date)"

cd $toplevel
# The source tree should be clean
git clean -idfxq
cp config.$(uname -m) .config

make deb-pkg					\
     BUILD_TOOLS=y				\
     KDEB_PKGVERSION=$version			\
     KERNELRELEASE=$version-$arch		\
     LOCALVERSION=_$version			\
     KBUILD_BUILD_TIMESTAMP="$timestamp"	\
     KBUILD_BUILD_USER="STE-Kernel"		\
     KBUILD_BUILD_HOST="ByteDance"		\
     -j$(nproc)
