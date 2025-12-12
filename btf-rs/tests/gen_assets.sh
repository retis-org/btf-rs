#!/bin/bash
set -ex

version="6.15.1"
tarball="linux-${version}.tar.xz"
url="https://cdn.kernel.org/pub/linux/kernel/v6.x/${tarball}"

assets=$(dirname $(readlink -f $0))/assets
builddir=$(mktemp -d -t btf-rs-XXXXXX)
cleanup() {
  rm -rf $builddir
}
trap cleanup EXIT INT TERM

# Download and extract the kernel sources.
curl --silent --output-dir $builddir -O $url
tar -xf $builddir/$tarball -C $builddir --strip-components=1

# Build a minimal configuration.
make -C $builddir tinyconfig
add_kconf() {
	echo $1=$2 >> $builddir/.config
}
add_kconf CONFIG_MODULES y
add_kconf CONFIG_MODULE_COMPRESS y
add_kconf CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT y
add_kconf CONFIG_BPF_SYSCALL y
add_kconf CONFIG_DEBUG_INFO_BTF y
add_kconf CONFIG_NET y
add_kconf CONFIG_INET y
add_kconf CONFIG_NETDEVICES y
add_kconf CONFIG_GENEVE y
add_kconf CONFIG_OPENVSWITCH m
add_kconf CONFIG_VETH m
make -C $builddir olddefconfig

# Compile and install into $assets/elf kernel and module images compressed with
# various algorithms.
build_variant() {
	echo CONFIG_KERNEL_$1=y >> $builddir/.config
	echo CONFIG_MODULE_COMPRESS_$2=y >> $builddir/.config
	make -C $builddir -j$(nproc)

	flavor="${1,,}+${2,,}"
	rm -rf $assets/elf/$flavor
	install -D $builddir/arch/x86/boot/bzImage $assets/elf/$flavor/vmlinux
	INSTALL_MOD_PATH=$assets/elf/$flavor make -C $builddir modules_install
	mv $assets/elf/$flavor/lib/modules/$version/kernel $assets/elf/$flavor/
}
build_variant BZIP2 XZ
build_variant XZ XZ
build_variant GZIP GZIP
build_variant ZSTD ZSTD

# Only keep the files we want.
find $assets/elf -type f,l \
	-not -name "vmlinux" \
	-not -name "openvswitch.ko.*" \
	-not -name "vport-geneve.ko.*" \
	-not -name "veth.ko.*" \
	-delete
find $assets/elf -type d -empty -delete

# Also copy uncompressed images.
rm -rf $assets/elf/uncompressed
install -D $builddir/vmlinux $assets/elf/uncompressed/vmlinux
install -D $builddir/net/openvswitch/openvswitch.ko \
	$assets/elf/uncompressed/kernel/net/openvswitch/openvswitch.ko
install -D $builddir/net/openvswitch/vport-geneve.ko \
	$assets/elf/uncompressed/kernel/net/openvswitch/vport-geneve.ko
install -D $builddir/drivers/net/veth.ko \
	$assets/elf/uncompressed/kernel/drivers/net/veth.ko

# Derive pure BTF files from the above, to allow having the same tests
# (ids & names will match).
objcopy --dump-section .BTF=$assets/btf/vmlinux $assets/elf/uncompressed/vmlinux
objcopy --dump-section .BTF=$assets/btf/openvswitch \
	$assets/elf/uncompressed/kernel/net/openvswitch/openvswitch.ko
