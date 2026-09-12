#!/bin/bash
# Build the Kata Containers guest kernel that apple/container boots by default,
# plus the Kubernetes networking options in portus-k8s.conf, for
# `container system kernel set`. Runs on any arm64 Linux with gcc; the intended
# way is a throwaway container (about 12 min on an M4 with 10 vCPUs):
#
#   container run --rm --cpus 10 --memory 8G \
#     -v $PWD/deploy/machine/kernel:/kernel ubuntu:24.04 bash /kernel/build-kata-kernel.sh
#   container system kernel set --binary deploy/machine/kernel/out/Image --force
#
# The kernel tree is built on the container's own disk (extracting it onto the
# shared mount fails on permissions); only Image, vmlinux and .config are copied
# back into kernel/out/, which is git-ignored.
set -euo pipefail
[ "$(id -u)" = 0 ] && SUDO= || SUDO=sudo
apt-get update -q >/dev/null 2>&1 || ${SUDO:-} apt-get update -q >/dev/null
KATA_REF=3.32.0
WORK=${WORK:-/kernel}
BUILD=${BUILD:-/build}; mkdir -p "$BUILD"
FRAG=$WORK/portus-k8s.conf
${SUDO:-} apt-get install -y -q build-essential flex bison libssl-dev libelf-dev bc bison python3 zstd git curl >/dev/null
cd "$BUILD"
[ -d kata-containers ] || git clone --depth 1 --branch "$KATA_REF" https://github.com/kata-containers/kata-containers.git
cp "$FRAG" kata-containers/tools/packaging/kernel/configs/fragments/common/zz-portus-k8s.conf
cd kata-containers/tools/packaging/kernel
KVER=$(awk '/^  kernel:/{p=1} p&&/version:/{gsub(/[" v]/,"",$2); print $2; exit}' ../../../versions.yaml)
echo "kernel $KVER, fragments: common + arm64 + zz-portus-k8s.conf"
./build-kernel.sh -a aarch64 -v "$KVER" -f setup
./build-kernel.sh -a aarch64 -v "$KVER" build
OUT=$WORK/out; mkdir -p "$OUT"
cp kata-linux-*/arch/arm64/boot/Image "$OUT/Image"
cp kata-linux-*/vmlinux "$OUT/vmlinux" 2>/dev/null || true
cp kata-linux-*/.config "$OUT/config"
grep -E 'CONFIG_(BRIDGE_NETFILTER|NF_TABLES|VXLAN|IP_SET|NETFILTER_XT_MATCH_COMMENT)=' "$OUT/config" | head
ls -la "$OUT"
