#!/bin/sh
# Installs Java and a pinned, checksum-verified jadx. Run as root.
set -eu

JADX_VERSION=1.5.6
JADX_SHA256=545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974

apt-get update
apt-get install -y --no-install-recommends ca-certificates curl default-jre-headless unzip
rm -rf /var/lib/apt/lists/*

archive=$(mktemp)
curl -fsSL -o "$archive" \
    "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip"
echo "${JADX_SHA256}  ${archive}" | sha256sum -c -
rm -rf /opt/jadx
unzip -q "$archive" -d /opt/jadx
rm -f "$archive"
ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx
