#!/usr/bin/env bash
set -e

ROOTFS_DIR="$(pwd)/rootfs/alpine"
TAR_FILE="$(pwd)/rootfs/alpine-minirootfs.tar.gz"
ALPINE_URL="https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.0-x86_64.tar.gz"

mkdir -p "$ROOTFS_DIR"

if [ -f "$ROOTFS_DIR/bin/sh" ]; then
    echo "[+] Alpine rootfs already exists at $ROOTFS_DIR"
    exit 0
fi

echo "[*] Downloading Alpine minirootfs..."
curl -sL "$ALPINE_URL" -o "$TAR_FILE"

echo "[*] Extracting to $ROOTFS_DIR..."
tar -xzf "$TAR_FILE" -C "$ROOTFS_DIR"
rm -f "$TAR_FILE"

echo "[+] Alpine RootFS ready at: $ROOTFS_DIR"
