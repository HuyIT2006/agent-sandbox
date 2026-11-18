#!/usr/bin/env bash
# =================================================================
# download_rootfs.sh
# Thành viên 1: Script tải và chuẩn bị Alpine Mini RootFS tối giản
#
# Alpine Linux minirootfs là hệ thống tệp gốc siêu nhẹ (~3MB nén)
# dùng làm base Read-Only cho Sandbox. Bao gồm:
#   - BusyBox (cung cấp shell /bin/sh và các lệnh cơ bản)
#   - musl libc (C library tối giản)
#   - apk package manager (nếu cần cài thêm gói)
#
# Sau khi giải nén, rootfs sẽ được mount Read-Only bởi bwrap.
# Sandbox chỉ có thể ghi vào /tmp (tmpfs) và /workspace (bind mount).
# =================================================================
set -euo pipefail

# ===== CẤU HÌNH =====
ALPINE_VERSION="3.20"
ALPINE_RELEASE="3.20.0"
ARCH="x86_64"
ALPINE_URL="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION}/releases/${ARCH}/alpine-minirootfs-${ALPINE_RELEASE}-${ARCH}.tar.gz"

# Tự động xác định thư mục gốc dự án
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

ROOTFS_DIR="${PROJECT_ROOT}/rootfs/alpine"
TAR_FILE="${PROJECT_ROOT}/rootfs/alpine-minirootfs-${ALPINE_RELEASE}.tar.gz"

# ===== KIỂM TRA ĐÃ TẢI CHƯA =====
if [ -f "${ROOTFS_DIR}/bin/sh" ]; then
    echo "[+] Alpine rootfs đã tồn tại tại: ${ROOTFS_DIR}"
    # Hiển thị thông tin kích thước
    ROOTFS_SIZE=$(du -sh "$ROOTFS_DIR" 2>/dev/null | cut -f1)
    echo "    Kích thước: ${ROOTFS_SIZE}"
    FILE_COUNT=$(find "$ROOTFS_DIR" -type f 2>/dev/null | wc -l)
    echo "    Số file   : ${FILE_COUNT}"
    exit 0
fi

echo "============================================================"
echo "  ALPINE MINI ROOTFS DOWNLOADER"
echo "  Version: Alpine Linux ${ALPINE_RELEASE} (${ARCH})"
echo "============================================================"

# ===== TẠO THƯ MỤC =====
mkdir -p "$ROOTFS_DIR"

# ===== TẢI ROOTFS =====
echo "[*] Đang tải Alpine minirootfs từ CDN chính thức..."
echo "    URL: ${ALPINE_URL}"

if command -v curl &>/dev/null; then
    curl -fSL --retry 3 --retry-delay 2 "$ALPINE_URL" -o "$TAR_FILE"
elif command -v wget &>/dev/null; then
    wget -q --tries=3 "$ALPINE_URL" -O "$TAR_FILE"
else
    echo "[!] Lỗi: Cần cài đặt 'curl' hoặc 'wget' để tải rootfs."
    exit 1
fi

# ===== GIẢI NÉN =====
echo "[*] Đang giải nén vào: ${ROOTFS_DIR}"
tar -xzf "$TAR_FILE" -C "$ROOTFS_DIR"

# ===== DỌN DẸP FILE NÉN =====
rm -f "$TAR_FILE"

# ===== XÁC MINH ROOTFS =====
if [ ! -f "${ROOTFS_DIR}/bin/sh" ]; then
    echo "[!] Lỗi: Giải nén thất bại — không tìm thấy /bin/sh trong rootfs!"
    exit 1
fi

# ===== THIẾT LẬP DNS CHO ROOTFS =====
# Tạo /etc/resolv.conf tối giản (dùng cho trường hợp sandbox cần DNS)
echo "nameserver 8.8.8.8" > "${ROOTFS_DIR}/etc/resolv.conf" 2>/dev/null || true

# ===== THỐNG KÊ KẾT QUẢ =====
ROOTFS_SIZE=$(du -sh "$ROOTFS_DIR" 2>/dev/null | cut -f1)
FILE_COUNT=$(find "$ROOTFS_DIR" -type f 2>/dev/null | wc -l)

echo "============================================================"
echo "[+] Alpine RootFS đã sẵn sàng!"
echo "    Đường dẫn : ${ROOTFS_DIR}"
echo "    Kích thước : ${ROOTFS_SIZE}"
echo "    Số file    : ${FILE_COUNT}"
echo "    Shell      : ${ROOTFS_DIR}/bin/sh"
echo "============================================================"
