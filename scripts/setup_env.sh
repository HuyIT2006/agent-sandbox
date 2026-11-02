#!/usr/bin/env bash
set -e

echo "=========================================================="
echo "   SECURE AGENTIC SANDBOX - ENVIRONMENT SETUP SCRIPT     "
echo "=========================================================="

# 1. Check Root / Sudo for system packages
if [ "$EUID" -ne 0 ]; then
  SUDO="sudo"
  echo "[*] Running with sudo for system packages..."
else
  SUDO=""
fi

# 2. Install OS packages
echo "[*] Installing required Linux system packages..."
$SUDO apt update
$SUDO apt install -y \
    bubblewrap \
    libseccomp-dev seccomp \
    iproute2 nftables iptables dnsmasq \
    python3-pip python3-venv \
    bpftrace \
    curl jq

# 3. Setup Cgroups v2 delegation for unprivileged user
echo "[*] Configuring Cgroups v2 permissions..."
CGROUP_USER_DIR="/sys/fs/cgroup/agent_sandbox"
if [ ! -d "$CGROUP_USER_DIR" ]; then
    $SUDO mkdir -p "$CGROUP_USER_DIR"
    $SUDO chown -R $USER:$USER "$CGROUP_USER_DIR"
    echo "[+] Created cgroup delegation: $CGROUP_USER_DIR"
fi

# 4. Setup Python Virtual Environment
echo "[*] Setting up Python virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "[+] Created venv directory."
fi

source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# 5. Download minimal Alpine rootfs for Core Sandbox
echo "[*] Preparing minimal Alpine RootFS for sandbox..."
chmod +x core/download_rootfs.sh
./core/download_rootfs.sh

echo "=========================================================="
echo "   [SUCCESS] Environment setup completed successfully!    "
echo "   Activate venv with: source venv/bin/activate            "
echo "=========================================================="
