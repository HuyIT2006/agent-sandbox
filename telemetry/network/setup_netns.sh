#!/usr/bin/env bash
# Thành viên 3: Thiết lập Network Namespace có kiểm soát Egress (Chống SSRF)
set -e

NETNS_NAME="sbx_netns"
VETH_HOST="veth-host"
VETH_SBX="veth-sbx"
HOST_IP="10.200.1.1/24"
SBX_IP="10.200.1.2/24"

if [ "$EUID" -ne 0 ]; then
  echo "[!] Cần quyền root (sudo) để cấu hình Network Namespace."
  exit 1
fi

echo "[*] Dọn dẹp cấu hình cũ nếu có..."
ip netns del "$NETNS_NAME" 2>/dev/null || true
ip link del "$VETH_HOST" 2>/dev/null || true

echo "[*] Tạo Network Namespace: $NETNS_NAME"
ip netns add "$NETNS_NAME"

echo "[*] Tạo veth pair ($VETH_HOST <-> $VETH_SBX)..."
ip link add "$VETH_HOST" type veth peer name "$VETH_SBX"
ip link set "$VETH_SBX" netns "$NETNS_NAME"

echo "[*] Gán địa chỉ IP..."
ip addr add "$HOST_IP" dev "$VETH_HOST"
ip link set "$VETH_HOST" up

ip netns exec "$NETNS_NAME" ip addr add "$SBX_IP" dev "$VETH_SBX"
ip netns exec "$NETNS_NAME" ip link set "$VETH_SBX" up
ip netns exec "$NETNS_NAME" ip link set lo up
ip netns exec "$NETNS_NAME" ip route add default via 10.200.1.1

echo "[*] Thiết lập quy tắc tường lửa Egress (Chống SSRF)..."
# 1. Chặn Cloud Metadata IP (169.254.169.254)
iptables -I FORWARD -s 10.200.1.2 -d 169.254.169.254 -j DROP

# 2. Chặn truy cập mạng nội bộ LAN / Private IPs
iptables -I FORWARD -s 10.200.1.2 -d 10.0.0.0/8 -j DROP
iptables -I FORWARD -s 10.200.1.2 -d 172.16.0.0/12 -j DROP
iptables -I FORWARD -s 10.200.1.2 -d 192.168.0.0/16 -j DROP

echo "[+] Cấu hình Network Namespace & Egress Firewall hoàn tất!"
echo "    Để test trong netns: sudo ip netns exec $NETNS_NAME ping 10.200.1.1"
