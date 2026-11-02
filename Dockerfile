# Dockerfile for Secure Agentic AI Sandbox Environment
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

WORKDIR /app

# 1. Cài đặt các gói hệ điều hành cần thiết cho Sandbox & Python
RUN apt-get update && apt-get install -y --no-install-recommends \
    bubblewrap \
    libseccomp-dev \
    seccomp \
    iproute2 \
    nftables \
    iptables \
    dnsmasq \
    curl \
    jq \
    python3 \
    python3-pip \
    python3-venv \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 2. Cài đặt Python Virtual Environment & Dependencies
COPY requirements.txt /app/requirements.txt
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# 3. Tải sẵn Alpine Mini RootFS vào image để làm Base Read-Only
RUN mkdir -p /app/rootfs/alpine && \
    curl -sL https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.0-x86_64.tar.gz \
    | tar -xz -C /app/rootfs/alpine

# 4. Sao chép toàn bộ mã nguồn
COPY . /app

# 5. Cấp quyền thực thi cho các scripts
RUN chmod +x /app/core/download_rootfs.sh /app/scripts/setup_env.sh 2>/dev/null || true

EXPOSE 8000

# 6. Mặc định khởi chạy Tool Execution API
CMD ["uvicorn", "gateway.api:app", "--host", "0.0.0.0", "--port", "8000"]
