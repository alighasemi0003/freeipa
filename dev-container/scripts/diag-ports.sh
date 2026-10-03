#!/usr/bin/env bash
set -euo pipefail
echo "=== listening ports ==="
ss -tlnp 2>/dev/null | grep -E ':(80|443|389|636|88|464)\b' || echo "(none matching)"
ss -ulnp 2>/dev/null | grep -E ':(88|464)\b' || true
echo "=== containers ==="
docker ps -a --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' | head -30
echo "=== compose ports ==="
grep -E 'PORT|ports:' -A20 /home/aligh/freeipa/dev-container/docker-compose.yml | head -40
echo "=== env ports ==="
grep -E '^[A-Z_]*PORT=' /home/aligh/freeipa/dev-container/.env || true
echo "=== docker info cgroup ==="
docker info 2>/dev/null | grep -Ei 'cgroup|Operating System|Server Version' || true
