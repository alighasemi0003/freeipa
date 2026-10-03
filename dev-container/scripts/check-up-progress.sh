#!/usr/bin/env bash
set -euo pipefail
echo "==== tail up.log ===="
tail -120 /home/aligh/freeipa/dev-container/output/up.log || true
echo "==== docker ===="
docker ps --format 'table {{.Names}}\t{{.Status}}' || true
echo "==== lines ===="
wc -l /home/aligh/freeipa/dev-container/output/up.log || true
