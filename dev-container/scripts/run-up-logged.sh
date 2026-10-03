#!/usr/bin/env bash
set -euo pipefail
cd /home/aligh/freeipa
mkdir -p dev-container/output
exec ./dev-container/up.sh >dev-container/output/up.log 2>&1
