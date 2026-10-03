#!/usr/bin/env bash
set -euo pipefail
LOG=/home/aligh/freeipa/dev-container/output/up.log
echo "==== last 60 lines ===="
tail -n 60 "$LOG"
echo "==== error lines ===="
grep -E 'error:|Error|Illegal|FAILED|RPM build complete|Verifying critical|Building RPMs' "$LOG" | tail -40 || true
