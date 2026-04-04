#!/bin/bash
# ENShell CRE Workflow Simulator
# Usage: ./simulate.sh <tx-hash>

if [ -z "$1" ]; then
  echo "Usage: ./simulate.sh <tx-hash>"
  echo "Example: ./simulate.sh 0xc41e89f3ea3cdd04a0f73b6c41da8a95539518d371c20daab0da65926266729e"
  exit 1
fi

cre workflow simulate firewall-analyzer \
  --target staging-settings \
  --evm-tx-hash "$1" \
  --evm-event-index 0 \
  --trigger-index 0 \
  --non-interactive \
  --skip-type-checks \
  --broadcast
