#!/usr/bin/env sh
set -eu

PORT="${WIREMARK_PORT:-47000}"
: "${WIREMARK_PEER:?set WIREMARK_PEER to the peer IP}"
PEER="$WIREMARK_PEER"
PEER="$PEER:$PORT"

sudo ./build/wiremark run \
  --queue-num "${WIREMARK_QUEUE:-70}" \
  --listen "0.0.0.0:$PORT" \
  --peer "$PEER" \
  --key-file "${WIREMARK_KEY:-wiremark.key}" \
  --device-id wiremark-remote \
  --log-dir "${WIREMARK_LOG_DIR:-logs}"
