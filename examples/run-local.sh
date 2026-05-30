#!/usr/bin/env sh
set -eu

: "${WIREMARK_PEER:?set WIREMARK_PEER to the peer IP}"

sudo ./build/wiremark run \
  --queue-num "${WIREMARK_QUEUE:-70}" \
  --listen "0.0.0.0:${WIREMARK_PORT:-47000}" \
  --peer "$WIREMARK_PEER:${WIREMARK_PORT:-47000}" \
  --key-file "${WIREMARK_KEY:-wiremark.key}" \
  --device-id wiremark-local \
  --log-dir "${WIREMARK_LOG_DIR:-logs}"
