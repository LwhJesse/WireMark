#!/usr/bin/env sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <tun-name> <cidr-address>" >&2
  echo "example: sudo $0 wm0 10.66.0.1/30" >&2
  exit 2
fi

ip addr add "$2" dev "$1" 2>/dev/null || true
ip link set "$1" up
