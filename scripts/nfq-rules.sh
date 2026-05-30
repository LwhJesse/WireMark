#!/usr/bin/env sh
set -eu

usage() {
  cat >&2 <<'EOF'
Usage:
  nfq-rules.sh add|del --scope all --peer-ip IP --wrapper-port PORT [--queue-num N]
  nfq-rules.sh add|del --scope flow --peer-ip IP --target-port PORT --wrapper-port PORT [--proto udp|tcp] [--queue-num N]

This installs iptables rules for WireMark NFQUEUE mode.

Scopes:
  all   Queue all local OUTPUT packets and inbound WireMark wrapper packets.
        Use this only on a dedicated experiment host.
  flow  Queue one peer/protocol/target-port flow and inbound WireMark wrapper packets.

Ports:
  --wrapper-port is the WireMark UDP wrapper port.
  --target-port is the protected application port used only by --scope flow.

WireMark's own outbound wrapper packets may still pass through OUTPUT NFQUEUE;
the daemon recognizes outbound wrapper packets and accepts them without
re-wrapping. Inbound wrapper packets are decrypted, verified, and replaced with
the original IP packet.
EOF
  exit 2
}

ACTION="${1:-}"
[ -n "$ACTION" ] || usage
shift

PEER_IP=""
TARGET_PORT=""
WRAPPER_PORT=""
PROTO="udp"
QUEUE_NUM="70"
SCOPE="all"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --scope) SCOPE="$2"; shift 2 ;;
    --peer-ip) PEER_IP="$2"; shift 2 ;;
    --target-port) TARGET_PORT="$2"; shift 2 ;;
    --wrapper-port) WRAPPER_PORT="$2"; shift 2 ;;
    --proto) PROTO="$2"; shift 2 ;;
    --queue-num) QUEUE_NUM="$2"; shift 2 ;;
    *) usage ;;
  esac
done

[ "$ACTION" = "add" ] || [ "$ACTION" = "del" ] || usage
[ -n "$PEER_IP" ] || usage
[ -n "$WRAPPER_PORT" ] || usage
[ "$SCOPE" = "all" ] || [ "$SCOPE" = "flow" ] || usage
if [ "$SCOPE" = "flow" ]; then
  [ -n "$TARGET_PORT" ] || usage
  [ "$TARGET_PORT" != "$WRAPPER_PORT" ] || {
    echo "target port and wrapper port must be different" >&2
    exit 2
  }
fi

cmd() {
  CHAIN="$1"
  shift
  if [ "$ACTION" = "add" ]; then
    iptables -I "$CHAIN" 1 "$@"
  else
    iptables -D "$CHAIN" "$@" 2>/dev/null || true
  fi
}

if [ "$SCOPE" = "all" ]; then
  cmd OUTPUT -j NFQUEUE --queue-num "$QUEUE_NUM"
else
  cmd OUTPUT -p "$PROTO" -d "$PEER_IP" --dport "$TARGET_PORT" -j NFQUEUE --queue-num "$QUEUE_NUM"
  cmd OUTPUT -p "$PROTO" -d "$PEER_IP" --sport "$TARGET_PORT" -j NFQUEUE --queue-num "$QUEUE_NUM"
fi

cmd INPUT -p udp -s "$PEER_IP" --sport "$WRAPPER_PORT" -j NFQUEUE --queue-num "$QUEUE_NUM"
cmd INPUT -p udp -s "$PEER_IP" --dport "$WRAPPER_PORT" -j NFQUEUE --queue-num "$QUEUE_NUM"

echo "WireMark NFQUEUE rules ${ACTION}ed"
