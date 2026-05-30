# WireMark Usage

## What WireMark Is

WireMark is a two-endpoint active **IPv4 packet authenticity and integrity gateway**.

Its single core promise is:

```text
accepted IPv4 packet = authenticated, unmodified original IPv4 packet produced by the peer
```

It is not a VPN, proxy, reliable transport, anti-blocking tool, traffic-hiding
layer, router, or NAT gateway. Loss, delay, duplicates, and reordering are path
behaviours or audit signals. WireMark only guarantees that accepted content is
real.

## Primary Mode Flow

`wiremark run` uses NFQUEUE by default:

```text
original IPv4 packet enters OUTPUT NFQUEUE
-> WireMark normalizes checksums, logs SHA256/time/sequence/tuple, computes tag12
-> AES-256-GCM wraps it into WireMark UDP fragments
-> original packet is dropped
-> peer INPUT NFQUEUE receives wrapper fragments
-> reassemble, decrypt, verify tag12
-> replace the wrapper with the restored original IPv4 packet
-> ACCEPT back into the kernel
```

If a packet is covered by the NFQUEUE rules, WireMark does not care whether the
upper protocol is SSH, HTTPS, QUIC, DNS, or a custom protocol.

## Build

Install dependencies:

```sh
# Arch
sudo pacman -S --needed base-devel cmake openssl pkgconf libnetfilter_queue iptables

# Debian/Ubuntu
sudo apt install build-essential cmake pkg-config libssl-dev libnetfilter-queue-dev iptables

# Fedora
sudo dnf install gcc-c++ make cmake openssl-devel pkgconf-pkg-config libnetfilter_queue-devel iptables

# RHEL / Rocky / Alma
sudo dnf install gcc-c++ make cmake openssl-devel pkgconf-pkg-config libnetfilter_queue-devel iptables
# If libnetfilter_queue-devel is unavailable, enable the distribution EPEL/CRB-equivalent repository first.
```

Build and test:

```sh
cmake -S . -B build
cmake --build build -j
./build/wiremark selftest
./build/wiremark doctor --peer-ip PEER_IP
```

For the primary mode, `doctor` must report NFQUEUE support, including:

```text
built_with_nfqueue=yes
module_dir="/lib/modules/$(uname -r)" exists=yes
module_nfnetlink_queue=yes
```

If NFQUEUE is unavailable, `wiremark run` must fail closed. It must not silently
fall back to TUN.

## Key And Two-Endpoint Use

Use this path for the first public test. Run the same steps on both endpoints unless a step says otherwise.

### 1. Create and copy the key

Create one high-entropy key and install the same key on both endpoints:

```sh
openssl rand -hex 32 > wiremark.key
chmod 600 wiremark.key
```

Copy `wiremark.key` to the other endpoint through a private channel. Do not commit it, paste it into public issues, or include it in published logs.

### 2. Set the endpoint variables

Run this block on each endpoint before copying the commands below. `WIREMARK_PEER` is the other endpoint IP as seen by the current machine. This is the only IP value you need to change.

```sh
export WIREMARK_PEER="replace-with-peer-ip"
export WIREMARK_PORT="47000"
export WIREMARK_QUEUE="70"
export WIREMARK_KEY="wiremark.key"
export WIREMARK_LOG_DIR="logs"
```

Examples:

```text
local machine: WIREMARK_PEER is the VPS public IP
VPS:           WIREMARK_PEER is the local machine public IP
```

`WIREMARK_PORT` is the WireMark UDP wrapper port. It is not the application port being protected.

### 3. Open the wrapper UDP port

Before installing NFQUEUE rules, allow inbound UDP `$WIREMARK_PORT` on both endpoints. If one endpoint is a VPS, open the same UDP port in the cloud security group and in the host firewall. WireMark does not change cloud firewall rules for you.

Host firewall examples:

```sh
# firewalld
sudo firewall-cmd --add-port="${WIREMARK_PORT}/udp" --permanent
sudo firewall-cmd --reload

# ufw
sudo ufw allow "${WIREMARK_PORT}/udp"
```

### 4. Start WireMark before installing NFQUEUE rules

Start the daemon first. In terminal A on each endpoint:

```sh
./build/wiremark doctor --peer-ip "$WIREMARK_PEER"

sudo ./build/wiremark run \
  --queue-num "$WIREMARK_QUEUE" \
  --listen "0.0.0.0:$WIREMARK_PORT" \
  --peer "$WIREMARK_PEER:$WIREMARK_PORT" \
  --key-file "$WIREMARK_KEY" \
  --device-id wiremark-node \
  --log-dir "$WIREMARK_LOG_DIR" \
  --session nfq \
  --quarantine-dir "$WIREMARK_LOG_DIR/quarantine" \
  --invalid-policy drop \
  --replay-policy drop
```

Do not install broad NFQUEUE rules before the daemon is running. On a remote SSH machine, broad rules can interrupt your session if the daemon is not ready.

### 5. Install NFQUEUE rules from another terminal

In terminal B, after the daemon is running:

```sh
sudo scripts/nfq-rules.sh add \
  --scope all \
  --peer-ip "$WIREMARK_PEER" \
  --wrapper-port "$WIREMARK_PORT" \
  --queue-num "$WIREMARK_QUEUE"
```

`--scope all` queues local OUTPUT traffic and inbound WireMark wrapper traffic. Use it only on a dedicated experiment host.

For a narrow experiment, protect only one target application port:

```sh
export TARGET_PORT="443"
export TARGET_PROTO="udp"

sudo scripts/nfq-rules.sh add \
  --scope flow \
  --peer-ip "$WIREMARK_PEER" \
  --target-port "$TARGET_PORT" \
  --wrapper-port "$WIREMARK_PORT" \
  --proto "$TARGET_PROTO" \
  --queue-num "$WIREMARK_QUEUE"
```

`--target-port` is the application port to protect. `--wrapper-port` is the WireMark UDP wrapper port.

### 6. Stop safely

Remove NFQUEUE rules before stopping the daemon:

```sh
sudo scripts/nfq-rules.sh del \
  --scope all \
  --peer-ip "$WIREMARK_PEER" \
  --wrapper-port "$WIREMARK_PORT" \
  --queue-num "$WIREMARK_QUEUE"
```

For the narrow mode, delete with the same variables used for add:

```sh
sudo scripts/nfq-rules.sh del \
  --scope flow \
  --peer-ip "$WIREMARK_PEER" \
  --target-port "$TARGET_PORT" \
  --wrapper-port "$WIREMARK_PORT" \
  --proto "$TARGET_PROTO" \
  --queue-num "$WIREMARK_QUEUE"
```

After the rules are removed, stop the WireMark daemon with Ctrl-C.

### 7. Optional example scripts

The example scripts use the same environment variables:

```sh
WIREMARK_PEER="$WIREMARK_PEER" WIREMARK_PORT="$WIREMARK_PORT" WIREMARK_QUEUE="$WIREMARK_QUEUE" examples/run-local.sh
WIREMARK_PEER="$WIREMARK_PEER" WIREMARK_PORT="$WIREMARK_PORT" WIREMARK_QUEUE="$WIREMARK_QUEUE" examples/run-remote.sh
```


`--peer auto` is passive-learning mode. The endpoint using `auto` must receive
and verify a wrapper from the peer before it can send protected outbound packets.
Do not run both endpoints with `--peer auto`.

## Receiver Policy And Quarantine

The receiver's verdict is based only on authentication and whether the same
WireMark sequence was already seen in this session:

- `accepted`: tag12 is valid and the sequence is new. The original IPv4 packet
  is restored and accepted. If the same `packet_sha256` was seen before, the log
  only adds `same_sha_seen_before: true`; the packet is still accepted.
- `verify_failed`: authentication failed. The candidate original packet is not
  trusted and is not restored by default.
- `duplicate_sequence`: tag12 is valid, but the same WireMark sequence was
  already seen. This is a duplicate/replayed wrapper and is handled by the
  replay policy.

Raw packet SHA256 is only a log/audit fingerprint. The field is
`packet_sha256`. WireMark does not use SHA to decide whether a packet is
trusted, and content repetition is not an exceptional verdict by itself.

Non-accepted wrappers are written to the quarantine directory:

```text
logs/quarantine/VERDICT/*.json
logs/quarantine/VERDICT/*.packet.bin
logs/quarantine/VERDICT/*.wrapper.bin
```

The JSON manifest is the stable external-tool interface. WireMark does not
process quarantined packets itself. External tools can watch the directory,
read the manifest, inspect the candidate packet/wrapper, and decide what to do.

Policies control the kernel verdict:

```sh
--invalid-policy drop|accept
--replay-policy drop|accept
```

Defaults are `drop`. `--invalid-policy accept` is an unsafe/debug mode: it
turns off WireMark's core integrity guarantee for authentication failures and
can inject unauthenticated candidate data. Do not use it for a security claim.
`--replay-policy accept` only affects authenticated duplicate-sequence wrappers.

## Logs

Logs are written under `--log-dir`:

```text
SESSION.packets.jsonl
SESSION.summary.json
```

The logs are for checking the core property:

```text
sender log: this original packet was captured, tagged with tag12, and wrapped
receiver log: this restored packet passed tag12 verification and sequence policy
```

Analyze sequence numbers, `packet_sha256`, verification failures, missing
sequences, duplicate sequences, repeated content, reordering, and latency. Loss
and blocking are path behaviours; they do not mean forged or modified content
was accepted.

`packet_decision` events contain:

```text
verdict, action, policy, origin, verify_ok, verify_kind,
duplicate_sequence, same_sha_seen_before, packet_sha256, quarantine_manifest
```

## Other Commands

- `wiremark interfaces`: inspect and classify local interfaces.
- `wiremark capture --iface auto`: passive capture only. It records traffic but
  does not protect it.
- `wiremark probe`: diagnostic experiment only. It is not the primary security path.
- `wiremark tun`: explicit non-primary TUN experiment mode. It is not the default and
  is not a fallback for `run`.

## Operating Rules

- Treat only the NFQUEUE primary path as the WireMark goal.
- Do not treat TUN, passive capture, or ordinary connectivity as primary-mode
  success.
- Do not claim that WireMark prevents loss, blocking, traffic analysis, or
  provides VPN functionality.
- Claim only this: every accepted restored IPv4 packet was produced by the
  key-holding peer and was not modified on the path.
