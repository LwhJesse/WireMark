# WireMark

WireMark is a two-endpoint **IPv4 packet authenticity and integrity gateway** for Linux.

It has one fixed primary purpose:

> Every IPv4 packet accepted by the receiving endpoint must be an authenticated,
> unmodified original packet produced by the peer WireMark endpoint.

WireMark is not a VPN product, not a proxy, not a censorship-circumvention system,
not a reliable transport, and not a traffic-hiding layer. It does not promise packet
delivery, availability, anonymity, replay-free application semantics, NAT traversal,
or general-purpose routing. Loss, delay, duplicates, throttling, and blocking are
network/path behaviours; WireMark's job is to ensure that accepted content is real.

## Security Property

For packets covered by the NFQUEUE rules, the intended invariant is:

```text
accepted IPv4 packet == authenticated original IPv4 packet from the peer endpoint
```

That means:

- modified wrapper data is rejected;
- forged wrapper data from a non-key-holder is rejected;
- unauthenticated original traffic is not allowed to bypass the active path;
- verification failure does not inject a packet into the peer's kernel stack.

A shared symmetric key authenticates membership in the two-endpoint WireMark pair.
It is not a third-party non-repudiation signature.

## Active Path

The default `wiremark run` mode uses Linux NFQUEUE in the kernel verdict path.
TUN is not the default and is not a fallback.

```text
original IPv4 packet enters OUTPUT NFQUEUE
-> normalize checksums, log metadata, compute keyed tag12
-> encrypt/authenticate into WireMark UDP wrapper fragments
-> DROP the unauthenticated original packet
-> peer INPUT NFQUEUE receives wrapper fragments
-> reassemble, decrypt, verify tag12
-> replace the wrapper with the restored original IPv4 packet
-> ACCEPT the restored packet back into the kernel
```

This is the lowest active backend currently implemented for ordinary Linux hosts
without SmartNIC, DPU, FPGA, or custom kernel code.

## Non-Goals

WireMark deliberately does not claim to provide:

- guaranteed delivery or anti-loss behaviour;
- resistance to blocking, throttling, or traffic analysis;
- stealth, obfuscation, or anonymity;
- a general VPN, transparent proxy, NAT gateway, or router;
- protection for traffic not captured by the installed NFQUEUE rules;
- protection after an endpoint, key file, rule set, or WireMark process is compromised.

Duplicates and reordering may be useful audit data. They are not treated as content
forgery: a duplicate of a valid packet is still content produced by the peer.
Applications that need exactly-once semantics must provide them above WireMark.

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

## Minimal Two-Endpoint Use

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

Receiver-side verification has three verdicts:

- `accepted`: tag12 verification succeeds and the sequence is new. The restored
  IPv4 packet is accepted. If the restored packet SHA256 was seen before, the
  log only adds `same_sha_seen_before: true`; the packet is still accepted.
- `verify_failed`: authentication fails. The candidate packet is not trusted and
  is not restored into the kernel by default.
- `duplicate_sequence`: tag12 verification succeeds, but the same WireMark
  sequence was already seen in this session. This is a duplicate/replayed
  wrapper and is handled by the replay policy.

Raw packet SHA256 is only an audit fingerprint. It is logged as
`packet_sha256`; it is never used as a trust decision or as a default drop
reason. Content repetition is only content repetition, not necessarily an
exception.

Non-accepted wrappers are written to the quarantine interface:

```text
logs/quarantine/VERDICT/*.json
logs/quarantine/VERDICT/*.packet.bin
logs/quarantine/VERDICT/*.wrapper.bin
```

The JSON manifest is the stable external-tool interface. WireMark does not
process quarantined packets itself. External tools can watch that directory,
read the manifest, inspect the binary packet/wrapper, and decide what to do.

Policies control the kernel verdict:

```sh
--invalid-policy drop|accept
--replay-policy drop|accept
```

Defaults are `drop`. `--invalid-policy accept` is an unsafe/debug mode: it
turns off WireMark's core integrity guarantee for authentication failures and
can inject unauthenticated candidate data. Do not use it for a security claim.
`--replay-policy accept` only affects verified duplicate-sequence wrappers.

## Other Commands

- `wiremark interfaces`: classify local network interfaces.
- `wiremark capture --iface auto`: passive capture only. It records traffic but
  does not protect it.
- `wiremark probe`: diagnostic experiment only. It is not the primary security path.
- `wiremark tun`: explicit non-primary TUN experiment. It is not the project goal,
  not the default, and not a fallback for `run`.

## Documentation

- Chinese usage: [docs/zh/usage.md](docs/zh/usage.md)
- English usage: [docs/en/usage.md](docs/en/usage.md)
- Chinese design: [docs/zh/design.md](docs/zh/design.md)
- English design: [docs/en/design.md](docs/en/design.md)
- Protocol pointer: [docs/protocol.md](docs/protocol.md)
