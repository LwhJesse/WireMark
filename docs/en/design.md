# WireMark Technical Design

## Project Boundary

WireMark is a two-endpoint active **IPv4 packet authenticity and integrity gateway**.

It does one thing:

> Every IPv4 packet accepted back into the receiver's kernel must be an
> authenticated, unmodified original IPv4 packet produced by the peer WireMark
> endpoint.

Equivalently:

```text
accepted IPv4 packet == authenticated original IPv4 packet from peer
```

WireMark is not a VPN, proxy, reliable transport, anti-blocking system,
traffic-hiding layer, general router, or NAT gateway. Packet loss, delay,
throttling, blocking, duplication, and reordering are path behaviours or audit
signals. WireMark does not repair them. It only fixes the authenticity and
integrity rule for accepted content.

## Threat Model

WireMark protects against unauthenticated content modification, forgery, and
injection by the network path.

Without the WireMark key, an on-path attacker cannot create new content that the
receiver accepts as peer-produced, and cannot change peer-produced content into
different content that the receiver silently accepts.

The attacker can still:

- drop packets;
- delay packets;
- throttle or block traffic;
- copy observed wrappers;
- deliver an old valid wrapper again;
- observe endpoint IPs, ports, sizes, direction, and timing.

These capabilities do not violate WireMark's core property: **if the receiver
accepts a packet, that packet was produced by the key-holding peer and its
content was not modified on the path.**

Applications that need exactly-once semantics or business-level deduplication
must implement them above WireMark. WireMark sequence numbers and logs can help
observe loss, duplicates, and reordering, but reliable delivery is not the
project goal.

## Primary Backend

Default `wiremark run` uses NFQUEUE, not TUN. TUN remains only as the explicit
non-primary `wiremark tun` experiment backend. It is not the default and not a
failure fallback.

The deployable layer boundary on ordinary machines and VPS instances is:

```text
SmartNIC/DPU/FPGA firmware: not required by this project
Linux kernel verdict path: WireMark primary path
TUN/application proxy layer: higher layer, explicit experiment only
```

The primary implementation uses the NFQUEUE verdict path:

```text
OUTPUT NFQUEUE: intercept original IPv4 packet -> authenticate/wrap -> DROP original
INPUT  NFQUEUE: intercept wrapper -> verify/unwrap -> replace with original IPv4 packet -> ACCEPT
```

If NFQUEUE is unavailable, the program must fail closed. It must not downgrade
to TUN or passive capture.

## Data Path

Sender:

```text
original IPv4 packet enters OUTPUT NFQUEUE
-> normalize checksums
-> log metadata and SHA256
-> compute keyed tag12
-> place into compact plaintext
-> AES-256-GCM encrypt/authenticate
-> send UDP wrapper fragments
-> return NF_DROP for the original packet
```

Receiver:

```text
wrapper fragment enters INPUT NFQUEUE
-> reassemble fragments
-> AES-256-GCM decrypt/authenticate
-> verify tag12
-> check authentication result and duplicate sequence within the session
-> restore original IPv4 packet
-> normalize checksums
-> replace the current queued wrapper with the restored packet
-> return NF_ACCEPT
```

On authentication failure, malformed input, reassembly failure, wrong key, or
wrong tag, the receiver does not restore the original packet by default.
Receiver policy only handles authentication failures and duplicate sequences. SHA256 is only a log/audit fingerprint and is not used for trust decisions. Non-accepted wrappers are saved to the quarantine interface for external tooling.

## Compact Plaintext

Each encrypted plaintext currently carries one original packet. The format keeps
batching capability:

```text
base_sequence varint
packet_count varint

repeat:
  original_len varint
  tag12 12 bytes
  original_packet original_len bytes
```

`tag12` is a keyed authentication tag:

```text
tag12 = HMAC-SHA256(integrity_key, seq || original_packet)[0:12]
```

The point is not ordinary hashing or deduplication. The point is that a non-key-
holder cannot construct accepted original packet content.

## Outer WireMark Frame

The compact plaintext is placed into a WireMark frame:

```text
magic/version/type/flags
session_id
frame_sequence
nonce
ciphertext_length
AES-256-GCM ciphertext+tag
```

The frame header is authenticated as AES-GCM AAD, and the payload is encrypted.
The shared symmetric key authenticates membership in the two-endpoint WireMark
pair. It is not a third-party non-repudiation signature.

## UDP Wrapper Fragmentation

The NFQUEUE backend sends wrappers over UDP. To avoid relying on outer IP
fragmentation, WireMark fragments frames at the application layer:

```text
WMF1
frame_id
fragment_index
fragment_count
fragment_len
fragment_payload
```

The receiver waits for a complete WireMark frame. Only after successful
reassembly and verification does it replace the current queued wrapper with the
restored original IPv4 packet.

## Checksum Handling

Before computing tag12, WireMark normalizes the IPv4 header checksum and
recomputes L4 checksums for unfragmented TCP, UDP, and ICMP packets. The
receiver normalizes again before reinjecting the restored packet. This prevents
checksum-offload intermediate state from being treated as ordinary packet bytes.

## Rule Scope

`scripts/nfq-rules.sh` supports two scopes:

- `--scope all`: queue local OUTPUT IPv4 packets and inbound wrappers. Use it on
  a dedicated experiment host. This is not a general VPN or transparent proxy
  promise.
- `--scope flow`: queue one selected peer/protocol/port flow and inbound
  wrappers. Use it for narrow validation.

If WireMark's own outbound wrapper is queued again by OUTPUT rules, the daemon
recognizes it as a wrapper and ACCEPTs it without wrapping again.

## Log Semantics

Logs audit the core property: which original packets were produced by the
sender, and which restored packets were verified and accepted by the receiver.

The sender records sequence, send time, original packet SHA256, tuple metadata,
and length. The receiver records receive time, verification result, restored
packet SHA256, tuple metadata, and length.

Logs can be used to analyze:

- which sequences were sent;
- which sequences were verified and accepted;
- which sequences are missing;
- verification failures, duplicates, reordering, and latency anomalies.

Loss is not treated as a content-security failure. Loss is path behaviour or an
interference signal.

## Exceptional Policy And Quarantine

Receiver-side verdicts:

- `accepted`: tag12 is valid and the sequence is new, so the packet is restored and accepted.
- `verify_failed`: authentication failed; the default is to drop and not restore.
- `duplicate_sequence`: tag12 is valid, but the same sequence was already seen in this session; replay policy applies.

`packet_sha256` is only for logging/audit. Valid tag + new sequence + old SHA is
still `accepted`; the log only adds `same_sha_seen_before: true`. WireMark no
longer uses duplicate SHA to decide whether to drop a packet.

Defaults are `drop`. Users can switch policies to `accept`:

```text
--invalid-policy drop|accept
--replay-policy drop|accept
```

`--invalid-policy accept` is an unsafe/debug mode. It turns off the core
integrity guarantee for authentication failures; a run in this mode must not be
presented as satisfying the normal WireMark security property. `--replay-policy
accept` only affects authenticated duplicate-sequence wrappers.

Non-accepted wrappers write:

```text
quarantine/VERDICT/*.json
quarantine/VERDICT/*.packet.bin
quarantine/VERDICT/*.wrapper.bin
```

The JSON manifest is the stable interface for external tools. WireMark does not
perform business handling, repair, or forensic analysis of quarantined packets.
Repeated content is only repeated content, not necessarily an exception; repeated
sequence numbers identify duplicate wrappers.

## Current Implementation Scope

- The primary path is IPv4-only.
- The primary mode is NFQUEUE. TUN is an explicit non-primary experiment mode.
- Runtime currently carries one original packet per WireMark frame. The format
  leaves room for batching, but the active path is not throughput-optimized.
- WireMark does not protect traffic not covered by NFQUEUE rules.
- WireMark does not protect compromised endpoints, leaked keys, modified rules,
  or replaced processes.
