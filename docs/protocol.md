# WireMark Protocol

This file is a stable pointer to the current protocol description.

WireMark's current protocol is the compact authenticated-original-packet format
used by the NFQUEUE active integrity gateway:

```text
len + tag12 + original_ipv4_packet
```

The protocol goal is fixed:

```text
accepted IPv4 packet == authenticated, unmodified original IPv4 packet produced by peer
```

Do not describe this protocol as a VPN, proxy, reliable transport, obfuscation
layer, or general routing protocol.

Current design documents:

- Chinese: [zh/design.md](zh/design.md)
- English: [en/design.md](en/design.md)

TLV-per-packet framing and TUN experiments are non-primary prototype material
and should not be treated as the current project purpose.
