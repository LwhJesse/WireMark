# Experiment Notes

This file is intentionally not the primary usage guide.

Use the current documentation instead:

- Chinese usage: [zh/usage.md](zh/usage.md)
- Chinese design: [zh/design.md](zh/design.md)
- English usage: [en/usage.md](en/usage.md)
- English design: [en/design.md](en/design.md)

The current project purpose is fixed:

```text
accepted IPv4 packet == authenticated, unmodified original IPv4 packet produced by peer
```

Probe, capture, and TUN experiment notes are non-primary material. They are not
the project goal. WireMark's primary path is the NFQUEUE active IPv4 packet
authenticity/integrity gateway.
