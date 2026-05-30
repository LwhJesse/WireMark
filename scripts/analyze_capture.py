#!/usr/bin/env python3
import json
import sys
from collections import Counter


def load(path):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            obj = json.loads(line)
            if obj.get("event") == "capture":
                rows.append(obj)
    return rows


def main():
    if len(sys.argv) != 3:
        print("usage: analyze_capture.py <local.packets.jsonl> <remote.packets.jsonl>", file=sys.stderr)
        return 2
    local_hashes = Counter(r.get("packet_sha256", r.get("sha256", "")) for r in load(sys.argv[1]))
    remote_hashes = Counter(r.get("packet_sha256", r.get("sha256", "")) for r in load(sys.argv[2]))
    common = local_hashes & remote_hashes
    local_only = local_hashes - remote_hashes
    remote_only = remote_hashes - local_hashes
    print(json.dumps(
        {
            "local_packets": sum(local_hashes.values()),
            "remote_packets": sum(remote_hashes.values()),
            "matched_packets": sum(common.values()),
            "local_only_packets": sum(local_only.values()),
            "remote_only_packets": sum(remote_only.values()),
            "local_unique_hashes": len(local_hashes),
            "remote_unique_hashes": len(remote_hashes),
            "matched_unique_hashes": len(common),
        },
        indent=2,
        ensure_ascii=False,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
