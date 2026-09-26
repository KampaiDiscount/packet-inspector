#!/usr/bin/env python3
"""Compare two captures by full-frame hashes without printing packet contents."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib

from scapy.utils import RawPcapNgReader, RawPcapReader


def _frames(path: str) -> tuple[Counter[str], list[str]]:
    reader = RawPcapNgReader if path.lower().endswith(".pcapng") else RawPcapReader
    with reader(path) as capture:
        ordered = [hashlib.sha256(raw).hexdigest() for raw, _metadata in capture]
        return Counter(ordered), ordered


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("expected")
    parser.add_argument("observed")
    args = parser.parse_args()
    expected, expected_order = _frames(args.expected)
    observed, _ = _frames(args.observed)
    missing = expected - observed
    unexpected = observed - expected
    print({
        "expected": expected.total(),
        "observed": observed.total(),
        "matched": (expected & observed).total(),
        "missing": missing.total(),
        "unexpected": unexpected.total(),
        "missing_hash_prefixes": [key[:16] for key in missing][:8],
        "missing_first_indices": [
            index for index, key in enumerate(expected_order, 1) if key in missing
        ][:8],
    })


if __name__ == "__main__":
    main()
