#!/usr/bin/env python3
"""Merge pcov capture files into one {relative path: [lines]} map."""
from __future__ import annotations

import collections
import glob
import json
import os
import sys


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: merge_coverage.py <cov_dir> <out.json> [app_root]", file=sys.stderr)
        return 2

    cov_dir, out_path = sys.argv[1], sys.argv[2]
    app_root = sys.argv[3] if len(sys.argv) > 3 else "/var/www/MISP/app/"

    merged: dict[str, set[int]] = collections.defaultdict(set)
    captures = 0
    for path in glob.glob(os.path.join(cov_dir, "*.json")):
        if os.path.basename(path) == os.path.basename(out_path):
            continue
        try:
            with open(path) as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            # A capture truncated by a killed request is expected; skip it.
            continue
        captures += 1
        for src, lines in data.items():
            merged[src.replace(app_root, "")].update(lines)

    with open(out_path, "w") as handle:
        json.dump({k: sorted(v) for k, v in merged.items()}, handle)

    print(
        f"merged {captures} captures -> {len(merged)} files, "
        f"{sum(len(v) for v in merged.values())} lines"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
