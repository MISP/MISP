#!/usr/bin/env python3
"""
Compare two attribute_search_bench.py text outputs.

Highlights:
  - Queries where the hit count differs (possible correctness issue)
  - Queries where the median time changed by >= 50%

Usage:
    python3 tests/attribute_search_bench_diff.py before.txt after.txt
"""

import re
import sys

# Matches lines like:
#   1   type_domain                500   0.069s   0.065s   0.077s
LINE_RE = re.compile(
    r"^\s*(\d+)\s+"      # index
    r"(\S+)\s+"           # name
    r"(-?\d+|ERR)\s+"    # hits
    r"(\d+\.\d+)s\s+"    # median
    r"(\d+\.\d+)s\s+"    # min
    r"(\d+\.\d+)s"       # max
)


def parse(path):
    """Return {name: (hits, median, min, max)} from a benchmark text file."""
    rows = {}
    with open(path) as f:
        for line in f:
            m = LINE_RE.match(line)
            if m:
                name = m.group(2)
                hits = int(m.group(3)) if m.group(3) != "ERR" else None
                median = float(m.group(4))
                lo = float(m.group(5))
                hi = float(m.group(6))
                rows[name] = (hits, median, lo, hi)
    return rows


def fmt_pct(old, new):
    if old == 0:
        return "+inf" if new > 0 else "0%"
    pct = (new - old) / old * 100
    sign = "+" if pct >= 0 else ""
    return f"{sign}{pct:.0f}%"


def fmt_time(t):
    return f"{t:.3f}s"


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <before.txt> <after.txt>")
        sys.exit(1)

    path_a, path_b = sys.argv[1], sys.argv[2]
    a = parse(path_a)
    b = parse(path_b)

    if not a:
        print(f"Error: no benchmark lines found in {path_a}")
        sys.exit(1)
    if not b:
        print(f"Error: no benchmark lines found in {path_b}")
        sys.exit(1)

    all_names = list(dict.fromkeys(list(a.keys()) + list(b.keys())))

    hit_diffs = []
    faster = []
    slower = []
    missing = []

    for name in all_names:
        if name not in a:
            missing.append((name, "missing from before"))
            continue
        if name not in b:
            missing.append((name, "missing from after"))
            continue

        h_a, med_a, _, _ = a[name]
        h_b, med_b, _, _ = b[name]

        if h_a is not None and h_b is not None and h_a != h_b:
            hit_diffs.append((name, h_a, h_b))

        if med_a > 0:
            change = (med_b - med_a) / med_a
        elif med_b > 0:
            change = float("inf")
        else:
            change = 0.0

        if abs(change) >= 0.5:
            entry = (name, med_a, med_b, change)
            if change < 0:
                faster.append(entry)
            else:
                slower.append(entry)

    faster.sort(key=lambda x: x[3])
    slower.sort(key=lambda x: -x[3])

    W = 40

    print("=" * 72)
    print(" Benchmark Comparison")
    print(f"  Before: {path_a}  ({len(a)} queries)")
    print(f"  After:  {path_b}  ({len(b)} queries)")
    print("=" * 72)

    # ── Hit count differences ──
    print()
    if hit_diffs:
        print(
            f"!! HIT COUNT DIFFERENCES "
            f"({len(hit_diffs)} queries) !!"
        )
        print(
            "   A changed hit count with the same data means "
            "a behavioural change."
        )
        print()
        print(
            f"   {'Query':<{W}} {'Before':>8} {'After':>8} "
            f"{'Delta':>8}"
        )
        print(f"   {'-' * W} {'-' * 8} {'-' * 8} {'-' * 8}")
        for name, h_a, h_b in hit_diffs:
            delta = h_b - h_a
            sign = "+" if delta > 0 else ""
            print(
                f"   {name:<{W}} {h_a:>8} {h_b:>8} "
                f"{sign}{delta:>7}"
            )
    else:
        print("No hit count differences — results are consistent.")

    # ── Performance improvements ──
    print()
    if faster:
        print(f"FASTER ({len(faster)} queries, >= 50% improvement):")
        print()
        print(
            f"   {'Query':<{W}} {'Before':>8} {'After':>8} "
            f"{'Change':>8}"
        )
        print(f"   {'-' * W} {'-' * 8} {'-' * 8} {'-' * 8}")
        for name, med_a, med_b, change in faster:
            print(
                f"   {name:<{W}} {fmt_time(med_a):>8} "
                f"{fmt_time(med_b):>8} {fmt_pct(med_a, med_b):>8}"
            )
    else:
        print("No queries improved by >= 50%.")

    # ── Performance regressions ──
    print()
    if slower:
        print(f"SLOWER ({len(slower)} queries, >= 50% regression):")
        print()
        print(
            f"   {'Query':<{W}} {'Before':>8} {'After':>8} "
            f"{'Change':>8}"
        )
        print(f"   {'-' * W} {'-' * 8} {'-' * 8} {'-' * 8}")
        for name, med_a, med_b, change in slower:
            print(
                f"   {name:<{W}} {fmt_time(med_a):>8} "
                f"{fmt_time(med_b):>8} {fmt_pct(med_a, med_b):>8}"
            )
    else:
        print("No queries regressed by >= 50%.")

    # ── Missing queries ──
    if missing:
        print()
        print(f"MISSING ({len(missing)}):")
        for name, reason in missing:
            print(f"   {name:<{W}} {reason}")

    # ── Full table ──
    print()
    print("-" * 72)
    print(" Full comparison")
    print("-" * 72)
    print(
        f"   {'Query':<{W}} {'Before':>8} {'After':>8} "
        f"{'Change':>8} {'Hits':>12}"
    )
    print(
        f"   {'-' * W} {'-' * 8} {'-' * 8} "
        f"{'-' * 8} {'-' * 12}"
    )
    total_a = 0.0
    total_b = 0.0
    for name in all_names:
        if name not in a or name not in b:
            continue
        h_a, med_a, _, _ = a[name]
        h_b, med_b, _, _ = b[name]
        total_a += med_a
        total_b += med_b
        pct = fmt_pct(med_a, med_b)

        hit_str = f"{h_a}/{h_b}"
        if h_a != h_b:
            hit_str += " !!"

        print(
            f"   {name:<{W}} {fmt_time(med_a):>8} "
            f"{fmt_time(med_b):>8} {pct:>8} {hit_str:>12}"
        )

    print()
    pct_total = fmt_pct(total_a, total_b)
    print(
        f"   {'TOTAL':<{W}} {fmt_time(total_a):>8} "
        f"{fmt_time(total_b):>8} {pct_total:>8}"
    )
    print()


if __name__ == "__main__":
    main()
