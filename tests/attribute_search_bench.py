#!/usr/bin/env python3
"""
Attribute restSearch benchmark suite.

Runs a set of predefined queries against /attributes/restSearch and
reports timing + hit counts.  Compare output across branches/commits
to spot performance regressions or improvements.

Usage:
    python3 tests/attribute_search_bench.py [BASE_URL]

Environment:
    KEY_ADMIN   API key (default: reads from script)
    BENCH_RUNS  Repetitions per query for median timing (default: 3)
"""

import json
import os
import statistics
import sys
import time
import urllib.request
import ssl

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5007"
KEY = os.environ.get(
    "KEY_ADMIN",
    "runyXUZC6aTu4KnxIkh79qDxjQjeIPtXpWjDy2Xv",
)
RUNS = int(os.environ.get("BENCH_RUNS", "3"))

# Accept self-signed certs on dev instances
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

# ── query catalogue ──────────────────────────────────
#
# Each entry: (short_name, description, json_body)
#
# The limit is intentionally set high on most queries so the
# benchmark measures real query cost, not just "return 5 rows".

QUERIES = [
    # -- Single attribute-table filters --
    (
        "type_domain",
        "Single type filter (domain)",
        {"type": "domain", "limit": 500, "returnFormat": "json"},
    ),
    (
        "type_ip-dst",
        "Single type filter (ip-dst)",
        {"type": "ip-dst", "limit": 500, "returnFormat": "json"},
    ),
    (
        "type_sha256",
        "Single type filter (sha256)",
        {"type": "sha256", "limit": 500, "returnFormat": "json"},
    ),
    (
        "category_network",
        "Category filter (Network activity)",
        {
            "category": "Network activity",
            "limit": 500,
            "returnFormat": "json",
        },
    ),
    (
        "to_ids_only",
        "IDS-flagged attributes only",
        {"to_ids": 1, "limit": 500, "returnFormat": "json"},
    ),

    # -- Value / wildcard filters --
    (
        "value_exact",
        "Exact value lookup",
        {"value": "8.8.8.8", "limit": 100, "returnFormat": "json"},
    ),
    (
        "value_wildcard_suffix",
        "Wildcard suffix (%.example.com)",
        {"value": "%.example.com", "limit": 500, "returnFormat": "json"},
    ),
    (
        "value_wildcard_prefix",
        "Wildcard prefix (192.168.%)",
        {"value": "192.168.%", "limit": 500, "returnFormat": "json"},
    ),
    (
        "value_wildcard_middle",
        "Wildcard middle (%google%)",
        {"value": "%google%", "limit": 500, "returnFormat": "json"},
    ),

    # -- Timestamp filters --
    (
        "timestamp_7d",
        "Attributes modified in last 7 days",
        {"timestamp": "7d", "limit": 500, "returnFormat": "json"},
    ),
    (
        "timestamp_30d",
        "Attributes modified in last 30 days",
        {"timestamp": "30d", "limit": 500, "returnFormat": "json"},
    ),
    (
        "timestamp_365d",
        "Attributes modified in last 365 days",
        {"timestamp": "365d", "limit": 500, "returnFormat": "json"},
    ),

    # -- Event-table filters --
    (
        "published_only",
        "Published events only",
        {"published": 1, "limit": 500, "returnFormat": "json"},
    ),
    (
        "threat_level_1",
        "Threat level = High",
        {"threat_level_id": 1, "limit": 500, "returnFormat": "json"},
    ),

    # -- Tag filters (positive) --
    (
        "tag_single",
        "Single positive tag (tlp:white)",
        {"tags": "tlp:white", "limit": 500, "returnFormat": "json"},
    ),
    (
        "tag_or_multi",
        "OR tags [tlp:white, tlp:green]",
        {
            "tags": ["tlp:white", "tlp:green"],
            "limit": 500,
            "returnFormat": "json",
        },
    ),
    (
        "tag_wildcard",
        "Wildcard tag (tlp:%)",
        {"tags": "tlp:%", "limit": 500, "returnFormat": "json"},
    ),

    # -- Tag filters (negative) --
    (
        "tag_not_single",
        "Exclude single tag (!tlp:red)",
        {
            "tags": {"NOT": ["tlp:red"]},
            "limit": 500,
            "returnFormat": "json",
        },
    ),
    (
        "tag_not_wildcard",
        "Exclude wildcard tag (!tlp:%)",
        {
            "tags": {"NOT": ["tlp:%"]},
            "limit": 500,
            "returnFormat": "json",
        },
    ),

    # -- Tag filters (AND) --
    (
        "tag_and_two",
        "AND two tags",
        {
            "tags": {"AND": ["tlp:white", "tlp:green"]},
            "limit": 500,
            "returnFormat": "json",
        },
    ),

    # -- Combined tag expressions --
    (
        "tag_combined_not_or",
        "Combined: !tlp:red + tlp:%",
        {
            "tags": ["!tlp:red", "tlp:%"],
            "limit": 500,
            "returnFormat": "json",
        },
    ),
    (
        "tag_combined_not_and_type",
        "Combined: !tlp:red + type:domain",
        {
            "type": "domain",
            "tags": {"NOT": ["tlp:red"]},
            "limit": 500,
            "returnFormat": "json",
        },
    ),

    # -- Cross-table combined filters --
    (
        "cross_type_published",
        "type:domain + published",
        {
            "type": "domain",
            "published": 1,
            "limit": 500,
            "returnFormat": "json",
        },
    ),
    (
        "cross_type_tag_published",
        "type:domain + tag:tlp:white + published",
        {
            "type": "domain",
            "tags": "tlp:white",
            "published": 1,
            "limit": 500,
            "returnFormat": "json",
        },
    ),
    (
        "cross_type_timestamp_tag",
        "type:ip-dst + 365d + tag:tlp:white",
        {
            "type": "ip-dst",
            "timestamp": "365d",
            "tags": "tlp:white",
            "limit": 500,
            "returnFormat": "json",
        },
    ),
    (
        "cross_type_toids_timestamp",
        "type:domain + to_ids + 30d",
        {
            "type": "domain",
            "to_ids": 1,
            "timestamp": "30d",
            "limit": 500,
            "returnFormat": "json",
        },
    ),

    # -- Heavy combined queries (the kind that trigger slow perf) --
    (
        "heavy_type_timestamp_tags",
        "type + timestamp + tags (reported slow query pattern)",
        {
            "type": ["md5", "sha1", "sha256", "domain", "ip-dst"],
            "timestamp": "90d",
            "tags": ["tlp:white", "tlp:green"],
            "limit": 500,
            "returnFormat": "json",
        },
    ),
    (
        "heavy_multi_type_neg_tag",
        "Multi-type + negative tag + published",
        {
            "type": ["domain", "ip-dst", "url"],
            "published": 1,
            "tags": {"NOT": ["tlp:red"]},
            "limit": 500,
            "returnFormat": "json",
        },
    ),
    (
        "heavy_wildcard_tag_timestamp",
        "Wildcard tag + timestamp + to_ids",
        {
            "tags": "tlp:%",
            "timestamp": "180d",
            "to_ids": 1,
            "limit": 500,
            "returnFormat": "json",
        },
    ),
    (
        "heavy_combined_and_not",
        "AND tags + NOT tag + type + published",
        {
            "type": "domain",
            "published": 1,
            "tags": {
                "AND": ["tlp:white"],
                "NOT": ["tlp:red"],
            },
            "limit": 500,
            "returnFormat": "json",
        },
    ),

    # ── Join-order-sensitive queries ─────────────────
    #
    # These queries pair filters of very different selectivity
    # so the optimal join order varies.  The naming convention:
    #   jo_<what_should_lead>_<what_is_broad>
    #
    # If the optimizer picks the wrong driving table, these
    # will be disproportionately slow.

    # -- Attr-tag selective, attribute table permissive --
    # Rare attr tag (~1-10 rows in attribute_tags) + deleted=0
    # (nearly all rows).  Best plan: scan attribute_tags first,
    # then probe attributes.
    (
        "jo_attrtag_deleted",
        "Rare attr tag + deleted:0 (tag should lead)",
        {
            "tags": "type:OSINT",
            "deleted": 0,
            "limit": 500,
            "returnFormat": "json",
        },
    ),
    # Broad attr tag (tlp:white, 80K attr tags) + deleted=0.
    # Contrast with above — both filter attribute_tags but with
    # vastly different selectivity.
    (
        "jo_broadtag_deleted",
        "Broad attr tag + deleted:0 (attr table may lead)",
        {
            "tags": "tlp:white",
            "deleted": 0,
            "limit": 500,
            "returnFormat": "json",
        },
    ),

    # -- Value selective, tag permissive --
    # Exact value (few rows via index) + broad wildcard tag.
    # Best plan: probe value index first, then check tags.
    (
        "jo_value_broadtag",
        "Exact value + broad tag (value should lead)",
        {
            "value": "8.8.8.8",
            "tags": "tlp:%",
            "limit": 500,
            "returnFormat": "json",
        },
    ),
    # Wildcard value (%google%) + narrow attr tag.
    # Best plan: scan attribute_tags first (few rows), then
    # LIKE-filter on joined attributes.
    (
        "jo_wildval_narrowtag",
        "Wildcard value + narrow tag (tag should lead)",
        {
            "value": "%google%",
            "tags": "type:OSINT",
            "limit": 500,
            "returnFormat": "json",
        },
    ),

    # -- Event-tag selective, attribute table permissive --
    # Event-only tag (312 events via event_tags, 0 attr tags)
    # + permissive type (sha256, 780K rows).
    # Best plan: resolve event_tags → event_ids first, then
    # filter attributes by event_id + type.
    (
        "jo_eventtag_bigtype",
        "Event-only tag + huge type (event_tags should lead)",
        {
            "tags": 'workflow:state="draft"',
            "type": "sha256",
            "limit": 500,
            "returnFormat": "json",
        },
    ),
    # Event-only tag + no other filter — pure event_tags scan.
    (
        "jo_eventtag_noattr",
        "Event-only tag, no attr filter (pure event_tags)",
        {
            "tags": 'workflow:state="draft"',
            "limit": 500,
            "returnFormat": "json",
        },
    ),
    # Broad event tag (tlp:white, 3278 events) + rare type.
    # Best plan: type index first (tiny), then check event tag.
    (
        "jo_raretype_broadevttag",
        "Rare type + broad event tag (type should lead)",
        {
            "type": "twitter-id",
            "tags": "tlp:white",
            "limit": 500,
            "returnFormat": "json",
        },
    ),

    # -- Timestamp selective, tag permissive --
    # Narrow timestamp (7d, few rows) + broad tag (tlp:%).
    # Best plan: timestamp index first.
    (
        "jo_timestamp_broadtag",
        "Narrow timestamp + broad tag (timestamp should lead)",
        {
            "timestamp": "7d",
            "tags": "tlp:%",
            "limit": 500,
            "returnFormat": "json",
        },
    ),
    # Wide timestamp (365d, most rows) + narrow event tag.
    # Best plan: event_tags first.
    (
        "jo_widetimestamp_narrowevttag",
        "Wide timestamp + narrow event tag (tag should lead)",
        {
            "timestamp": "365d",
            "tags": "type:OSINT",
            "limit": 500,
            "returnFormat": "json",
        },
    ),

    # -- Multi-table pile-ups --
    # These combine 3+ filter axes to stress the planner.

    # Narrow timestamp + narrow event tag + broad type
    (
        "jo_3way_ts_evttag_type",
        "3-way: 7d + event tag + broad type",
        {
            "timestamp": "7d",
            "tags": "type:OSINT",
            "type": "domain",
            "limit": 500,
            "returnFormat": "json",
        },
    ),
    # Broad timestamp + broad tag + narrow value
    (
        "jo_3way_val_ts_tag",
        "3-way: exact value + 365d + broad tag",
        {
            "value": "8.8.8.8",
            "timestamp": "365d",
            "tags": "tlp:%",
            "limit": 500,
            "returnFormat": "json",
        },
    ),
    # Event-only tag + event published + type + to_ids
    (
        "jo_4way_evttag_pub_type_ids",
        "4-way: event tag + published + type + to_ids",
        {
            "tags": 'workflow:state="draft"',
            "published": 1,
            "type": "domain",
            "to_ids": 1,
            "limit": 500,
            "returnFormat": "json",
        },
    ),
    # AND tags (two broad) + negative tag + narrow timestamp
    (
        "jo_and_not_timestamp",
        "AND[tlp:white,tlp:green] + NOT[tlp:red] + 30d",
        {
            "tags": {
                "AND": ["tlp:white", "tlp:green"],
                "NOT": ["tlp:red"],
            },
            "timestamp": "30d",
            "limit": 500,
            "returnFormat": "json",
        },
    ),
    # Wildcard value + event-only tag + published
    (
        "jo_wildval_evttag_pub",
        "Wildcard value + event-only tag + published",
        {
            "value": "%malware%",
            "tags": 'workflow:state="draft"',
            "published": 1,
            "limit": 500,
            "returnFormat": "json",
        },
    ),

    # -- Deleted attribute edge cases --
    # deleted=1 (include all) is rare but forces different scan
    (
        "jo_deleted_all_tag",
        "Show deleted + tag (deleted changes row count)",
        {
            "deleted": 1,
            "tags": "tlp:white",
            "limit": 500,
            "returnFormat": "json",
        },
    ),
    (
        "jo_deleted_only_type",
        "Deleted only + type (tiny rowset)",
        {
            "deleted": 2,
            "type": "domain",
            "limit": 500,
            "returnFormat": "json",
        },
    ),

    # -- Category with wildly different cardinality vs tag --
    # Tiny category (Person, 12 rows) + broad tag
    (
        "jo_tinycat_broadtag",
        "Tiny category + broad tag (category should lead)",
        {
            "category": "Person",
            "tags": "tlp:%",
            "limit": 500,
            "returnFormat": "json",
        },
    ),
    # Huge category (Payload delivery, 1.1M) + narrow event tag
    (
        "jo_hugecat_narrowevttag",
        "Huge category + narrow event tag (tag should lead)",
        {
            "category": "Payload delivery",
            "tags": "type:OSINT",
            "limit": 500,
            "returnFormat": "json",
        },
    ),
]


def run_query(body):
    """Execute a single restSearch call, return (hits, seconds)."""
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        f"{BASE}/attributes/restSearch",
        data=data,
        headers={
            "Authorization": KEY,
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )
    t0 = time.perf_counter()
    with urllib.request.urlopen(req, context=CTX) as resp:
        raw = resp.read()
    elapsed = time.perf_counter() - t0
    result = json.loads(raw)
    if "response" in result and "Attribute" in result["response"]:
        hits = len(result["response"]["Attribute"])
    else:
        hits = -1
    return hits, elapsed


def main():
    print(f"{'=' * 78}")
    print(f" Attribute restSearch Benchmark")
    print(f" {BASE}  |  {RUNS} run(s) per query")
    print(f"{'=' * 78}")
    print()
    W = 38  # name column width
    print(
        f"{'#':<3} {'Name':<{W}} {'Hits':>6} "
        f"{'Median':>8} {'Min':>8} {'Max':>8}"
    )
    print(
        f"{'-' * 3} {'-' * W} {'-' * 6} "
        f"{'-' * 8} {'-' * 8} {'-' * 8}"
    )

    total_time = 0.0
    prev_prefix = None
    for idx, (name, desc, body) in enumerate(QUERIES, 1):
        # Print a separator between sections
        prefix = name.split("_")[0]
        if prev_prefix and prefix != prev_prefix:
            print()
        prev_prefix = prefix

        timings = []
        hits = 0
        for _ in range(RUNS):
            try:
                h, t = run_query(body)
                hits = h
                timings.append(t)
            except Exception as e:
                print(
                    f"{idx:<3} {name:<{W}} {'ERR':>6} "
                    f"{str(e)[:40]}"
                )
                break
        else:
            med = statistics.median(timings)
            lo = min(timings)
            hi = max(timings)
            total_time += med
            print(
                f"{idx:<3} {name:<{W}} {hits:>6} "
                f"{med:>7.3f}s {lo:>7.3f}s {hi:>7.3f}s"
            )

    print()
    print(f"{'=' * 78}")
    print(f" Total median time: {total_time:.3f}s  ({len(QUERIES)} queries)")
    print(f"{'=' * 78}")

    # Dump machine-readable summary for diff tooling
    summary_file = os.environ.get("BENCH_OUTPUT")
    if summary_file:
        rows = {}
        for idx, (name, desc, body) in enumerate(QUERIES, 1):
            timings = []
            hits = 0
            for _ in range(RUNS):
                try:
                    h, t = run_query(body)
                    hits = h
                    timings.append(t)
                except Exception:
                    break
            if timings:
                rows[name] = {
                    "hits": hits,
                    "median_s": round(statistics.median(timings), 4),
                }
        with open(summary_file, "w") as f:
            json.dump(rows, f, indent=2)
        print(f"\nJSON summary written to {summary_file}")


if __name__ == "__main__":
    main()
