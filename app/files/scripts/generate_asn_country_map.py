#!/usr/bin/env python3
"""
generate_asn_country_map.py — derive an ASN -> dominant-country lookup
from the MISP-managed GeoOpen-Country-ASN mmdb (DD-12, dashboard v2).

The GeoOpen-Country-ASN mmdb is IP-prefix-keyed: each prefix carries a
country iso_code AND an autonomous system number. A single ASN spans
prefixes in many countries, so "the country of an ASN" is not a value
the DB holds directly. This script approximates it as the country in
which the ASN announces the most IPv4 address space ("dominant
announced space") — the operationally-relevant notion for threat
infrastructure (where an AS actually operates space, not where it is
registered).

IPv6 prefixes are intentionally excluded from the dominance vote: their
address counts (2^(128-prefixlen)) dwarf IPv4 and would swamp the
tally. ASNs that announce only IPv6 therefore do not appear in the map
(rare). Records without a real 2-letter ISO or with the "Not routed"
ASN 0 / "None" placeholder are skipped.

Output: a JSON object {"<asn>": "<ISO alpha-2>", ...} written next to
the mmdb. Re-run whenever the mmdb is updated. Consumed by
AttributeGeoMapWidget's 'asn' source (dashboard v2).

Usage: python3 generate_asn_country_map.py [<mmdb path>] [<out path>]
Requires: maxminddb (the GeoIP reader python package).
"""
import ipaddress
import json
import os
import re
import sys

import maxminddb

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB = os.path.join(HERE, '..', 'geo-open', 'GeoOpen-Country-ASN.mmdb')
DEFAULT_OUT = os.path.join(HERE, '..', 'geo-open', 'asn-country.json')

ISO_RE = re.compile(r'^[A-Z]{2}$')


def build(db_path, out_path):
    # asn -> {iso: summed IPv4 address count}
    tally = {}
    with maxminddb.open_database(db_path) as reader:
        for network, record in reader:
            if not isinstance(network, ipaddress.IPv4Network):
                continue
            country = (record or {}).get('country') or {}
            iso = country.get('iso_code')
            asn = country.get('AutonomousSystemNumber')
            if not iso or not asn or asn == '0' or not ISO_RE.match(iso):
                continue
            bucket = tally.setdefault(str(asn), {})
            bucket[iso] = bucket.get(iso, 0) + network.num_addresses
    # dominant country per ASN = the one with the most announced IPv4 space
    asn_map = {
        asn: max(counts.items(), key=lambda kv: kv[1])[0]
        for asn, counts in tally.items()
    }
    with open(out_path, 'w') as fh:
        json.dump(asn_map, fh, separators=(',', ':'), sort_keys=True)
    return len(asn_map)


def main():
    db_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_DB
    out_path = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_OUT
    count = build(db_path, out_path)
    print('Wrote %d ASN->country entries to %s' % (count, out_path))


if __name__ == '__main__':
    main()
