#!/usr/bin/env python3
"""
build_iso_centroids.py — DD-45 Phase B1.

Generates `iso-centroids.json` from `world-110m.geojson` for the
dashboard v2 PewPewMap render kind: per-country polygon centroid in
[longitude, latitude], keyed by ISO alpha-2.

The vendored `world-110m.geojson` only carries `properties.name`
(Natural Earth English names like "United States of America",
"W. Sahara", "Bosnia and Herz."). We resolve those to ISO alpha-2
via pycountry + a small override table for Natural Earth's
abbreviated / informal names. Entities that don't have an ISO code
(Somaliland, N. Cyprus) map to None and are dropped — the widget's
arc resolution silently skips ISO codes it can't centroid.

Antimeridian handling: the vendored geojson was already split at
±180° at vendor time (see vendor/VENDORING.md). For features whose
polygons sit on BOTH the deep-east and deep-west sides (Fiji,
Kiribati, Russia's Chukotka), a naive Cartesian centroid lands in
the Atlantic. We "unwrap" the western pieces (+360°) into a
continuous longitude space before the centroid calc, then wrap the
result back into [-180, 180].

Holes are intentionally ignored — for countries with enclaves
(South Africa / Lesotho), the outer-ring-only centroid is off by
~10-30 km at this scale, which is invisible at PewPewMap arc-
endpoint resolution.

Run from the repo root:

    python3 app/files/scripts/build_iso_centroids.py

Output overwrites:

    app/webroot/js/dashboard/charts/vendor/iso-centroids.json

Build-time dependency: `pycountry` (not vendored — this script is
run locally, output is committed). Run again after every world-
110m.geojson re-vendor.
"""

import json
import os
import sys

import pycountry

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))))
INPUT = os.path.join(REPO_ROOT,
    'app/webroot/js/dashboard/charts/vendor/world-110m.geojson')
OUTPUT = os.path.join(REPO_ROOT,
    'app/webroot/js/dashboard/charts/vendor/iso-centroids.json')

# Hand-coded overrides for Natural Earth's abbreviated / informal
# names that don't fuzzy-match pycountry cleanly. Values are ISO
# alpha-2; None for de-facto / non-recognised entities that should
# be dropped (no stable ISO code).
NAME_OVERRIDES = {
    'Bosnia and Herz.':           'BA',
    'Central African Rep.':       'CF',
    'Czechia':                    'CZ',
    "Côte d'Ivoire":              'CI',
    'Dem. Rep. Congo':            'CD',
    'Dominican Rep.':             'DO',
    'Eq. Guinea':                 'GQ',
    'eSwatini':                   'SZ',
    'Falkland Is.':               'FK',
    'Fr. S. Antarctic Lands':     'TF',
    'Kosovo':                     'XK',
    'Macedonia':                  'MK',
    'N. Cyprus':                  None,
    'Palestine':                  'PS',
    'S. Sudan':                   'SS',
    'Solomon Is.':                'SB',
    'Somaliland':                 None,
    'Turkey':                     'TR',
    'United States of America':   'US',
    'W. Sahara':                  'EH',
}


def polygon_centroid(ring):
    """Cartesian centroid + signed area of one polygon ring.

    Standard shoelace formula. Input ring is a list of [lon, lat]
    pairs with the last point == the first (closed ring). Returns
    ((cx, cy), |area|), or (None, 0) for degenerate rings.
    """
    cx = cy = area = 0.0
    for i in range(len(ring) - 1):
        x0, y0 = ring[i]
        x1, y1 = ring[i + 1]
        cross = x0 * y1 - x1 * y0
        area += cross
        cx += (x0 + x1) * cross
        cy += (y0 + y1) * cross
    area *= 0.5
    if area == 0:
        return None, 0
    cx /= (6 * area)
    cy /= (6 * area)
    return (cx, cy), abs(area)


def feature_spans_antimeridian(feat):
    """True if a feature has polygon vertices on BOTH sides of ±180°.

    Heuristic: vertices with lon > 90 AND vertices with lon < -90
    in the SAME feature. Catches Fiji / Kiribati / Russia, leaves
    everything else alone.
    """
    has_east = has_west = False
    polys = (feat['geometry']['coordinates']
             if feat['geometry']['type'] == 'MultiPolygon'
             else [feat['geometry']['coordinates']])
    for poly in polys:
        for lon, _ in poly[0]:
            if lon > 90:
                has_east = True
            elif lon < -90:
                has_west = True
            if has_east and has_west:
                return True
    return False


def feature_centroid(feat):
    """Area-weighted centroid of a (Multi)Polygon feature.

    Antimeridian-spanning features have their western polygons
    shifted +360° into continuous space before the per-polygon
    centroid is computed; the final result is wrapped back into
    [-180, 180].
    """
    geom = feat['geometry']
    polys = (geom['coordinates']
             if geom['type'] == 'MultiPolygon'
             else [geom['coordinates']])
    spans = feature_spans_antimeridian(feat)

    total_cx = total_cy = total_a = 0.0
    for poly in polys:
        outer = poly[0]
        if spans:
            mean_lon = sum(p[0] for p in outer) / len(outer)
            if mean_lon < 0:
                outer = [[lon + 360, lat] for lon, lat in outer]
        c, a = polygon_centroid(outer)
        if c is None:
            continue
        total_cx += c[0] * a
        total_cy += c[1] * a
        total_a += a
    if total_a == 0:
        return None
    cx = total_cx / total_a
    cy = total_cy / total_a
    if cx > 180:
        cx -= 360
    return (cx, cy)


def resolve_iso(name):
    """Resolve a Natural Earth country name to ISO alpha-2.

    Order: overrides table → pycountry exact lookup → pycountry
    fuzzy search (top hit). None if no match (entity gets dropped
    from the output). pycountry's exact `lookup()` matches a few
    formal-name variants (Russian Federation, Brunei Darussalam)
    that Natural Earth shortens; `search_fuzzy()` covers those
    without bloating the override table.
    """
    if name in NAME_OVERRIDES:
        return NAME_OVERRIDES[name]
    try:
        return pycountry.countries.lookup(name).alpha_2
    except LookupError:
        pass
    try:
        return pycountry.countries.search_fuzzy(name)[0].alpha_2
    except (LookupError, IndexError):
        return None


def main():
    with open(INPUT) as f:
        geo = json.load(f)
    out = {}
    skipped = []
    for feat in geo['features']:
        name = feat['properties'].get('name', '')
        iso = resolve_iso(name)
        if iso is None:
            skipped.append(name)
            continue
        centroid = feature_centroid(feat)
        if centroid is None:
            skipped.append(name + ' (no geometry)')
            continue
        out[iso] = [round(centroid[0], 4), round(centroid[1], 4)]
    with open(OUTPUT, 'w') as f:
        json.dump(out, f, separators=(',', ':'), sort_keys=True)
        f.write('\n')
    print('Wrote {}: {} ISO centroids'.format(OUTPUT, len(out)))
    if skipped:
        print('Skipped (no ISO mapping or no geometry): {}'.format(
            ', '.join(skipped)))


if __name__ == '__main__':
    main()
