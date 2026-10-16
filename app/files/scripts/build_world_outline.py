#!/usr/bin/env python3
"""
build_world_outline.py — the Value Intelligence page's map thumbnail.

Generates the SVG world outline the Value Intelligence page's geolocation
renderer draws its points on, from the same vendored
`world-110m.geojson` the dashboard's map widgets use. The output is a
CakePHP element holding one `<symbol>`:

    app/View/Themed/Overmind/Elements/Values/Renderers/world_outline.ctp

**Why a baked path rather than the dashboard's renderer.** The
dashboard draws maps with ECharts (`charts.module.mjs`, kind `geo`),
which costs ~740 KB of bundle plus the 437 KB GeoJSON before a single
country appears. The geolocation widget's thumbnail is ~180x88 inside
a strip whose whole argument is that it paints at the speed of a
database read, so it gets the outline as markup: same source data,
same projection, no request and no script. The pane-sized rendering
uses the same symbol at a larger size.

Projection is equirectangular, which is the projection a rectangle
already is: x = longitude + 180, y = 90 - latitude. Antarctica is
dropped rather than drawn and clipped — it is a third of the height of
a world map and none of the answer to *where is this address*, so its
vertices are not worth the bytes. The templates that `<use>` the
symbol crop to 84N..58S in their own viewBox.

Three reductions, all about the size of the string this bakes into a
template: each ring is simplified with Douglas-Peucker at TOLERANCE
degrees, coordinates are rounded to DECIMALS, and a ring whose
bounding box is under MIN_SPAN degrees on both sides is dropped — at
thumbnail scale such a ring is a sub-pixel speck. At the defaults the
outline is ~39 KB of path data (~10 KB gzipped) for 258 rings.

Run from the repo root:

    python3 app/files/scripts/build_world_outline.py

No third-party dependency. Run again after every world-110m.geojson
re-vendor.
"""

import json
import os
import sys

# Douglas-Peucker tolerance in degrees. 0.4 keeps every coastline
# recognisable at 180px wide while dropping ~2/3 of the vertices.
TOLERANCE = 0.4

# Coordinate precision in decimal degrees. One decimal is ~11 km,
# which is a third of a pixel at the pane-sized rendering.
DECIMALS = 1

# Rings whose bounding box is under this many degrees on BOTH sides
# are dropped as sub-pixel specks.
MIN_SPAN = 1.2

# The symbol spans the whole world in raw projected units, so a point
# drawn at (lon + 180, 90 - lat) lands where it belongs with no offset
# to reason about. Cropping to 84N..58S - which keeps Cape Horn
# (-55.9) and the north of Greenland, and drops the Antarctic - is the
# job of the viewBox on whichever <svg> does the <use>.

VIEWBOX = '0 0 360 180'

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
SRC = os.path.join(ROOT, 'webroot', 'js', 'dashboard', 'charts',
                   'vendor', 'world-110m.geojson')
DST = os.path.join(ROOT, 'View', 'Themed', 'Overmind', 'Elements',
                   'Values', 'Renderers', 'world_outline.ctp')


def perpendicular(point, start, end):
    """Distance from `point` to the segment `start`-`end`, in degrees."""
    dx = end[0] - start[0]
    dy = end[1] - start[1]
    if dx == 0 and dy == 0:
        return ((point[0] - start[0]) ** 2
                + (point[1] - start[1]) ** 2) ** 0.5
    t = ((point[0] - start[0]) * dx + (point[1] - start[1]) * dy) \
        / (dx * dx + dy * dy)
    t = max(0.0, min(1.0, t))
    return ((point[0] - (start[0] + t * dx)) ** 2
            + (point[1] - (start[1] + t * dy)) ** 2) ** 0.5


def simplify(points, tolerance):
    """Douglas-Peucker, iterative so a long coastline cannot recurse
    past Python's stack limit."""
    if len(points) < 3:
        return points
    keep = [False] * len(points)
    keep[0] = keep[-1] = True
    stack = [(0, len(points) - 1)]
    while stack:
        low, high = stack.pop()
        furthest = -1
        best = tolerance
        for i in range(low + 1, high):
            distance = perpendicular(points[i], points[low], points[high])
            if distance > best:
                best = distance
                furthest = i
        if furthest != -1:
            keep[furthest] = True
            stack.append((low, furthest))
            stack.append((furthest, high))
    return [p for p, k in zip(points, keep) if k]


def round_off(value):
    rounded = round(value, DECIMALS)
    # -0.0 serialises as "-0", which is two characters for nothing.
    return 0.0 if rounded == 0 else rounded


def number(value):
    """Shortest faithful spelling: `12` rather than `12.0`."""
    if value == int(value):
        return str(int(value))
    return ('%.*f' % (DECIMALS, value)).rstrip('0').rstrip('.')


def ring_to_path(coordinates):
    """One closed ring as an SVG subpath, or None if it is too small to
    be worth drawing."""
    longitudes = [c[0] for c in coordinates]
    latitudes = [c[1] for c in coordinates]
    if (max(longitudes) - min(longitudes) < MIN_SPAN
            and max(latitudes) - min(latitudes) < MIN_SPAN):
        return None
    points = []
    previous = None
    for longitude, latitude in simplify(coordinates, TOLERANCE):
        point = (round_off(longitude + 180), round_off(90 - latitude))
        if point == previous:
            continue        # collapsed by the rounding
        points.append(point)
        previous = point
    if len(points) < 4:
        return None
    out = ['M%s %s' % (number(points[0][0]), number(points[0][1]))]
    for x, y in points[1:]:
        out.append('L%s %s' % (number(x), number(y)))
    return ''.join(out) + 'Z'


def rings_of(geometry):
    if not geometry:
        return
    if geometry['type'] == 'Polygon':
        for ring in geometry['coordinates']:
            yield ring
    elif geometry['type'] == 'MultiPolygon':
        for polygon in geometry['coordinates']:
            for ring in polygon:
                yield ring


TEMPLATE = '''<?php
/**
 * The world, once per page, as a `<symbol>` the map widgets `<use>`.
 *
 * GENERATED — do not edit the path by hand. Rebuild with:
 *
 *     python3 app/files/scripts/build_world_outline.py
 *
 * The geometry is the same vendored Natural Earth outline the
 * dashboard's map widgets draw (`webroot/js/dashboard/charts/vendor/
 * world-110m.geojson`); what differs is how it is delivered. The
 * dashboard hands the GeoJSON to ECharts at runtime, which is the
 * right trade for a pane-sized chart and the wrong one for a %(w)dpx
 * thumbnail in a strip that paints at the speed of a database read:
 * ~740 KB of bundle and a 437 KB fetch before a coastline appears.
 * Baked to a path it is %(kb)d KB of markup and no request at all.
 *
 * Equirectangular — x = longitude + 180, y = 90 - latitude — over the
 * whole world, so a point drawn at those coordinates lands where it
 * belongs with no offset to reason about. There is no Antarctica: it
 * is a third of the height of a world map and none of the answer to
 * *where is this address*, and the templates crop to 84N..58S in
 * their own viewBox.
 *
 * **Emitted once per render.** Both the compact widget and the pane
 * rendering ask for it, and on a page carrying both the second ask is
 * a no-op — a `<use>` needs one definition, not one each.
 */
if (!empty($this->viewVars['vpWorldOutlineDrawn'])) {
    return;
}
$this->set('vpWorldOutlineDrawn', true);
?>
<svg class="vp-world-def" aria-hidden="true" focusable="false"><symbol
    id="vp-world" viewBox="%(viewbox)s"><path class="vp-world-land"
    vector-effect="non-scaling-stroke" d="%(d)s"/></symbol></svg>
'''


def main():
    if not os.path.exists(SRC):
        sys.exit('missing %s — re-vendor the world GeoJSON first' % SRC)
    with open(SRC, 'r') as handle:
        geo = json.load(handle)

    subpaths = []
    kept = 0
    dropped = 0
    for feature in geo.get('features', []):
        name = (feature.get('properties') or {}).get('name') or ''
        if name == 'Antarctica':
            continue
        for ring in rings_of(feature.get('geometry')):
            subpath = ring_to_path(ring)
            if subpath is None:
                dropped += 1
                continue
            subpaths.append(subpath)
            kept += 1

    d = ''.join(subpaths)
    with open(DST, 'w') as handle:
        handle.write(TEMPLATE % {
            'd': d,
            'viewbox': VIEWBOX,
            'kb': round(len(d) / 1024.0),
            'w': 180,
        })
    print('%s rings kept, %s dropped, %d bytes of path -> %s'
          % (kept, dropped, len(d), DST))


if __name__ == '__main__':
    main()
