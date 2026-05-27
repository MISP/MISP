# ECharts + world map — vendoring notes

Dashboard v2 charts use Apache ECharts (DD-02) with a tree-shaken
bundle pulling in only the chart types, components, and renderer the
in-tree widgets actually need. We also vendor a low-resolution world
GeoJSON for the OrganisationMap widget and similar geo-typed widgets.

## Files in this directory

| File | Origin | Size (raw / gzipped) |
|---|---|---|
| `echarts.bundle.mjs` | Built locally with esbuild from `echarts@6.0.0`. ESM, minified. Includes BarChart, LineChart, MapChart, PieChart, GraphChart + supporting components + Canvas renderer. (PieChart added for the DiskUsageMonitorWidget donut, DD-29; GraphChart added for the MispAdminSyncTestWidget network diagram, DD-33 — a `type:'graph'` series renders nothing if GraphChart isn't `use()`'d. Same tree-shaking gotcha as PieChart.) | 702 KB / 239 KB |
| `echarts.bundle.LEGAL.txt` | esbuild-extracted attribution comments from ECharts source. Required to ship alongside. | 1 KB / — |
| `LICENSE.echarts` | The ECharts package's upstream `LICENSE` file (Apache 2.0, with NOTICE-style attributions to upstream contributors). Required by the licence. | 12 KB / — |
| `world-110m.geojson` | World countries GeoJSON at 1:110,000,000 resolution (177 country features), converted from TopoJSON in `world-atlas@2.0.2` via `topojson-client.feature()`, then **antimeridian-split** so polygons spanning the date line (Russia, Fiji, Antarctica…) render correctly under ECharts. | 437 KB / 146 KB |
| `LICENSE.world-atlas` | The world-atlas package's upstream LICENSE file (ISC, by Mike Bostock + Natural Earth public-domain data). | 1 KB / — |
| `d3-geo.bundle.mjs` | Built locally with esbuild from `d3-geo@3.1.1` + `d3-geo-projection@4.0.0`. Exports `geoNaturalEarth1` (d3-geo core), `geoRobinson` and `geoCylindricalEqualArea` (d3-geo-projection) for the WorldMap projection option (DD-15, DD-16). ESM, minified. | 17.4 KB / 7.4 KB |
| `LICENSE.d3-geo`, `LICENSE.d3-geo-projection` | Upstream LICENSE files (ISC, Mike Bostock). The esbuild `--legal-comments=external` sidecar was empty (no inline notices survive minification), so these LICENSE files are the attribution. | 2 KB / — |
| `VENDORING.md` | This file. | — |

**Combined wire weight for a dashboard with a geo widget:**
JS + GeoJSON ≈ 1 MB raw / ≈ 360 KB gzipped on first load.
JS only (no geo widget): 216 KB gzipped — significantly lighter if a
deployment doesn't ship `OrganisationMapWidget` or similar map types.

## Reproducing the bundle

```bash
mkdir -p /tmp/echarts-bundle && cd /tmp/echarts-bundle
npm init -y > /dev/null
npm install --silent --no-audit --no-fund echarts@6.0.0 esbuild@0.24.0

cat > entry.mjs <<'EOF'
import * as echarts from 'echarts/core';
import { BarChart, LineChart, MapChart, PieChart, GraphChart } from 'echarts/charts';
import {
  GridComponent, TooltipComponent, LegendComponent, TitleComponent,
  DataZoomComponent, GeoComponent, VisualMapComponent, DatasetComponent,
} from 'echarts/components';
import { CanvasRenderer } from 'echarts/renderers';
echarts.use([
  BarChart, LineChart, MapChart, PieChart, GraphChart,
  GridComponent, TooltipComponent, LegendComponent, TitleComponent,
  DataZoomComponent, GeoComponent, VisualMapComponent, DatasetComponent,
  CanvasRenderer,
]);
export default echarts;
export { echarts };
EOF

./node_modules/.bin/esbuild entry.mjs \
  --bundle --format=esm --target=es2022 --minify \
  --legal-comments=external \
  --outfile=echarts.bundle.mjs

cp echarts.bundle.mjs echarts.bundle.mjs.LEGAL.txt \
   /var/www/MISP7/app/webroot/js/dashboard/charts/vendor/
cp node_modules/echarts/LICENSE \
   /var/www/MISP7/app/webroot/js/dashboard/charts/vendor/LICENSE.echarts
```

## Reproducing the world GeoJSON

`world-atlas@2.0.2`'s TopoJSON encodes Russia, Fiji, and Antarctica
with ring segments going directly from ~+180° to ~-180° (a single
polygon spanning the date line). ECharts' geo renderer doesn't
antimeridian-split, so it draws those segments as straight horizontal
lines across the entire map ("grey bands" artefact). The build below
adds a **post-pass that splits any antimeridian-crossing polygon**
using `polygon-clipping`'s boolean intersection against the eastern
and western [-180, 180] tiles.

```bash
mkdir -p /tmp/world-atlas && cd /tmp/world-atlas
npm init -y > /dev/null
npm install --silent --no-audit --no-fund \
  world-atlas@2.0.2 topojson-client@3 polygon-clipping@0.15

cat > convert.mjs <<'EOF'
import * as topojson from 'topojson-client';
import polygonClipping from 'polygon-clipping';
import { readFileSync, writeFileSync } from 'fs';

// Walk every ring and "unwrap" longitudes into a continuous space
// (tracking +360 / -360 jumps). A continuous ring whose bbox spans
// >360° has crossed the date line; clip it against the [-180,180]
// tiles it overlaps and translate each tile back into [-180,180].

function unwrapRing(ring) {
  const out = [[ring[0][0], ring[0][1]]];
  let shift = 0;
  for (let i = 1; i < ring.length; i++) {
    const dlon = ring[i][0] - ring[i - 1][0];
    if (dlon > 180)       shift -= 360;
    else if (dlon < -180) shift += 360;
    out.push([ring[i][0] + shift, ring[i][1]]);
  }
  return out;
}
function bbox(ring) {
  let minLon = Infinity, maxLon = -Infinity;
  for (const p of ring) {
    if (p[0] < minLon) minLon = p[0];
    if (p[0] > maxLon) maxLon = p[0];
  }
  return [minLon, maxLon];
}
function clipBand(rings, lo, hi, shift) {
  const subject = [rings.map((r) => r.slice())];
  const band = [[
    [lo, -90], [hi, -90], [hi, 90], [lo, 90], [lo, -90],
  ]];
  return polygonClipping.intersection(subject, band).map((poly) =>
    poly.map((ring) => ring.map(([lon, lat]) => [lon + shift, lat])),
  );
}
function splitAntimeridian(geometry) {
  if (!geometry) return geometry;
  const polys = geometry.type === 'Polygon'
    ? [geometry.coordinates]
    : geometry.coordinates;
  const fixed = [];
  for (const poly of polys) {
    const outer = unwrapRing(poly[0]);
    const [minLon, maxLon] = bbox(outer);
    if (maxLon - minLon < 360 && maxLon <= 180 && minLon >= -180) {
      fixed.push(poly);
      continue;
    }
    const all = poly.map(unwrapRing);
    const tiles = new Set();
    for (const p of all[0]) tiles.add(Math.floor((p[0] + 180) / 360));
    for (const k of tiles) {
      for (const cp of clipBand(all, k * 360 - 180, k * 360 + 180, -k * 360)) {
        fixed.push(cp);
      }
    }
  }
  return { type: 'MultiPolygon', coordinates: fixed };
}

const topo = JSON.parse(readFileSync('node_modules/world-atlas/countries-110m.json', 'utf8'));
const geo = topojson.feature(topo, topo.objects.countries);
for (const feat of geo.features) feat.geometry = splitAntimeridian(feat.geometry);
writeFileSync('world-110m.geojson', JSON.stringify(geo));
EOF

node convert.mjs
cp world-110m.geojson \
   /var/www/MISP7/app/webroot/js/dashboard/charts/vendor/
cp node_modules/world-atlas/LICENSE.md \
   /var/www/MISP7/app/webroot/js/dashboard/charts/vendor/LICENSE.world-atlas
```

`polygon-clipping@0.15` is **MIT-licensed** (Mike Bostock's algorithm,
Adam Krebs's implementation) — GPL-compatible per FSF, AGPL-compatible
in the same direction as DD-07's other deps. It's a build-time
dependency only; nothing from the package lands in `webroot/`.

## Reproducing the d3-geo projection bundle (DD-15, DD-16)

Provides `geoNaturalEarth1` + `geoRobinson` + `geoCylindricalEqualArea`
for the WorldMap `projection` option. d3-geo core has Natural Earth;
Robinson and the cylindrical-equal-area family live in
d3-geo-projection. `geoCylindricalEqualArea().parallel(45)` is the
Gall-Peters projection (DD-16). All ISC (Mike Bostock).

```bash
mkdir -p /tmp/d3geo-bundle && cd /tmp/d3geo-bundle
npm init -y > /dev/null
npm install --silent --no-audit --no-fund \
  d3-geo@3 d3-geo-projection@4 esbuild@0.24.0

cat > entry.mjs <<'EOF'
export { geoNaturalEarth1 } from 'd3-geo';
export { geoRobinson, geoCylindricalEqualArea } from 'd3-geo-projection';
EOF

./node_modules/.bin/esbuild entry.mjs \
  --bundle --format=esm --target=es2022 --minify \
  --legal-comments=external \
  --outfile=d3-geo.bundle.mjs

cp d3-geo.bundle.mjs \
   /var/www/MISP7/app/webroot/js/dashboard/charts/vendor/
cp node_modules/d3-geo/LICENSE \
   /var/www/MISP7/app/webroot/js/dashboard/charts/vendor/LICENSE.d3-geo
cp node_modules/d3-geo-projection/LICENSE \
   /var/www/MISP7/app/webroot/js/dashboard/charts/vendor/LICENSE.d3-geo-projection
# The .LEGAL.txt sidecar is empty (no inline notices survive minify) —
# the two LICENSE files above are the required attribution.
```

ECharts integration (in `charts.module.mjs`): a d3 projection object is
`p([lng,lat]) → [x,y]` with `p.invert`; wrap as
`{ project: p, unproject: p.invert }` for `series.projection`. d3 emits
north-up in y-down space, so no sign handling is needed (contrast the
hand-rolled Mercator). Always re-check round-trip **and** north-up when
adding a projection — the inverse is iterative for these two.

## Usage from dashboard v2

```js
import echarts from '/js/dashboard/charts/vendor/echarts.bundle.mjs';

// For non-geo charts:
const chart = echarts.init(el);
chart.setOption({
  xAxis: { type: 'category', data: [...] },
  yAxis: { type: 'value' },
  series: [{ type: 'bar', data: [...] }],
});

// For geo charts:
const worldGeo = await fetch('/js/dashboard/charts/vendor/world-110m.geojson').then(r => r.json());
echarts.registerMap('world', worldGeo);
const map = echarts.init(el);
map.setOption({
  series: [{ type: 'map', map: 'world', data: [{ name: 'United States of America', value: 42 }, ...] }],
  visualMap: { min: 0, max: 100, calculable: true },
});
```

The `name` field in geo data must match the GeoJSON `properties.name` —
the world-atlas dataset uses Natural Earth's English country names
(e.g. `"United States of America"`, not `"United States"`).

## Bundled features

The current bundle includes:

- **Charts:** Bar, Line, Map (geo)
- **Components:** Grid (cartesian axes), Tooltip, Legend, Title,
  DataZoom (time scrubbing), Geo, VisualMap (choropleth coloring),
  Dataset (multi-series source)
- **Renderer:** Canvas

Adding more chart types later (Pie, Heatmap, Treemap, Sunburst,
Sankey) means: add to `entry.mjs`, rebuild, expect bundle-size growth.
A rough rule of thumb for tree-shaken ECharts: each additional simple
chart type ≈ 5–15 KB gzipped; map / heatmap / sankey ≈ 20–40 KB
gzipped each.

## Trade-offs to revisit later

- **Geo support is the heavy item.** Roughly 60-70 KB gzipped of the
  216 KB ECharts bundle is geo machinery (MapChart + GeoComponent +
  VisualMapComponent + label-layout helpers). If a deployment ships
  no geo widget, splitting the bundle into "core" + "geo" lazy-loaded
  pieces would save first-paint weight. Not worth the complexity in
  Phase 0–2; revisit if dashboard load times become an issue.
- **High-res world map.** `countries-110m` is small but the country
  shapes look chunky at large zoom. If we end up needing finer
  resolution, `world-atlas`'s `countries-50m` (756 KB raw) is the
  next step up.
- **Country naming.** The Natural Earth naming convention may not
  match every internal MISP use of country names (e.g. organisation
  records). A small mapping table (likely in `WidgetToolkit.php`,
  alongside the existing country-code table) may be needed when the
  OrganisationMap widget is ported in Phase 5.5.
