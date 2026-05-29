# ECharts + world map — vendoring notes

Dashboard v2 charts use Apache ECharts (DD-02) with a tree-shaken
bundle pulling in only the chart types, components, and renderer the
in-tree widgets actually need. We also vendor a low-resolution world
GeoJSON for the OrganisationMap widget and similar geo-typed widgets.

## Files in this directory

| File | Origin | Size (raw / gzipped) |
|---|---|---|
| `echarts.bundle.mjs` | Built locally with esbuild from `echarts@6.0.0`. ESM, minified. Includes BarChart, LineChart, MapChart, PieChart, GraphChart, LinesChart + supporting components + Canvas renderer. (PieChart added for the DiskUsageMonitorWidget donut, DD-29; GraphChart added for the MispAdminSyncTestWidget network diagram, DD-33 — a `type:'graph'` series renders nothing if GraphChart isn't `use()`'d. Same tree-shaking gotcha as PieChart. LinesChart + EffectScatterChart added for the AttackFlowMapWidget pew-pew arcs, DD-45 Phase C — `type:'lines'` / `type:'effectScatter'` render nothing if those series aren't `use()`'d. LinesChart draws the arcs; EffectScatterChart draws the pulsing destination glow at victim centroids. +20 KB raw / +5 KB gzipped over the DD-33 bundle.) | 721 KB / 245 KB |
| `echarts.bundle.LEGAL.txt` | esbuild-extracted attribution comments from ECharts source. Required to ship alongside. | 1 KB / — |
| `LICENSE.echarts` | The ECharts package's upstream `LICENSE` file (Apache 2.0, with NOTICE-style attributions to upstream contributors). Required by the licence. | 12 KB / — |
| `world-110m.geojson` | World countries GeoJSON at 1:110,000,000 resolution (177 country features), converted from TopoJSON in `world-atlas@2.0.2` via `topojson-client.feature()`, then **antimeridian-split** so polygons spanning the date line (Russia, Fiji, Antarctica…) render correctly under ECharts. | 437 KB / 146 KB |
| `LICENSE.world-atlas` | The world-atlas package's upstream LICENSE file (ISC, by Mike Bostock + Natural Earth public-domain data). | 1 KB / — |
| `d3-geo.bundle.mjs` | Built locally with esbuild from `d3-geo@3.1.1` + `d3-geo-projection@4.0.0`. Exports `geoNaturalEarth1` + `geoOrthographic` (d3-geo core), `geoRobinson` and `geoCylindricalEqualArea` (d3-geo-projection) for the WorldMap projection option (DD-15, DD-16) and the AttackFlowMap "globe" mode (DD-46). `geoOrthographic` powers the pew-pew 2.5D globe (DD-46, superseding DD-45's echarts-gl plan) — added to the bundle for +0.1 KB gzipped since it shares d3-geo core machinery. ESM, minified. | 18.1 KB / 7.5 KB |
| `LICENSE.d3-geo`, `LICENSE.d3-geo-projection` | Upstream LICENSE files (ISC, Mike Bostock). The esbuild `--legal-comments=external` sidecar was empty (no inline notices survive minification), so these LICENSE files are the attribution. | 2 KB / — |
| `iso-centroids.json` | Per-country polygon centroids keyed by ISO alpha-2 — `{"ISO_A2": [lon, lat], ...}`. Built from `world-110m.geojson` by `app/files/scripts/build_iso_centroids.py` (DD-45 Phase B1). Consumed by `AttackFlowMapWidget` (DD-45) to resolve attacker/victim country codes to arc endpoints. Run the script again any time `world-110m.geojson` is re-vendored. | 4 KB / 2 KB |
| `globe.bundle.mjs` | Built locally with esbuild from `globe.gl@2.46.1` (Three.js — `three-globe@2.45.2` / `three@0.184.0`). ESM, minified, tree-shaken. The **lazy** vendor bundle for the `AttackFlowMapWidget` "Globe (3D)" `webgl-globe` mode (DD-47) — a real WebGL textured/lit globe. **NOT** part of `echarts.bundle.mjs`; dynamic-`import()`ed by `charts.module.mjs` only on the first `webgl-globe` render, so the ~95% of deployments on the 2D / orthographic modes never fetch it. globe.gl owns its own WebGL canvas (it is not an ECharts `setOption` builder; cf. the d3-geo orthographic mode which is). | 1.76 MB / 508 KB |
| `globe.bundle.LEGAL.txt` | esbuild-extracted inline `@license` banners that survive minification (the Three.js MIT banner + a regenerator-runtime note). | 1 KB / — |
| `globe.bundle.LICENSES.txt` | Consolidated third-party notice: the **full LICENSE text of all 42 bundled packages** (globe.gl + three + three-globe + the transitive d3-\* / h3-js / @turf/\* / tinycolor2 / preact / lodash-es / … tree). Every one is **MIT / ISC / Apache-2.0 / Unlicense** — permissive, no copyleft, AGPL-compatible (DD-07 lineage holds; no new copyleft review). One consolidated NOTICE file rather than 42 `LICENSE.*` sidecars, to keep the dir legible — the small bundles above keep their per-lib `LICENSE.*`. | 62 KB / — |
| `earth-night-2k.jpg` | **"Night" skin** (default) for the `webgl-globe` mode (DD-47 G2). Earth-at-night "city lights" — **NASA Visible Earth *Black Marble***, **public domain** (a US-Government work; not copyrightable, no licence sidecar needed). Sourced from the `earth-night.jpg` example in the MIT `three-globe` package (native 4096×2048), downscaled to 2048×1024 at JPEG q85. Night surface chosen deliberately: arcs + rings pop against the dark field, it pre-aligns with the incoming dark MISP theme, and it leans into the playful Norse-attack-map riff the widget *is* (DD-48). | 205 KB / — |
| `earth-day-2k.jpg` | **"Day" skin** for the `webgl-globe` mode (DD-49). NASA **Blue Marble** daytime earth (blue oceans, green/tan land, clouds) — public domain. From `three-globe`'s `earth-blue-marble.jpg` example (native 4096×2048), downscaled to 2048×1024 at JPEG q80. The brighter alternate to the (dark) night skin. | 279 KB / — |
| `earth-dark-2k.jpg` | **"Dark" skin** for the `webgl-globe` mode (DD-49). Minimal near-black globe with dark-grey landmasses — public domain. From `three-globe`'s `earth-dark.jpg` example (native 2048×1024), re-encoded q85. A moody, low-detail surface where the arcs dominate. | 81 KB / — |
| `VENDORING.md` | This file. | — |

**Combined wire weight for a dashboard with a geo widget:**
JS + GeoJSON ≈ 1 MB raw / ≈ 360 KB gzipped on first load.
JS only (no geo widget): 216 KB gzipped — significantly lighter if a
deployment doesn't ship `OrganisationMapWidget` or similar map types.

`globe.bundle.mjs` (508 KB gzipped) is **excluded from those figures**:
it is lazy-loaded only when an `AttackFlowMapWidget` is set to the opt-in
`webgl-globe` mode, and browser-cached thereafter. The default `2d` and
the lightweight d3-geo `3d-globe` modes never fetch it (DD-46, DD-47).

## Reproducing the bundle

```bash
mkdir -p /tmp/echarts-bundle && cd /tmp/echarts-bundle
npm init -y > /dev/null
npm install --silent --no-audit --no-fund echarts@6.0.0 esbuild@0.24.0

cat > entry.mjs <<'EOF'
import * as echarts from 'echarts/core';
import { BarChart, LineChart, MapChart, PieChart, GraphChart, LinesChart, EffectScatterChart } from 'echarts/charts';
import {
  GridComponent, TooltipComponent, LegendComponent, TitleComponent,
  DataZoomComponent, GeoComponent, VisualMapComponent, DatasetComponent,
} from 'echarts/components';
import { CanvasRenderer } from 'echarts/renderers';
echarts.use([
  BarChart, LineChart, MapChart, PieChart, GraphChart, LinesChart, EffectScatterChart,
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
export { geoNaturalEarth1, geoOrthographic } from 'd3-geo';
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

## Reproducing the globe.gl 3D bundle (DD-47)

The lazy WebGL globe (`webgl-globe` mode of `AttackFlowMapWidget`). This
is a **separate** bundle from `echarts.bundle.mjs` — globe.gl owns its
own Three.js WebGL canvas, so it cannot share ECharts' machinery, and it
is genuinely heavy (Three core + three-globe + wrapper). Keeping it out
of the main bundle and dynamic-`import()`ing it on first `webgl-globe`
render means deployments that never use the 3D mode pay nothing.

DD-46 deliberately *removed* lazy-bundle machinery for the orthographic
disc (d3-geo is already vendored, +0.1 KB); DD-47 re-introduces it here
because the weight (508 KB gz) and the genuinely-different output (true
textured/lit 3D) justify it. echarts-gl was rejected in DD-46 (2022,
echarts@6-incompatible, 247 KB gz); globe.gl is MIT and actively
maintained (2.46.1 published 2026-05-16).

```bash
mkdir -p /tmp/globegl-bundle && cd /tmp/globegl-bundle
npm init -y > /dev/null
npm install --silent --no-audit --no-fund \
  globe.gl@2.46.1 three@0.184.0 esbuild@0.24.0
# globe.gl pulls three-globe@2.45.2 + the d3-*/h3-js/@turf/* tree as deps.

cat > entry.mjs <<'EOF'
import Globe from 'globe.gl';
export default Globe;
export { Globe };
EOF

./node_modules/.bin/esbuild entry.mjs \
  --bundle --format=esm --target=es2022 --minify \
  --legal-comments=external \
  --outfile=globe.bundle.mjs

cp globe.bundle.mjs \
   /var/www/MISP7/app/webroot/js/dashboard/charts/vendor/
# esbuild names the sidecar <outfile>.LEGAL.txt; rename to match the
# echarts.bundle.LEGAL.txt convention in this dir:
cp globe.bundle.mjs.LEGAL.txt \
   /var/www/MISP7/app/webroot/js/dashboard/charts/vendor/globe.bundle.LEGAL.txt
```

The `.LEGAL.txt` sidecar only captures the few inline `@license` banners
that survive minification (Three.js, regenerator-runtime). MIT/ISC still
require each package's copyright + permission notice to ship, so the
consolidated `globe.bundle.LICENSES.txt` is generated from every bundled
package's own LICENSE file. To regenerate it, rebuild with a metafile and
walk the inputs:

```bash
cd /tmp/globegl-bundle
./node_modules/.bin/esbuild entry.mjs --bundle --format=esm \
  --target=es2022 --minify --legal-comments=external \
  --metafile=meta.json --outfile=/dev/null

node -e '
const fs=require("fs"), path=require("path");
const m=require("./meta.json"); const pkgs=new Set();
for(const f of Object.keys(m.inputs)){
  const mm=f.match(/node_modules\/((@[^/]+\/[^/]+)|([^/]+))\//);
  if(mm) pkgs.add(mm[1]);
}
function lic(d){ let n; try{n=fs.readdirSync(d);}catch(e){return null;}
  const c=n.filter(x=>/^licen[sc]e/i.test(x)||/^copying/i.test(x))
           .sort((a,b)=>a.length-b.length);
  for(const f of c){const p=path.join(d,f);
    try{if(fs.statSync(p).isFile())return fs.readFileSync(p,"utf8").trim();}catch(e){}}
  return null; }
let out="Third-party license notices for globe.bundle.mjs\n"+"=".repeat(70)+"\n\n";
for(const p of [...pkgs].sort()){
  const pj=require(`./node_modules/${p}/package.json`);
  out+="-".repeat(70)+`\n${p}@${pj.version} — ${pj.license}\n`+"-".repeat(70)+"\n";
  out+=(lic(`./node_modules/${p}`)||`[SPDX: ${pj.license}]`)+"\n\n";
}
fs.writeFileSync("globe.bundle.LICENSES.txt", out);
'
cp globe.bundle.LICENSES.txt \
   /var/www/MISP7/app/webroot/js/dashboard/charts/vendor/
```

All 42 bundled packages are permissive (MIT / ISC / Apache-2.0 /
Unlicense). If a future `globe.gl`/`three` bump pulls a copyleft
(GPL/LGPL/AGPL) transitive dep, the AGPL-compatibility assumption breaks
— re-run the license walk above and review before shipping.

The earth textures (the `webgl-globe` skins, DD-47 G2 + DD-49) are NASA
public-domain images that ship in `three-globe`'s example dir,
downscaled to 2048×1024:

```bash
T=/tmp/globegl-bundle/node_modules/three-globe/example/img
V=/var/www/MISP7/app/webroot/js/dashboard/charts/vendor
convert $T/earth-night.jpg       -resize 2048x1024 -quality 85 $V/earth-night-2k.jpg  # night (default)
convert $T/earth-blue-marble.jpg -resize 2048x1024 -quality 80 $V/earth-day-2k.jpg    # day (Blue Marble)
convert $T/earth-dark.jpg        -resize 2048x1024 -quality 85 $V/earth-dark-2k.jpg   # dark (minimal)
```

NASA imagery is public domain (a US-Government work), so no licence
sidecar is required for the images — but keep this provenance note. To
add another skin: vendor a texture here, add it to the `GLOBE_TEXTURES`
map in `charts.module.mjs` AND the `skin` enum + `resolveSkin()`
whitelist in `PewPewMapWidget.php` (both must list it, or a stored value
silently degrades to `night`).

## Reproducing `iso-centroids.json` (DD-45 Phase B1)

Per-country centroids for the PewPewMap render kind (DD-45). Computed
from the vendored `world-110m.geojson` so the centroid landmarks are
consistent with the same simplified country polygons the WorldMap
already draws.

```bash
pip install pycountry  # build-time only; not vendored
python3 app/files/scripts/build_iso_centroids.py
```

Implementation notes:

- **Centroid math is Cartesian shoelace on `[lon, lat]` pairs**,
  area-weighted across MultiPolygon parts. Outer rings only (holes
  ignored — South Africa / Lesotho-style enclaves at this scale shift
  the centroid by ~10-30 km, invisible at arc-endpoint resolution).
- **Antimeridian unwrap.** Features with polygons on both sides of
  ±180° (Fiji, Russia's Chukotka, US Aleutians) get their *western*
  polygons shifted +360° into a continuous longitude space before the
  centroid is computed; the result is wrapped back into [-180, 180].
  Without this, Fiji's two half-polygons would average to a centroid
  in the Atlantic.
- **Name → ISO resolution** via `pycountry`: exact `lookup()` first
  (catches Russia → Russian Federation, Brunei → Brunei Darussalam),
  then `search_fuzzy()` for the remainder. A small `NAME_OVERRIDES`
  table in the script handles the dozen-ish Natural Earth
  abbreviations that don't match (`W. Sahara` → EH, `Bosnia and Herz.`
  → BA, `Dem. Rep. Congo` → CD, etc.). De-facto entities without ISO
  codes (Somaliland, N. Cyprus) map to `None` and are silently
  dropped.
- **Output:** sorted-key JSON, ~4 KB on disk. Format
  `{"ISO_A2": [lon, lat], ...}`. The widget reads it server-side via
  `json_decode(file_get_contents(...))`; it's not exposed to the
  browser (the rendered `flows[]` payload carries pre-resolved
  centroids).

Run the script again whenever `world-110m.geojson` is re-vendored, so
the centroids stay aligned with the polygons they correspond to. The
script + output are checked in; the script is not invoked at runtime.

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

- **Charts:** Bar, Line, Map (geo), Pie, Graph, Lines, EffectScatter
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
