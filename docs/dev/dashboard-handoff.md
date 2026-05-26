# Dashboard v2 — Session handoff (2026-05-26 — geo/threat map widgets round complete)

Thirteenth session. Authoritative state lives in:

- `dashboard-prd.md` — spec (binding decisions table §15, now incl. DD-15).
- `dashboard-progress.md` — task state. **Phase 5 + 5.5 closed; Phase 6
  (merge) is the only tracked phase left.** The post-5.5 "new widget
  types" section now has the geo work logged (+ open follow-ups).
- `dashboard-design-decisions.md` — DD-01..DD-15 (DD-11..15 new this
  session).

This file is the bridge: ephemeral session context. Replace as work
progresses.

## TL;DR — this session (10 signed commits, all `%G?`=U, none merged)

The user merged `develop` into `dashboards` (`795bda17c`, bringing the
new `GeoOpen-Country-ASN.mmdb`), then we built out the geo/threat map
widgets one feature at a time, with two real bugs caught along the way:

```
7248f08a0 new geo world-map widget — 4 sources (DD-11)
5915601cd new ASN source — offline-derived ASN->country map (DD-12)
603ad9c34 fix Add Widget gallery search now culls (CSS [hidden] override)
d7a3add6d chg geo threat red scale  [SUPERSEDED by DD-13]
78800c78a new threat actor origins map (galaxy-library distribution)
bed832998 fix WorldMap renders CN/RU/US — ISO->name reconcile to geojson
552d2a457 new per-widget WorldMap colour palette (DD-13)
64e4db184 new WorldMap projection option, Mercator default (DD-14)
3d8360640 fix Mercator was upside down — negate y in both project+unproject
c6b72e66d new Robinson + Natural Earth projections via vendored d3-geo (DD-15)
```

**User still does the merge — do NOT open the PR or merge.**

## Two new widgets (both reuse `WorldMap` → no new render kind / glyph)

1. **`AttributeGeoMapWidget`** (DD-11, DD-12) — geolocates *recent event
   data* to country counts. Config `sources` (default all 5):
   - `ip` — `ip-src`/`ip-dst`/`ip-src|port`/`ip-dst|port` (value1) +
     `domain|ip` (value2) → `GeoOpen-Country.mmdb` (one Reader, reused).
   - `domain_tld` — ccTLD of `domain`/`domain|ip` (value1) → the country
     galaxy's `tld`→`ISO` elements.
   - `asn` — `AS` attrs → `app/files/geo-open/asn-country.json` (derived).
   - `country_galaxy` — events tagged `misp-galaxy:country=…` →
     cluster `ISO` element.
   - `threat_actor` — events tagged `misp-galaxy:threat-actor=…` →
     cluster `country` element (already ISO).
   Per-source cap `limit` (10000), `time_window` (P30D, toolbar-reachable).
2. **`ThreatActorCountryMapWidget`** — geographic distribution of *all
   known threat actors in the galaxy library* (independent of event
   data). `COUNT(DISTINCT GalaxyCluster.uuid)` over `galaxy_elements`
   key=`country`, galaxy type=`threat-actor`. Optional top-N `limit`.

Both default `palette: danger` (red) + `projection: mercator`, both
configurable per instance.

## Key architecture facts confirmed this session (REUSE THESE)

- **WorldMap ISO→name must match the vendored geojson** (`bed832998`).
  `WorldMap.ctp` translates ISO→English name; the vendored
  `world-110m.geojson` uses Natural-Earth names that differ from
  `WidgetToolkit` for 11 countries (CN→`China`, RU→`Russia`,
  US→`United States of America`, CZ→`Czechia`, KP→`North Korea`,
  KR→`South Korea`, LA→`Laos`, MZ→`Mozambique`, SZ→`eSwatini`,
  IE→`Ireland`; **Malta has no 110m feature**). An explicit override map
  after `array_flip` fixes the reverse map; the toolkit's forward
  (name→ISO, used by `Organisation*` widgets) is untouched. **Any new
  map widget emits ISO alpha-2; codes the geojson doesn't know are
  silently dropped.**
- **No-ACL posture for the geo widgets** (DD-11). They bypass per-user
  ACL (bare `find('column')` / joins) for scalability — aggregate
  per-country counts only, **no values, no drilldown**, available to all
  users. User-accepted, citing the global Statistics endpoint precedent.
  (`ThreatActorCountryMapWidget` isn't even an "exception" — the galaxy
  library is instance-wide reference data.) **User wants an
  ACL-enforced switchable path eventually** — logged follow-up.
- **`cacheLifetime` is INERT in v2** — nothing reads it. Perf guard =
  bounded query (per-source cap + recency window) + `autoRefreshDelay
  = false`. Don't rely on `cacheLifetime`.
- **`fetchAttributes` injects `object_id = 0` unless `flatten => 1`** —
  it would silently miss object-nested IPs/domains. The geo widget uses
  bare `find('column')`, which has no such implicit filter (and no ACL).
- **Galaxy country/ISO via `galaxy_elements` SQL joins**, not JSON
  parsing: country galaxy has `ISO` + `tld` elements; threat-actor
  galaxy has `country` (ISO alpha-2). `galaxy_clusters` carries multiple
  version-rows per actor (same uuid) → **dedup by `uuid`** for counts.
- **Palette mechanism (DD-13).** Widget returns `palette` from
  `handler()`; named palettes (`accent` default / `danger` / `success` /
  `warning` / `info`) → semantic token pairs (`--misp-dash-<sem>-muted`
  low + `--misp-dash-<sem>` high), resolved in `buildGeoOption`.
  Per-widget override via a `palette` `enum` `$schema` (default `danger`
  on threat widgets). Renderer-generic; org/COVID omit it → stay blue.
  The old CSS-`[data-widget-name]` hack is **retired**.
- **Projection mechanism (DD-14, DD-15).** Widget returns `projection`;
  `buildGeoOption` defaults to `mercator` (`payload.projection ||
  'mercator'`) so **all** WorldMap widgets are Mercator now (incl.
  org/COVID, untouched). `equirectangular` = ECharts native flat grid.
  `mercator` hand-rolled — **negate y in BOTH project & unproject**
  (custom projections render in canvas y-down, NOT auto-flipped like the
  native path). `naturalEarth`/`robinson` via vendored
  `vendor/d3-geo.bundle.mjs` (d3 bakes north-up in, no sign handling;
  `wrapD3` adapter). **LESSON (cost me two wrong cuts): a round-trip
  test proves the inverse is consistent, NOT the orientation — also
  assert north-maps-above-south, or the map ships upside down.**
- **mmdb facts.** `GeoOpen-Country.mmdb` (IP→country, 11 MB) and
  `GeoOpen-Country-ASN.mmdb` (81 MB) are both **IP-prefix-keyed** — you
  *cannot* map a bare ASN→country from them, and the PHP `MaxMind\Db\
  Reader` can't enumerate. So `AS` attrs are mapped via
  `asn-country.json`, derived offline by
  `app/files/scripts/generate_asn_country_map.py` (Python `maxminddb`
  enumerates → dominant-announced-IPv4-space country; 77,846 entries).
  **Regenerate that JSON when the mmdb updates** — logged follow-up.

## Open follow-ups (in the progress tracker; none blocking)

- **Regenerate `asn-country.json` on mmdb update** — wire
  `generate_asn_country_map.py` into MISP's geo-open mmdb update job.
- **ACL-enforced switchable path** for the geo widget (user wants both
  the fast no-ACL path and an ACL-correct one, chosen on perf).
- **org/COVID maps palette + projection opt-in** — one handler line each
  if those maps should also be configurable (currently inherit
  mercator + blue).
- **Default threat maps to Robinson/Natural Earth?** Mercator is the
  default (DD-14); switching is a one-line `$schema` `default` change —
  the user's call.
- More new widget types — user may enumerate.
- **Phase 6 merge — the USER does this, not us.**

## Live test instance (unchanged, verified up this session)

- URL `http://localhost:5007/dashboards` (302 without a session).
- Admin user id 1 (`admin@admin.test`), pw `Password12345`,
  **on the Overmind theme** (no jQuery / `misp.js` — board-owned ESM
  surfaces only; see DD-10).
- Admin API key `dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC`.
- DB: `mysql -u misp -pPassword1234 misp`.

### Reusable verification recipes

```bash
KEY=dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC
# REST render — returns the BARE handler data (ISO-keyed, pre-translation):
curl -s -X POST -H "Authorization: $KEY" -H "Accept: application/json" \
  --data-urlencode "widget=<Name>Widget" --data-urlencode "config={}" \
  http://localhost:5007/dashboards/renderWidget
# HTML render — the TRANSLATED WorldMap payload (ISO->geojson name +
#   palette + projection). Needs a session cookie: see the
#   reference-misp-login-dance memory; then curl -b "$CJ" (no Accept).
# Projection math: node round-trip test + assert north-above-south
#   (NOT round-trip alone — see DD-14/15 lesson).
```

## Convention reminders

- **Commit per logical task; never `git add -A`; explicit `git add` +
  `git status --short` first; sign (`%G?`=U).** **GPG gotcha this
  session:** `git commit -S` run non-interactively times out on the
  pinentry once the agent's passphrase cache expires. Workarounds: have
  the user warm the cache (`! echo x | gpg --clearsign >/dev/null`) then
  retry, OR write the message to `/tmp/msg` and have the user run
  `! git -C /var/www/MISP7 commit -S -F /tmp/msg`. A successful commit
  warms the cache for subsequent ones.
- **New files: `chgrp www-data` before commit** (widget classes, the
  vendored bundle + LICENSE files all got this).
- **Hard-refresh after CSS/JS edits** (`?v=185` asset buster doesn't
  bump per-file). **PHP renderer/handler changes need only a reload**
  (server-side, no static-asset cache).
- **Additive-only posture:** these widgets are pure additions; the
  shared-renderer touches (`WorldMap.ctp` ISO fix, `charts.module.mjs`
  palette/projection) were bug-fixes / requested features within the
  dashboard's own code — fine, but mind the blast radius (they affect
  org/COVID maps too).
- **Record meaningful decisions as DD-NN** + a PRD §15 row. Vendoring a
  dep also updates the DD-07 licence table + `vendor/VENDORING.md`.
- **Render-kind glyph rule** (CLAUDE.md): only new `$render` values need
  a glyph — both new widgets reuse `WorldMap`, so none needed.
- User wants **rigorous pushback** and genuine forks surfaced via
  AskUserQuestion (this session: ASN feasibility, ACL posture, palette
  model, projection scope).

## Quick-start for the next session

1. Read `dashboard-prd.md` (§15 table) + `dashboard-design-decisions.md`
   (DD-11..15 are the geo/map work) + this file. Skim
   `dashboard-progress.md` Post-5.5 section for task-level detail.
2. Verify instance: `curl -s http://localhost:5007/dashboards -o /dev/null
   -w "%{http_code}\n"` → 302.
3. **No specific task is mandated** — the geo/threat-map round is
   complete and committed. The user will direct (likely another new
   widget, a tweak, one of the open follow-ups, or the merge). If
   touching the WorldMap renderer or a map widget, re-read the "Key
   architecture facts" above first — the ISO-name, palette, projection,
   and no-ACL conventions are easy to trip over.
4. Do NOT start the merge — the user does that.
