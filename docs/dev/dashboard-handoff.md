# Dashboard v2 — Session handoff (2026-05-26 — aliasing + generic widget cache + Peters/Natural-Earth)

Fourteenth session. Authoritative state lives in:

- `dashboard-prd.md` — spec (binding decisions table §15, now incl.
  DD-16..DD-20).
- `dashboard-progress.md` — task state. **Phase 5 + 5.5 closed; Phase 6
  (merge) is the only tracked phase left.** The two post-5.5 sections
  now read: "New widget types" (geo/threat maps + projections) and
  "**New features**" (aliasing ✅, default layouts ⬜, geo caching ✅ +
  generic cache ✅).
- `dashboard-design-decisions.md` — DD-01..DD-20 (DD-16..20 new this
  session).

This file is the bridge: ephemeral session context. Replace as work
progresses.

## TL;DR — this session (5 signed commits, all `%G?`=U, none merged)

Continued the user-driven post-5.5 work, one item at a time:

```
781afe7df new Peters (Gall-Peters) projection — vendored d3-geo geoCylindricalEqualArea (DD-16)
c017653e7 chg default WorldMap projection Mercator -> Natural Earth, all maps (DD-17)
68908c735 new widget aliasing — per-instance display name (DD-18)
34e67c470 new Redis cache for AttributeGeoMapWidget — per-config hash, 1h TTL (DD-19)
f477ed4ad chg extract widget caching into a generic WidgetCache helper (DD-20)
```

**The USER does the merge — do NOT open the PR or merge.**

## What landed (reuse these facts)

### Projections (DD-16, DD-17) — `charts/charts.module.mjs` + the two threat widgets
- **`peters`** = Gall-Peters cylindrical equal-area, `wrapD3(geoCylindricalEqualArea().parallel(45))`.
  The vendored `charts/vendor/d3-geo.bundle.mjs` was rebuilt to add the
  `geoCylindricalEqualArea` export (no new dep — `d3-geo-projection@4`
  already in DD-07; recipe in `vendor/VENDORING.md`). WorldMap enum is
  now `mercator | equirectangular | naturalEarth | robinson | peters`.
- **Default projection is now `naturalEarth`** (was mercator), at BOTH
  layers: the renderer-level fallback in `buildGeoOption`
  (`payload.projection || 'naturalEarth'` + unknown-name fallback) AND
  the two threat widgets' `$schema` default + handler fallback. So
  org/COVID maps (which don't declare projection) render Natural Earth
  too. Mercator/Robinson/Peters stay selectable. User confirmed they
  want one uniform default, no per-widget-type defaults.
- Projection lesson still applies: hand-rolled custom projections render
  y-DOWN (negate y + assert north-up; round-trip alone is insufficient —
  DD-14). d3-backed ones (naturalEarth/robinson/peters) bake north-up in.

### Widget aliasing (DD-18) — per-instance display name
- **Label precedence: `config.alias` → class `$title` → class name.**
  Edited via a "Display name" field at the top of the configure form (a
  `string` schema field **injected server-side** into every widget's
  `$schema` in `DashboardsController::index()` AND `renderWrapper()` —
  exactly like the `refresh_delay` injection). Blank = use `$title`.
- Fixed a latent bug: the enrichment never surfaced `$title`, so
  un-aliased titlebars used to show the **class name**. Now they show
  the real name.
- New wrapper hooks (both default + Overmind `wrapper.ctp`):
  `data-widget-title` (= `$title`, the client fallback) and
  `data-misp-widget-title` (the label span — theme-independent because
  default uses `.misp-widget-title`, Overmind uses `.card-title`).
- Live update: `board.module._applyTitle(el)` (called in configure
  `onSave`/`onPreview`) rewrites the label from `config.alias` →
  `data-widget-title` → `data-widget-name`, since `_renderWidget` only
  swaps the body.
- The Phase-1 proto's dormant **top-level** `alias` scaffolding was
  removed (one notion of alias = `config.alias`). Configure typed-tier
  heading renamed "Filters" → "Settings".
- Multiple instances of one widget already worked (keyed by
  `instance_id`); aliasing just labels them. The admin board already had
  hand-authored `config.alias` values (e.g. "Usage - Financial") that
  were invisible under the old wrapper and now render.

### Generic widget cache (DD-19 → DD-20) — `app/Lib/Dashboard/Tools/WidgetCache.php`
- **Opt in declaratively** with two optional public props, NO cache code
  in `handler()`:
  ```php
  public $cache_duration = 3600;        // TTL seconds; > 0 enables
  public $cache_path = 'misp:...';      // optional; auto-derived if omitted
  ```
- `DashboardsController::renderWidget()` wraps the single `handler()`
  call (line ~388) in `WidgetCache::remember($widget, $config, fn)`.
  Widgets that declare nothing run live (transparent). Redis down →
  silent live render.
- **Key** = `<path>:<sha256(config)>`. Path = `$cache_path` or
  auto-derived `misp:<Inflector::underscore(class − "Widget")>_cache`
  (AttributeGeoMapWidget → `misp:attribute_geo_map_cache`). The whole
  `handler()` payload is cached + returned verbatim on a hit.
- **Hash input** = the post-`CanonicalTypeAdapter` config, `ksort`-ed,
  with `WidgetCache::NON_DATA_KEYS` (`alias`, `refresh_delay`) **stripped**
  — so differently-aliased instances of one widget SHARE a cache entry
  (this protects DD-18; it's a deliberate refinement of "hash all the
  config", flagged to + accepted by the user).
- **Key is config-only, not per-user** — correct ONLY for ACL-free
  aggregate widgets (DD-11). Documented as a precondition in the helper:
  a future ACL-enforced cached widget must add a user/scope dimension.
- `AttributeGeoMapWidget` opts in (`misp:attribute_geo_map_cache`, 1h)
  and is otherwise back to its pure sweep.
- Unit test: `app/Test/WidgetCacheTest.php` (9 cases). Note: PHPUnit
  **8.5** here — use `assertRegExp`, not `assertMatchesRegularExpression`.

## Open follow-ups (in the progress tracker; none blocking)

- **#2 default dashboard layouts (analyst / admin / community)** — the
  remaining user-enumerated feature; NOT started. Needs planning: how
  layouts are authored/shipped, how a user picks+applies one, and how it
  interacts with the existing template system (Save/Import/Export, DD-10)
  + `LayoutFixup`.
- **Wire caching into `ThreatActorCountryMapWidget`** — offered (it's a
  no-ACL galaxy-library aggregate, a clean fit). Two-line opt-in; user
  hasn't said yes. Don't add unprompted.
- **Regenerate `asn-country.json` on mmdb update** (DD-12 follow-up).
- **ACL-enforced switchable path** for the geo widget (DD-11 follow-up).
- **org/COVID maps palette opt-in** (projection already covered by
  DD-17's renderer default).
- More new widget types — user may enumerate.
- **Phase 6 merge — the USER does this, not us.**

## Live test instance (unchanged, verified up this session)

- URL `http://localhost:5007/dashboards` (302 without a session).
- Admin user id 1 (`admin@admin.test`), pw `Password12345`,
  **on the Overmind theme** (no jQuery / `misp.js`; board-owned ESM
  surfaces only — DD-10). Its saved board has 15 widgets incl. 3
  `UsageDataWidget` + 2 `TrendingAttributesWidget` instances with aliases.
- Admin API key `dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC`.
- DB: `mysql -u misp -pPassword1234 misp`. Redis: `redis-cli -n 13`.

### Reusable verification recipes
```bash
KEY=dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC
# REST render — BARE handler data (top-level data/scope/palette/projection):
curl -s -X POST -H "Authorization: $KEY" -H "Accept: application/json" \
  --data-urlencode "widget=<Name>Widget" --data-urlencode "config={}" \
  http://localhost:5007/dashboards/renderWidget
# renderWrapper (Add Widget path) needs instance_id in the URL:
#   .../dashboards/renderWrapper/w_test  (POST widget=, config=)
# HTML index / wrapper render → session cookie (reference-misp-login-dance
#   memory): the titlebar label + data-widget-title live in wrapper.ctp.
# Cache keys: redis-cli -n 13 KEYS 'misp:attribute_geo_map_cache*'
#   (use KEYS for sync reads in scripts; --scan races background jobs).
# Projection math: node round-trip test + assert north-above-south.
```

## Convention reminders

- **Commit per logical task; never `git add -A`; explicit `git add` +
  `git status --short` first; sign (`%G?`=U).** GPG: `git commit -S -F
  /tmp/msg` worked non-interactively all session (cache stayed warm); if
  it ever times out on pinentry, have the user warm it or run the commit.
- **New web-served files: `chgrp www-data`** (widget/helper classes,
  vendored bundles). **Test files stay `iglocska:iglocska`** (CLI-run,
  not web-served — matches `CanonicalTypeAdapterTest`).
- **Hard-refresh after CSS/JS edits** (`?v=185` buster doesn't bump
  per-file). PHP renderer/handler changes need only a reload.
- **Record meaningful decisions as DD-NN + a PRD §15 row.** Overturned
  decisions get a follow-up DD, never an in-place edit (DD-17 supersedes
  DD-14's default; DD-20 generalises DD-19 — both left intact).
- **Render-kind glyph rule** (CLAUDE.md): only new `$render` values need
  a glyph. Nothing this session added a render kind.
- User wants **rigorous pushback + genuine forks via AskUserQuestion**
  (this session: Peters hand-roll vs vendor; alias editing surface) and
  is fine **iterating a design mid-build** (the cache went default-only →
  whole-payload → per-config-hash → generic helper across three turns).
  When the user questions a premise, re-verify rather than defend.

## Quick-start for the next session

1. Read `dashboard-prd.md` §15 + `dashboard-design-decisions.md`
   DD-16..20 + this file. Skim `dashboard-progress.md` post-5.5 sections.
2. Verify instance: `curl -s http://localhost:5007/dashboards -o /dev/null
   -w "%{http_code}\n"` → 302.
3. **No task is mandated.** The likely next item is **#2 default
   dashboard layouts** (needs a planning/fork round first — don't just
   build). The user may instead pick the threat-map cache opt-in, another
   widget, a follow-up, or the merge.
4. If touching the WorldMap renderer, the wrapper/aliasing, or the cache,
   re-read the matching "What landed" section above — the projection
   north-up rule, the alias label-precedence + hooks, and the
   NON_DATA_KEYS exclusion are each easy to trip over.
5. Do NOT start the merge — the user does that.
