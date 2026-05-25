# Dashboard v2 — Session handoff (2026-05-25 — Phase 5.5 closed + pre-merge polish)

Eleventh session. Authoritative state lives in:

- `dashboard-prd.md` — spec (binding decisions table §15, now incl. DD-09).
- `dashboard-progress.md` — task state. **Phase 5 + Phase 5.5 fully
  closed.** Phase 6 (merge) is the only remaining tracked phase.
- `dashboard-design-decisions.md` — DD-01..DD-09 (DD-09 new this session).

This file is the bridge: ephemeral session-level context. Replace it
as work progresses.

## ⚠️ Forward plan — READ THIS FIRST (user direction, 2026-05-25)

The merge gate is green, but the user is **NOT merging yet**. Explicit
sequence the user gave:

1. **A round of design-decision / UX tweaks** ("mostly some UX tweaks")
   before the feature is considered done. Several already landed this
   session (see Arc B); **expect more — the user drives them one at a
   time.** Treat each as a small design decision: surface trade-offs,
   recommend, record meaningful ones as DD-NN.
2. **Then add new *types* of widgets / new functionality.** (Not yet
   started — this is the bigger next chunk.)
3. **The user does the merge themselves** — do NOT open the PR or merge.
4. **After merge, the user will ask for help documenting the feature.**

So the next session is almost certainly **more UX tweaks and/or new
widget types**, not Phase 6. Don't push toward the merge.

## TL;DR — this session (18 signed commits, all `%G?` = U)

Two arcs. **Arc A: closed all of Phase 5.5** (the merge gate). **Arc B:
a pre-merge UX/feature polish round** per the user's "more changes
first" direction.

**Arc A — Phase 5.5 (merge gate), fully closed** (detail in the prior
handoff revision + git `3746ae3b2..62349cfb0`):
- Data parity 5/5, widget parity 38/38 (37 widgets + custom-loader),
  surface parity 10/10, pre-merge cleanup 7/7.
- Two code changes surfaced by the sweeps: `fc3c4cd5b` fixed
  MispAdminWorkerWidget's pre-existing PHP 8.x crash; `da819c16d` gave
  the 3 `OrgsContributors*` widgets a typed `timeframe` schema.
- `getForm/add` closed as deliberate obsolescence (gallery replaces it).
- jvectormap removed (dead); D3 + Chart.min.js retained (live consumers).

**Arc B — pre-merge polish:**
- `ebfefea5e` — **doc**: recorded that the parked `LayoutFixup` mixed-id
  mint collision is **provably unreachable from migrate-then-add** (the
  user pressed on this; tracing `_mintFinalInstanceId` confirmed it).
  Still parked; only a hand-edited import blob could trigger it.
- `99fbaf230` — **removed the prototype "Overmind" pill** that each
  widget title bar carried (a Phase-0/1 theme-override-visible marker).
- `35592360b` — **DD-09 calm widget chrome**: titlebar made transparent
  (no fill/divider, both themes); action icons hidden in view mode and
  revealed on widget `:hover`/`:focus-within`; always-visible in edit
  mode. Title + refresh chip always visible. CSS-only.
- `f5fa90285` — **restored per-widget raw-data export** (lost-in-rework
  v1 feature). A ⬇ download menu-button on each widget toolbar → JSON /
  CSV. Backend `exportjson` now returns the bare handler output (v1
  parity); `exportcsv` = flattened CSV; plain REST render stays wrapped.
- `d7f173206` — **fix**: removed the underline BS5 `.btn-link` put on
  the Overmind toolbar icons.
- `544abf83e` — **fix**: the export download was a detached-anchor +
  sync-revoke anti-pattern → FF/Safari rendered the JSON in-page instead
  of saving. Now appends the anchor + defers revoke.

## Where we are

```
Phase 0.4 / 1 / 2 / 3 / 4 / 5 / 5.5                               [x] CLOSED
Phase 6 — Merge to develop                                       [ ] (USER does this; not us)

Post-5.5 pre-merge polish (untracked phase — user-driven, in progress):
  [x] DD-09 calm chrome
  [x] Overmind prototype pill removed
  [x] Per-widget raw-data export restored (+ underline + download fixes)
  [x] Export menu clip on 1-row widgets fixed (CSS :has() transient lift)
  [x] Import/Export config → board-owned side panel (theme-independent; DD-10)
  [x] Removed Phase 0.3 debug-readout footer (layout-JSON dump) — prototype cruft
  [ ] More UX tweaks — user will enumerate
  [ ] New widget types / functionality — not started
```

## Live test instance

- URL: `http://localhost:5007/dashboards`
- Admin user id 1 (`admin@admin.test`), password `Password12345`.
- Admin API key: `dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC`.
- **Admin is on the Overmind theme** (`UserSetting:ui_theme="Overmind"`).
  Most of this session's UX work is most visible there. To check the
  default theme, temporarily set `ui_theme` to `"default"` and restore.
- DB: `mysql -u misp -pPassword1234 misp`.

**State at session end (all restored byte-exact):** admin's 13-widget
board, `UserSetting:dashboard` = 2066 bytes; `ui_theme="Overmind"`;
`dashboards` table = 6 rows (all legacy-shape). Backup kept at
`/tmp/dash_backup.json`. v2 working tree clean (the dirty paths in
`git status` are unrelated submodules / untracked tooling, never ours).

**Hard-refresh after any CSS/JS edit** — the `?v=185` cache-buster in
`AppController` does NOT bump per-file. Several "is it broken?" reports
this session were just stale cached assets.

### Reusable smoke recipes

```bash
KEY=dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC
# Render a widget (REST: {data,renderer,config}; HTML: the .ctp body):
curl -s -X POST -H "Authorization: $KEY" -H "Accept: application/json" \
  --data-urlencode "widget=<Name>Widget" --data-urlencode "config={}" \
  http://localhost:5007/dashboards/renderWidget
# Raw-data export (v1-parity): bare JSON / flattened CSV
curl -s -X POST -H "Authorization: $KEY" -H "Accept: application/json" \
  --data-urlencode "widget=UsageDataWidget" --data-urlencode "config=[]" \
  "http://localhost:5007/dashboards/renderWidget/w_x/exportjson:1"
# Widget metadata (schema/category/render) for the gallery:
curl -s -X POST -H "Authorization: $KEY" -H "Accept: application/json" \
  http://localhost:5007/dashboards/widgets
# Session-login dance for HTML pages: see reference-misp-login-dance memory.
# ALWAYS back up + byte-exact restore UserSetting:dashboard around DB writes.
```

## Key architecture facts confirmed this session (reuse these)

- **Widget toolbar chrome (DD-09):** titlebar transparent; action icons
  in `.misp-widget-actions` (default) / `.card-header .btn-group`
  (Overmind) are `opacity:0` in `[data-misp-board-mode="view"]`,
  revealed on `.misp-widget:hover` / `:focus-within`, always-on in edit.
- **No themed widget-renderer overrides exist** → every
  `Widgets/<renderer>.ctp` is theme-independent; theme = page CSS +
  ECharts tokens only.
- **Both dashboard layouts load `dashboard.default.css`** then the theme
  overlay, so shared widget classes styled in the default sheet retone
  automatically under Overmind via `--misp-dash-*` tokens. (That's why
  the export menu needed no overmind.css change.)
- **Per-widget actions dispatch** through one delegated listener
  (`board.module.mjs _wireWidgetActions`) on `data-misp-widget-action`
  — works for dynamically-added tiles with no per-tile wiring. Vocabulary:
  `refresh | configure | remove | export-json | export-csv`.
- **Reusable WAI-ARIA menu** = `menu-button.module.mjs` (`initMenuButtons`);
  markup contract `[data-misp-menubutton]` > `[-trigger]` + `[-menu]`
  (`role=menu`) > `[role=menuitem]`. It does NOT self-close on item
  click (the click is inside its root) — close it explicitly. Server-
  rendered instances are hydrated by `boot()`'s document-wide call;
  dynamically-added tiles call `initMenuButtons(wrapperEl)`.
- **`renderWidget` export contract:** `exportjson` → bare `$data`;
  `exportcsv` → `_dataToCsv($data)`; plain `_isRest()` (no export param)
  → wrapped `{instance_id,widget,config,renderer,data}`. Don't re-merge
  these branches.
- **Robust blob download:** anchor MUST be in the document + revoke on a
  deferred tick, or FF/Safari render the blob in-page.
- **`Dashboard::import()` stores verbatim; fix-ups are on-read only**
  (`LayoutFixup`). The kv-tier configure fallback (DD-06) is load-bearing
  for custom widgets — don't remove it.

## Discovered work / parked

- **`LayoutFixup` mixed-id mint collision** — parked; provably
  unreachable from real UI flows (migrate-then-add traced safe via
  `_mintFinalInstanceId` = max+1). Only a hand-edited import blob
  triggers it. Cheap fix logged in the progress doc if ever wanted.
- ~~**Export menu clipping on very short widgets**~~ — **FIXED 2026-05-25.**
  Confirmed real on 1-row (80px) widgets via a headless before/after
  harness (menu bottom item clipped against `.misp-widget`'s rounded-
  corner `overflow:hidden`). Fix did NOT move the overflow to the body
  (handoff's earlier idea — that risks a 6px scrollbar/corner poke on
  scrolling widgets); instead lifts the clip *transiently and only while
  the export menu is open* via `.misp-widget:has(.misp-widget-menu.is-open)
  { overflow: visible }` (mirrored on `.card.misp-widget--overmind`).
  Corners re-clip on close; body keeps its own `overflow:auto`; z-index:20
  correctly paints the escaping menu above the widget below. CSS-only,
  both themes; lightweight cleanup, no DD.
- **Real widgets emit drilldown maps** — Phase 5 renderer contract is
  wired + smoked; nothing in-tree consumes it. Natural fit for the "new
  functionality" phase.
- Carryovers (unchanged): `blocklist_orgs` rich picker (needs handler
  rewrite); Chart.min.js / D3 migration (non-dashboard consumers);
  import HTML form-paste string-foreach quirk (now *bypassed* by the
  DD-10 panel, which POSTs to updateSettings; the quirk only remains on
  the legacy `/dashboards/import` action reachable via the no-JS href
  fallback); file-mode-drift root
  cause; time_window dropdown UX; grid drop-on-occupied cascade;
  tlp:clear invisible bars; OrgEventsWidget months>13 dates;
  EventEvolutionLineWidget end_date; live-preview race; dormant
  `dashboard.midnight.css` loader; EventStreamWidget pre-fetch overshoot.

## Lessons this session

1. **Hard-refresh first when the user reports a UI bug.** The `?v=185`
   cache-buster doesn't bump per-file; stale assets masqueraded as bugs.
2. **Re-verify a premise the moment the user questions it** (the
   migrate-then-add collision question forced a trace that *strengthened*
   the safe conclusion — and corrected my parked-note wording).
3. **`preventDefault()` ≠ stop other handlers** — but check whether a
   competing handler actually matches before blaming it (the export
   "popover" was my own blob anti-pattern, not a MISP global handler).
4. **A canonical type isn't a free drop-in** — declaring a param as one
   wires the client picker AND the server translation; the handler must
   read the translated shape (`blocklist_orgs`→`org_filter` would break
   the handler, so it stayed on the kv-tier; only `timeframe`→`int`).
5. **Build to v1 parity for restored features** — check the old format
   on the `2.5` branch (`git show 2.5:...`) and replicate it (bare JSON
   + flattened CSV + `<widget>_<id>_export.<type>` filename).

## Convention reminders

- Commit per logical task; never `git add -A`; explicit `git add` +
  `git status --short` first; body references the task. Sign commits
  (`%G?`=U). **Per-row for granular tracker work; per-feature/per-group
  for batches.**
- New files: `chgrp www-data` before commit (none landed this session —
  all edits to existing files; temp smoke harnesses lived in `/tmp/`).
- **Themed wrapper parity:** any chrome/`data-*` change on the base
  `widget/wrapper.ctp` must be mirrored in the Overmind wrapper in the
  SAME commit (the export menu-button was added to both).
- **Dashboard chrome icons are inline glyphs/SVG, not Font Awesome.**
- **External links pair `target=_blank` + `rel=noopener noreferrer`.**
- **Record meaningful design decisions as DD-NN** in
  `dashboard-design-decisions.md` + a PRD §15 binding row (DD-09 set the
  pattern this session). Lightweight cleanups don't need a DD.
- User wants **rigorous pushback**, not a yes-machine — surface
  trade-offs, name alternatives, recommend, then go with the user's call.
  Use AskUserQuestion for genuine forks (this session: session scope,
  jvectormap removal, edit-mode chrome, scope, export UI shape).
- **Render-kind glyph requirement:** any new `$render` value / new
  `Widgets/` template ships a matching glyph in `render-thumbs.mjs` in
  the same commit. (Relevant for the upcoming "new widget types" work.)
- Tracker/decision docs are ground truth between hitm/afk sessions.
- Surface context status past 75% at task boundaries. (This session was
  paced to ~47% at handoff.)

## Quick-start cheatsheet for the next session

1. Read `dashboard-prd.md` (spec) + `dashboard-progress.md` (state) +
   this file.
2. Verify the instance: `curl -s http://localhost:5007/dashboards
   -o /dev/null -w "%{http_code}\n"` → 302 without a session.
3. **Phase 5 + 5.5 are CLOSED. The user is doing more pre-merge UX
   tweaks, then new widget types, then merging themselves.** Wait for
   the user's next tweak/feature; do NOT start the merge.
4. When building UI: respect DD-09 calm chrome, the menu-button pattern,
   themed-wrapper parity, and hard-refresh to see CSS/JS changes.
5. Commit one task at a time, signed; back up + restore admin's
   dashboard around DB-mutating smokes.
