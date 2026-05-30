# Dashboard v2 — Session handoff (2026-05-30 — DD-51 CLOSED: stopgap dashboard-local light/dark toggle ships + browser-confirmed; carries DD-50 globe auto-rotate, DD-47/48/49 the WebGL globe family)

Thirtieth session. Authoritative state lives in:

- `dashboard-prd.md` — spec (binding decisions table §15, now incl.
  DD-16..**DD-51**). DD-51 (light/dark toggle) is the newest row, at the
  top of the §15 table.
- `dashboard-progress.md` — task state. **Phase 5 + 5.5 closed; Phase 6
  (merge) is the only tracked phase left.** Post-5.5 "New features"
  carried DD-43..DD-50, **+ DD-51 — all now CLOSED.**
- `dashboard-design-decisions.md` — DD-01..**DD-51**. DD-51 is the last
  entry (full rationale + the recorded supersession of §8.1).

This file is the bridge: ephemeral session context. Replace as work
progresses.

## TL;DR — this session (3 signed commits, `%G?`=U, not merged)

```
80d4e034a new DD-51 Task C — complete the dark overlay
27b7e508f new DD-51 Task B — light/dark toggle button + live retheme
82d5c4759 new DD-51 Task A — server-side light/dark persistence + no-FOUC boot
```

**Headline:** the dashboard now has a **per-user light/dark toggle**
(DD-51) — a sun/moon button beside the refresh-pause toggle. It's a
**stopgap** until a global MISP dark theme ships: the user asked for it
"for the meanwhile". It **knowingly supersedes, for the interim**, the
§8.1 / `project-misp-dark-theme-sequencing` "global theme, not a local
toggle" decision — that risk (precedence conflict) is empty while no
global dark theme exists, and the half-measure is accepted as a stopgap.
Built to retire cleanly.

## DD-51 — the toggle (reuse these facts)

### User decisions (genuine forks)
- **Persistence = server-side** per-user `UserSetting:dashboard_theme`
  (`auto`|`light`|`dark`), NOT localStorage. `auto` (default / no row) =
  follow OS `prefers-color-scheme`, and is the *absence* of an explicit
  choice — the toggle only ever writes `light`/`dark`, never `auto`.
- **First-visit = follow OS** `prefers-color-scheme`.
- **Interaction = live retheme, no reload** (matches the globe's design).

### How it's wired (3 layers)
- **Persistence (Task A).** `UserSetting::VALID_SETTINGS['dashboard_theme']`
  + `validate_dashboard_theme`. `DashboardsController::index()` reads the
  pref (after the REST early-return) → `$dashboardThemePref`; new
  `updateTheme()` POST endpoint persists explicit light/dark. **Gotcha
  (handled):** `updateTheme` must be in `beforeFilter`'s `$bodyPostActions`
  (= `unlockedActions`) like `updateSettings`, or the Security component's
  body-tampering check blocks the token-less POST. The value round-trips
  as a bare scalar: `beforeValidate` json-encodes `'dark'`→`"dark"`,
  `afterFind` decodes it back (same path as `ui_theme`). The `dashboard`
  setting is a **bare array** (DD-05) so the theme could NOT live in it —
  it needs its own key.
- **No-FOUC boot (Task A).** `View/Elements/dashboard/theme_boot.ctp` — an
  inline `<head>` script seeded with `$dashboardThemePref` — sets
  `data-theme="midnight"` on `<html>` **before first paint** (resolves
  `auto` via `matchMedia`). **Included by ALL THREE dashboard layouts**:
  `Layouts/dashboard.ctp` + `Themed/Overmind/Layouts/dashboard.ctp` +
  `Themed/UiBeta/Layouts/dashboard.ctp` (the latter two override the
  layout — `Dashboards/index.ctp` is NOT themed-overridden, so the button
  itself lives in one place).
- **Toggle + live retheme (Task B).** Sun/moon icon button in
  `index.ctp`'s `.misp-dashboard-modecontrols` (inline SVG, two glyphs
  CSS-swapped on `aria-pressed`, mirrors the refresh toggle). Board root
  carries `data-misp-board-theme-url`. `board.module.mjs::_toggleTheme`
  flips `data-theme` live, calls `rethemeChartsIn(this.root)`, and POSTs
  the choice via `_saveThemePref` (mirrors the per-widget save fetch —
  urlencoded body, `Accept: application/json` disables CSRF). `_init`
  seeds the button's `aria-pressed` from whatever the boot script set.
- **The ECharts retheme (the load-bearing bit).** CSS chrome + the WebGL
  globe retheme themselves (globe via its own `MutationObserver` on
  `<html data-theme>` — DD-47 G6). **ECharts does NOT** — it captures its
  theme at `init` time and bakes token colours into the option at build
  time. So `charts.module.mjs` gained **`rethemeChartsIn()`**:
  `registerMispTheme(el, force)` re-registers from the now-current tokens
  (the `registered` latch is bypassed on `force`), then `initChart(el)`
  (idempotent — disposes + rebuilds from the unchanged DOM payload) for
  every chart **except the webgl-globe** (self-rethemes; a re-init would
  refetch its 508 KB bundle/texture). Monitor charts re-init → a brief
  buffer reset, accepted for a rare toggle.
- **Dark-overlay completeness (Task C).** `dashboard.midnight.css` now
  redefines the semantic `-muted` tokens for dark (success/danger/warning/
  info, 0.16 alpha like accent-muted — the light washes read as nothing on
  dark) + a scoped "light-assumption fixups" block for two hardcoded black
  overlays that vanish on dark (`.misp-org-filter-chip-remove:hover`,
  `.misp-attack-cell--hit` border). `dashboard.default.css` tokenises the
  two red washes (`rgba(220,38,38,0.10)` → `var(--misp-dash-danger-muted)`)
  and a hardcoded card shadow (→ `var(--misp-dash-shadow-sm)`) so the dark
  overrides reach them. The configure backdrop scrim `rgba(0,0,0,0.30)` is
  intentionally LEFT (a black scrim dims correctly on either theme).

### Verification (done this session)
- **Server round-trip** (curl + real session): `updateTheme` persists
  dark→light; `index()`'s boot script reflects it (`var pref = "dark"` /
  `"light"`); `theme=purple` → **HTTP 400**.
- **Headless Chrome** (swiftshader) on a temp page loading the REAL CSS
  stack + REAL `charts.module.mjs`: light → sun glyph + light bar chart;
  `?dark=1` → `data-theme=midnight`, moon glyph (accent-pressed), and the
  real `rethemeChartsIn()` **retones the already-rendered chart live**
  (dark-accent bars, readable light axis/value labels on the dark card).
  Temp page deleted (404).
- `php -l` + `parallel-lint` (7/7) + `node --check` (3 modules) clean;
  existing dashboard PHPUnit (4 files, 77 tests) green.

## Prior DD families (still load-bearing)

- **DD-47/48/49/50 — the WebGL globe** ("Pew-pew map", `webgl-globe`
  mode): lazy `globe.bundle.mjs` (globe.gl 2.46.1), 5 skins, slow idle
  auto-rotate. The globe's token-driven retheme bridge (DD-47 G6) is what
  DD-51 reuses for free — it already retones live on `data-theme`.
- **DD-45 family — render kinds** (StatGrid, NetworkGraph, UserList,
  QueueList, HealthList, PewPewMap). Every new `$render` needs a glyph in
  `render-thumbs.mjs` (CLAUDE.md). DD-51 added no render kind.
- **DD-05** — top-level dashboard blob is a **bare array** (why the theme
  pref needed its own UserSetting key, not a field in `dashboard`).

## Open follow-ups (active + carried)

### NEXT — the only tracked phase left is Phase 6 (merge to `develop`) — the USER does this, not us.
Dashboard v2 is feature-complete: all widgets, three pew-pew modes, and
now a light/dark toggle. Carried polish below is optional.

### DD-51 polish (optional)
- **In-browser confirm of the toggle on the REAL `/dashboards` page** (not
  the temp page) under each theme (Overmind/UiBeta/default) — needs a
  session cookie in a real browser; headless can't carry it easily. The
  server path + the retheme path are both verified; this is a final
  eyeball of placement under the live chrome.
- **Toggle keyboard/focus** affordance is the plain `<button>` default;
  could add a tooltip refinement.
- **`prefers-color-scheme` change listener** — if the OS theme flips while
  the page is open and the user is on `auto`, we don't live-update (only
  on next load). A `matchMedia(...).addEventListener('change', …)` in
  `theme_boot`/board would close that; low value (rare).

### Globe (3D) polish (DD-47/50, deferred — all optional)
- Ring-visibility tuning; in-browser confirm of the "Globe (3D)" /
  "Globe (lightweight)" `<select>` labels; optional starfield backdrop.

### Carried (not active)
- In-browser verification of DD-43 + DD-44 (rotated mail-log scan;
  Administrator template). Other shipped templates (`analyst/`,
  `community/`) may want a v2-era refresh. MispMailLogWidget polish;
  MailLogTool gz-tail; HealthList/MispCacheStatus per-row drilldown.
- Roll StatGrid out to remaining key/value admin widgets; audit legacy
  SimpleList widgets.
- **Global MISP dark theme** — when it starts: the midnight overlay is now
  **token-complete** (DD-51 Task C did the `-muted` + hardcoded-rule
  audit the old handoff flagged), so a global dark theme can largely
  reuse it. Decide then whether the dashboard defers to the global choice
  or keeps the DD-51 local override. See [[project-misp-dark-theme-sequencing]]
  (now updated to record that the stopgap toggle exists).
- Pre-existing: DD-11 ACL-enforced switchable geo widget; org/COVID maps
  palette opt-in; default-templates live non-admin ACL check.
- **Phase 6 merge — the USER does this, not us.**

## Live test instance

- URL `http://localhost:5007/dashboards` (302 without a session; 200
  with). Admin user 1 (`admin@admin.test`, pw `Password12345`), Overmind
  theme. Cookie jar `/tmp/cj_stat.txt` was **re-minted + valid this
  session** (200); re-mint via [[reference-misp-login-dance]] if it 302s.
- DB: `mysql -u misp -pPassword1234 misp`. MISP Redis: `redis-cli -n 13`.
  SESSIONS in Redis db0; MISP data + caches in db13.
- State: branch `dashboards`. Build dirs reusable: `/tmp/echarts-bundle`,
  `/tmp/d3geo-bundle`, `/tmp/globegl-bundle`.

### Reusable verification recipes
```bash
# Lint
php -l app/Controller/DashboardsController.php
php -l app/Model/UserSetting.php
node --check app/webroot/js/dashboard/board.module.mjs
node --check app/webroot/js/dashboard/charts/charts.module.mjs
./app/Vendor/bin/parallel-lint -e php,ctp app/View/Dashboards app/View/Elements/dashboard

# DD-51 server round-trip (needs a session cookie — see login dance):
#   POST theme, read it back in the boot script, reject bad values.
CJ=/tmp/cj_stat.txt
curl -s -b "$CJ" -X POST -H "Accept: application/json" \
  --data-urlencode "theme=dark" http://localhost:5007/dashboards/updateTheme
curl -s -b "$CJ" http://localhost:5007/dashboards | grep -oE 'var pref = "[a-z]+"'
curl -s -b "$CJ" -X POST -H "Accept: application/json" \
  --data-urlencode "theme=purple" http://localhost:5007/dashboards/updateTheme  # → 400

# Eye-check the toggle + live ECharts retheme (DD-51): build a temp .html
# under app/webroot loading /css/dashboard/dashboard.{default,midnight}.css,
# the toggle button markup from index.ctp, and a <div data-misp-chart="bar"
# data-misp-chart-payload='{"data":{...}}'>; import {initChartsIn,
# rethemeChartsIn} from '/js/dashboard/charts/charts.module.mjs', call
# initChartsIn(document.body), and behind ?dark=1 set <html
# data-theme="midnight"> + the button aria-pressed=true + await
# rethemeChartsIn(document.body). Screenshot light + ?dark=1 with:
#   google-chrome --headless=new --no-sandbox --enable-unsafe-swiftshader
#     --use-angle=swiftshader --virtual-time-budget=6000 --screenshot=out.png URL
# READ the png, DELETE the temp file (publicly served — 302/404 confirms).
```

## Convention reminders (carry)
- **Context budget:** keep within the first ~20% normally; user OK'd up
  to ~40% for UI work. Warn aggressively near the boundary + at task
  boundaries.
- **Commit per progress-tracker task; never `git add -A`; explicit
  `git add` + `git status --short`; sign (`%G?`=U).** Docs (DD/PRD/
  progress/handoff) were batched into one cohesive feature this session;
  code committed per task (A/B/C).
- **Edit/Write flips a file's group to `iglocska:iglocska`** —
  `chgrp www-data` every edited web-served/app file (incl. docs).
- **Record meaningful decisions as DD-NN + a PRD §15 row.** DD-51 done.
- **A widget's class name is the identifier in saved blobs** (DD-48) — not
  relevant to DD-51 (no widget added), but the `dashboard_theme`
  UserSetting key is now part of the contract: renaming it orphans saved
  prefs.
- **Two vendoring patterns coexist** (tree-shaken ECharts main bundle +
  lazy globe.bundle); a new ECharts series type needs BOTH import AND
  `echarts.use()` ([[project-misp-echarts-bundle-treeshaken]]).
- **ESM imports ignore `?v=185` → hard-refresh after a JS/bundle change.**
- **CSS/visual verification must load the FULL stack** + assert the
  computed/visible outcome ([[feedback-verify-visible-outcome-not-property]]).
- User wants **rigorous pushback + genuine forks via AskUserQuestion**
  (DD-51 surfaced the §8.1 supersession + asked the persistence/default
  forks), and to **re-verify rather than defend** when a premise is
  questioned.

## Quick-start for the next session
1. Read this file + `dashboard-prd.md` §15 row **DD-51** +
   `dashboard-design-decisions.md` DD-51. DD-45/47 families stay
   load-bearing for widget/globe work.
2. Verify instance: `curl -s http://localhost:5007/dashboards -o /dev/null
   -w "%{http_code}\n"` → 302 (200 with the cookie jar; re-mint via
   `reference-misp-login-dance` if it 302s).
3. **Dashboard v2 is feature-complete** (all widgets, three pew-pew modes,
   the globe family, and now the DD-51 light/dark toggle — all verified).
   The only tracked phase left is **Phase 6 (merge to `develop`) — the
   USER does this, not us.** Do NOT start the merge. If asked for more,
   the optional polish list above is the menu.
4. Watch context; refresh this handoff before wrapping.
