# Analyst Dashboard — Session handoff

**State (2026-06-02):** the analyst dashboard track is **COMPLETE**. W1–W8 are
all BUILT + verified (Phases B1–B9); **W9 (sightings rework) is DECLINED
(AD-16)** — dropped at spec time because the sighting ACL is intractable for an
analyst widget (existing sightings widgets gate on `perm_site_admin` while
`Sighting->restSearch` is user-scoped) and the engine is slow / patchily used;
the user declined ("the ACL for that is indeed a shitshow"). **No active work
remains** — anything further is user-requested follow-up only (see end).

**This is a NEW, SEPARATE track** from the main dashboard work (whose bridge is
`dashboard-handoff.md`). Main dashboard v2 is feature-complete; this track builds
the **analyst widget surface**. Authoritative state lives in:

- `analyst-dashboard-prd.md` — the mini-PRD. §3 = 9-widget roster (status);
  §5 = per-widget detail; §6 = **AD-NN** decision log (AD-01..**16**; W9 declined
  at AD-16; next = **AD-17**).
- `analyst-dashboard-progress.md` — the task tracker. Spec status, the
  **B1–B9 build backlog** (all done), and a **Discovered work** section.
- This file — ephemeral session bridge; replace as work progresses.

## TL;DR — last session (Phase B9: widget settings canonization — COMPLETE)
Promoted every `$params`-only "advanced" knob the track added into a first-class
**typed `$schema`** entry, so the configure form's **Settings tier** renders a
real control instead of a raw-JSON key. **Pure additive `$schema` edits — zero
platform/JS/adapter/handler change** (the configure form already renders scalar
types; `WidgetSchema` already whitelists `bool`/`int`/`enum`/`string`). Four
promotions:
- `OverlapWithMyOrgWidget.exclude_own_org` → **bool** (checkbox). `055449873`
- `TrendingWidget.dimension` → **enum** `<select>` (3 values + `enum_labels`,
  kept in lock-step with the `dimensions()` registry). `9aef5a133`
- `NewDataStatsWidget.country`/`sector` → **string** text inputs (`''` default
  keeps the auto-detect waterfall). `aed57a35e`
- `EventStreamWidget.tags`/`published`/`limit` → **string/bool/int** (user
  signed off; re-verified the inherited `handler()` genuinely consumes them, so
  W6 `EventStreamCardsWidget` gains the controls via verbatim inheritance;
  handler unchanged; `fields` stays advanced). `9815d5f7c`
- Sweep + posture commit `2189bd0f3`. **No duplication** (a key in both `$params`
  and `$schema` renders once — the form's `handledKeys` filters it from the
  Advanced tier). Verified through the **real `configure.module.mjs`**
  (`--dump-dom` + screenshots `/home/iglocska/b9_configure_*.png`). Recipe now in
  [[reference-dashboard-widget-render-verification]] (configure-form path).

## What now exists in the tree (reuse it; don't re-derive)
- **Built analyst widgets** (W1–W8): `TrendingWidget` (+`Trending` render, 3
  dims), `NewDataStatsWidget` (`StatGrid`), `EventStreamCardsWidget`
  (+`EventCards` render), `OverlapWithMyOrgWidget` (W8, EventCards + overlap
  badge), `AttackWidget` (+`Attack` render, AD-15 heatmap redesign).
  Infra: `DashboardURLValidator`, `WidgetCache` `'org'` scope.
- **Render kinds available** (`app/View/Elements/dashboard/Widgets/`): Achievements,
  Attack, BarChart, Button, **EventCards**, HealthList, Index, MonitorLineChart,
  MultiLineChart, NetworkGraph, OrgsPictures, PewPewMap, PieChart, QueueList,
  **SimpleList**, **StatGrid**, **Trending**, UserList, WorldMap. A NEW render
  kind ⇒ a matching glyph in `render-thumbs.mjs` (CLAUDE.md rule).
- **Typed-settings convention (B9):** prefer a typed `$schema` entry
  (`bool`/`int`/`enum`/`string`) over a `$params`-only knob; keep `$params` as
  the field help. Only freeform dicts/arrays (AttackWidget `filters`,
  EventStream `fields`) legitimately stay raw/advanced.

## TRACK COMPLETE — no active work
W1–W8 are all BUILT + verified (Phases B1–B9). **W9 is DECLINED (AD-16):** the
W9 spec-time recon surfaced that both existing sightings widgets
(`RecentSightingsWidget`, `ThresholdSightingsWidget`) gate on `perm_site_admin`
via `checkPermissions()`, while `Sighting->restSearch($user, …)` is itself
user-ACL-aware — reconciling that gate-vs-ACL conflict for an analyst widget,
on top of the slow / patchily-used engine, isn't worth it. **User declined.**
The existing sightings widgets are left untouched. Full rationale: PRD §6 AD-16.

### Follow-ups (user-requested only — none are queued)
- Clear `w_8`'s stale 2023 `filters.timestamp` for a full all-time heatmap.
- Heatmap-tile default-width bump (labeled cells want >3×4).
- Richer `tags`→`tag_filter` chip picker on `EventStreamWidget` — would need a
  handler change (the canonical translates to `include`/`exclude`, not the `tags`
  comma-string fetchEvent reads) → main-track touch, **sign-off** first.
- `ThresholdSightingsWidget.threshold` is an untyped `$params` knob — only worth a
  B9-style promotion if that widget is ever touched (it's site-admin-only / main
  track).
- The user recomposes the analyst `template.json` (their job).

## Verifying a widget — recipe in [[reference-dashboard-widget-render-verification]]
Two real paths: (1) **body render** — `renderWidget` is CSRF-unlocked → REST+APIkey
returns the JSON `data` (validates the handler); web-UI POST + session cookie
returns the real `.ctp` HTML; snap-chromium screenshot (the chrome is
**`$HOME`-confined** — stage harness + screenshots under `/home/iglocska/`, NOT
`/tmp`; inline/serve `dashboard.default.css` for tokens). (2) **configure-form
render** (a `$schema`→controls check) — serve the real webroot over http so
`configure.module.mjs` + its relative imports resolve; feed a synthetic widget el
the real `data-widget-schema` JSON; `--dump-dom` asserts the controls. **Session
cookie** jar `/tmp/cj_stat.txt` (re-mint via [[reference-misp-login-dance]] if it
302s). **Clock/data caveat:** box clock 2026-06-02; corpus is stale (sightings
newest 2026-03-24, events ~2026-05-29) — use wide / all-time windows.

## Conventions (carry)
- **AD-NN** decision numbering (next = **AD-17**), cross-linked to parent `DD-NN`.
- **Additive-only** ([[feedback_additive_only_posture]]): new widgets + new render
  kinds = pure additions; existing-code touches need **sign-off**. Sign-offs
  granted so far: B4 DD-03 relaxation; B1.6 `WidgetCache` `'org'` scope; B7/AD-15
  `Attack.ctp` rewrite + `AttackWidget` `time_window`; B9 `EventStreamWidget`
  schema. **For W9, prefer a new analyst sibling over editing the site-admin-gated
  `RecentSightingsWidget`** (avoids an existing-code touch).
- **Add built/touched widgets to user 1's test dashboard**
  ([[feedback_add_touched_widgets_to_dashboard]]): append (back up the layout
  first; never replace), dedupe by class, then smoke-test. Board backup convention:
  `/tmp/dash_backup.json`.
- **Sequential** ([[feedback_sequential_implementation]]): one task at a time;
  research may parallelise, code never.
- **Commit per task** ([[feedback_commit_per_task]]); **never `git add -A`** —
  explicit `git add` + `git status --short`; **sign** (`git commit -S`, `%G?`=U).
  If signing times out, the GPG passphrase lapsed — ask the user to run
  `! echo x | gpg --clearsign -o /dev/null`, then retry.
- **chgrp www-data** every edited web-served/app file incl. docs.
- A **NEW render kind ⇒ a matching glyph** in `render-thumbs.mjs` (CLAUDE.md).
  Reusing an existing kind ⇒ no glyph.
- One task close = tick the tracker checkbox + a 1–3 line **Done note**; commit
  body references the tracker task.
- User wants **rigorous pushback + genuine forks via AskUserQuestion**, and to
  **re-verify rather than defend** when a premise is questioned
  ([[feedback_question_stated_premises]]). (B9's EventStreamWidget fix came from
  exactly this — the user questioned "out of scope" and the re-verify proved the
  filters were live.)
- **Recomposing the analyst `template.json` is the USER's job** — we build
  widgets; the user arranges the board.

## Live test instance (shared with the main track)
- `http://localhost:5007/dashboards` (302 w/o session, 200 with). Admin user 1
  `admin@admin.test` / `Password12345` (**org_id = 1**, site-admin), API key
  `dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC`, Overmind theme. Cookie jar
  `/tmp/cj_stat.txt` (re-mint via [[reference-misp-login-dance]] if it 302s).
- DB `mysql -u misp -pPassword1234 misp`; Redis `redis-cli -n 13` (data),
  db0 sessions. Correlation engine = **Default**. Branch: `dashboards` — both
  tracks ship together.

## Quick-start for next session
**The track is done — there is no queued analyst-dashboard work.** W1–W8 BUILT +
verified (B1–B9); W9 DECLINED (AD-16). If the user opens new analyst-dashboard
work, it's a fresh request — read the tracker's "✅ ANALYST DASHBOARD TRACK
COMPLETE" marker + PRD §3 roster for the as-built state, and the "Follow-ups"
list above for the only loose ends (all user-requested, none queued). For
anything new, carry the Conventions below (additive-only, commit-per-task signed,
AD-NN numbering — next would be **AD-17**, verify via the real render path).
