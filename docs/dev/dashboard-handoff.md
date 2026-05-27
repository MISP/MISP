# Dashboard v2 — Session handoff (2026-05-27 — default-template lifecycle: auto-ingest, prune, fallback default, single-default hardening + asn-country regen)

Sixteenth session. Authoritative state lives in:

- `dashboard-prd.md` — spec (binding decisions table §15, now incl.
  DD-16..DD-27).
- `dashboard-progress.md` — task state. **Phase 5 + 5.5 closed; Phase 6
  (merge) is the only tracked phase left.** Post-5.5 work continues in the
  "New widget types" and "**New features**" sections; the default-template
  follow-ups closed this session are sub-bullets under the DD-22 feature
  block.
- `dashboard-design-decisions.md` — DD-01..DD-27 (DD-23..DD-27 new this
  session).

This file is the bridge: ephemeral session context. Replace as work
progresses.

## TL;DR — this session (5 signed commits, all `%G?`=U, none merged)

```
52760acaf chg harden __unsetPreviousDefault — demote ALL defaults, not just first (DD-27)
c90d0ec92 new promote Analyst as fallback default when none is set (DD-26)
b93846d42 new prune orphaned built-in templates on explicit ingest (DD-25)
17f7a9455 new auto-ingest default templates on update/install (DD-24)
6c84bb285 new regenerate asn-country.json at release time via preRelease (DD-23)
```

Two user threads: the **DD-12 asn-country follow-up** (DD-23), then the
**default-template lifecycle** (DD-24..27, one task at a time, fork-surfaced
before code).

**The USER does the merge — do NOT open the PR or merge.**

## What landed (reuse these facts)

### DD-23 — `asn-country.json` regen wired into `cake Admin preRelease`
- **Premise corrected:** there is **no automated geo-open mmdb-update job**.
  `app/files/geo-open/` is a plain git-tracked dir (not a submodule, no
  downloader/cron); the mmdb files **and** `asn-country.json` are
  maintainer-hand-committed artifacts (`chg: [GeoOpen] …`). Instances get
  them via `git pull`.
- So the regen hook is the maintainer's **pre-release** step:
  `AdminShell::preRelease()` (which already dumps `db_schema.json` /
  `describeTypes.json`). New `AdminShell::updateAsnCountryMap()` runs
  `generate_asn_country_map.py` via `ProcessTool::execute([
  ProcessTool::pythonBin(), …])` (the managed venv), writing the tracked
  json; called from `preRelease()` **and** registered as a standalone
  `cake Admin updateAsnCountryMap` for mid-cycle mmdb bumps.
- **Fail-safe:** missing `maxminddb`/mmdb → caught, non-fatal `$this->err()`
  warning, json left intact (never zeroed). Regen is **deterministic**
  (sort_keys + fixed separators → byte-identical on an unchanged mmdb, no
  git churn).
- **`maxminddb` declared in `requirements-dev.txt`** (user's call —
  preRelease is "for developers"; prod consumes the committed json).
  Trade-off: an admin running the standalone subcommand in prod must install
  `maxminddb` by hand (gets the warning otherwise).

### DD-24 — auto-ingest default templates on update/install
- `AppModel::DB_CHANGES` gains `151 => false`; `updateMISP()` gains
  `case 151:` → new private `__importDefaultDashboardTemplates()` (inits the
  Dashboard model, calls DD-22's idempotent
  `importTemplatesFromDirectory()`, logs SYSTEM `update_database`; returns
  true so a missing templates dir never fails the migration chain).
- Covers **update** (instances cross 151) **and fresh install**
  (`INSTALL/MYSQL.sql` baselines `db_version=126`; `runUpdates` replays the
  delta through 151). **151 has shipped nowhere yet** — so production
  instances cross it for the first time *with all of DD-24/26's code in
  place* (this matters for the fallback default below).
- **Deliberate divergence:** MISP keeps reference-data *content* ingest
  on-demand (only schema migrates); user chose **unconditional** auto-ingest
  anyway (3 tiny selectable/deletable rows).

### DD-25 — prune orphaned built-ins (opt-in)
- New `$prune` param (default false) on `importTemplatesFromDirectory()`.
  **Explicit ingest only** (gallery action + CLI pass `true`); the silent
  auto-ingest on update calls it bare → **an update never deletes a
  dashboard** (user's call).
- Safe because `user_id=0` is exclusively built-ins (`saveDashboardTemplate`
  always uses a real user_id). Guards: `default=0` (never delete the active
  default), non-empty shipped set (no wipe-all on a missing dir), uuid
  collected per parseable manifest.
- **Discovered latent bug** (Discovered-work section): the `Dashboard` model
  declares `belongsTo Organisation` with `foreignKey => 'org_id'`, but there
  is **no `org_id` column** (it's `restrict_to_org_id`). `deleteAll()` /
  `updateAll()` auto-join on the phantom column and **crash**
  (`Unknown column 'Dashboard.org_id' in 'ON'`). Workaround everywhere this
  session: collect ids via `find` (recursive=-1, no join) + per-id
  `delete()`/`saveField()`.

### DD-26 — Analyst as fallback default when the instance has none
- Manifest may declare `"default_fallback": true` (only **Analyst** does).
  After ingest, if `COUNT(default=1)==0`, that candidate is promoted to the
  global default (via `saveField`). Result gains `'promoted_default'`.
- **Fires on every ingest — explicit + the silent auto-ingest** (user's
  "Both" call). Only fills an empty slot — never overrides an admin's
  default. Surfaced via CLI `[DEFAULT]` line, controller log/flash, SYSTEM
  log.
- **Refines DD-22's blanket `default=0`:** `__importTemplate` now
  **preserves an existing row's `default` on upsert** (forces 0 only on
  insert of a new row), so an admin's promotion of a built-in survives
  re-ingest instead of being demoted-then-flipped-to-Analyst.

### DD-27 — `__unsetPreviousDefault()` hardened
- The single-default invariant is **soft** (no DB constraint on
  `dashboards.default`). The helper demoted only the *first* `default=1`
  row; now it demotes **every** one when a new default is saved.
- Loop + `saveField` by id (not `updateAll` — phantom `org_id` join).
  **`$this->id` saved/restored** around the loop so the demotion never
  contaminates the create-vs-update state of the `save()`
  `saveDashboardTemplate` runs next (create path needs `$this->id` false to
  INSERT).

## Open follow-ups (in the progress tracker / DD trail; none blocking)

- **Default templates — live non-admin ACL check** (browser two-user;
  deferred — no non-admin API key, advanced_authkeys on).
- **Dashboard `belongsTo Organisation` phantom `org_id`** — proper fix is
  `foreignKey => 'restrict_to_org_id'` (or drop the unused assoc); see
  Discovered work. Pre-existing; low reach.
- **Regenerate `asn-country.json` on mmdb update** is now wired (DD-23) —
  but `db_schema.json`'s `db_version` still syncs only at `preRelease`
  (unchanged MISP behaviour; not a bug).
- **DD-11 ACL-enforced switchable geo widget path**; **org/COVID maps
  palette opt-in** (projection already covered by DD-17).
- More new widget types / features — user may enumerate.
- **Phase 6 merge — the USER does this, not us.**

## Live test instance (verified up this session)

- URL `http://localhost:5007/dashboards` (302 without a session).
  Admin user id 1 (`admin@admin.test`), pw `Password12345`, Overmind theme.
  Admin API key `dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC`.
- DB: `mysql -u misp -pPassword1234 misp`. Redis: `redis-cli -n 13`.
- **State after this session:** `db_version=151`; built-ins #12 Administrator
  / #13 Analyst / #14 Community (`user_id=0`); **#13 Analyst is the global
  default** (the DD-26 fallback, left set on the dev box). One `default=1`
  row total. `maxminddb 3.1.1` was installed into `venv/` to test DD-23.

### Reusable verification recipes
```bash
# Ingest built-ins (explicit → prunes + promotes fallback). Idempotent.
app/Console/cake Dashboard importDefaultTemplates
# Regenerate asn-country.json (needs maxminddb in MISP.python_bin venv):
app/Console/cake Admin updateAsnCountryMap
# Built-in rows + which is default:
mysql -u misp -pPassword1234 misp -e \
  "SELECT id,name,user_id,\`default\` FROM dashboards WHERE user_id=0;"
# Drive a migration step directly (updateMISP is public; bypasses the
# osuser guard on `cake Admin runUpdates`): a throwaway AppShell calling
# ClassRegistry::init('Dashboard')->updateMISP(<n>) — delete it after.
# NB: Dashboard updateAll/deleteAll CRASH (phantom org_id) — use find+save.
```

## Convention reminders

- **NEW — context budget: keep sessions within the first ~20%**, warn
  aggressively as usage nears 20%, at task boundaries
  (`feedback_context_threshold_warning` memory; supersedes the old 75%).
- **Commit per progress-tracker task; never `git add -A`; explicit
  `git add` + `git status --short`; sign (`%G?`=U).** GPG warm all session
  (`git commit -S -F /tmp/msg`).
- **The Edit/Write tools flip a file's group to `iglocska:iglocska`** —
  `chgrp www-data` every edited web-served/app file afterward (siblings are
  `iglocska:www-data`). Test/throwaway files stay `iglocska:iglocska`.
- **New `app/files/` data dir → add a `.gitignore` `!` exception.**
- **Record meaningful decisions as DD-NN + a PRD §15 row.** Refinements get
  a new DD that supersedes the old aspect (DD-26 refines DD-22; DD-27 closes
  DD-26's gap) — never an in-place edit of the superseded DD.
- **Render-kind glyph rule** (CLAUDE.md): only new `$render` values need a
  glyph. Nothing this session added one.
- User wants **rigorous pushback + genuine forks via AskUserQuestion**, and
  when they question a premise, **re-verify rather than defend** (this
  session: the "no geo-open update job" premise correction; the auto-vs-
  explicit forks for ingest/prune/promote).

## Quick-start for the next session

1. Read `dashboard-prd.md` §15 + `dashboard-design-decisions.md` DD-23..27 +
   this file. Skim the progress tracker's post-5.5 sections.
2. Verify instance: `curl -s http://localhost:5007/dashboards -o /dev/null
   -w "%{http_code}\n"` → 302.
3. **No task is mandated.** The default-template lifecycle (ingest / prune /
   fallback default / single-default hardening) and the asn-country regen
   are done. The user may pick a follow-up above, a new widget/feature, or
   the merge.
4. **Gotchas to carry:** Dashboard `updateAll`/`deleteAll` crash (phantom
   `org_id`) — use find+per-id save/delete. `default` single-invariant is
   soft (DD-27). Ingest paths: silent auto-ingest = additive + fallback-
   promote only (no prune); explicit admin/CLI = prune + promote. The Edit
   tool flips file group — `chgrp www-data` after edits.
5. **Watch context aggressively — wrap up + refresh this handoff before
   20%.** Do NOT start the merge — the user does that.
