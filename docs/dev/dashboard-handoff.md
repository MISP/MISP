# Dashboard v2 — Session handoff (2026-05-26 — board-widget caching + default dashboard templates)

Fifteenth session. Authoritative state lives in:

- `dashboard-prd.md` — spec (binding decisions table §15, now incl.
  DD-16..DD-22).
- `dashboard-progress.md` — task state. **Phase 5 + 5.5 closed; Phase 6
  (merge) is the only tracked phase left.** Post-5.5 work continues in
  the "New widget types" and "**New features**" sections; both new
  features this session (caching-the-board, default templates) are now
  closed there.
- `dashboard-design-decisions.md` — DD-01..DD-22 (DD-21, DD-22 new this
  session).

This file is the bridge: ephemeral session context. Replace as work
progresses.

## TL;DR — this session (5 signed commits, all `%G?`=U, none merged)

Two user-driven features, each planned + fork-surfaced before code, one
task at a time:

```
15b8d35d1 new WidgetCache per-user key scope — opt-in cache_scope='user' (DD-21)
813648b55 new cache the 5 user-independent board widgets at 1h (DD-20)
f3abd0900 new cache the 3 ACL-scoped board widgets at 1h, per-user key (DD-21)
1982f415d new default dashboard templates — file-shipped, on-demand ingest (DD-22)
037244035 new author analyst/admin/community starter layouts; drop Overview (DD-22)
```

**The USER does the merge — do NOT open the PR or merge.**

## What landed (reuse these facts)

### Board-widget caching (DD-21 extends DD-20) — the ACL-leak gate
- **The rule, learned the hard way:** `WidgetCache`'s default key is
  **config-only, not per-user**. It is safe **only** when a widget's
  `handler()` output does NOT depend on the requesting user. Before
  adding `cache_duration` to any widget, **read its `handler()`** and
  check for `$user` scoping (`filterEventIds($user)`, `perm_site_admin`
  branches, `org_id` conditions, role-based redaction). User-dependent
  output + a config-only shared cache = one viewer's data served to
  another once multi-user.
- **DD-21 mechanism:** a widget that IS user-dependent declares
  `public $cache_scope = 'user';` → the key gains a `u<id>:` segment
  (`<path>:u<id>:<sha256(config)>`). Default (absent) = `'global'` =
  DD-20 config-only key, unchanged. **Fail-safe:** a `'user'`-scoped
  widget rendered without a usable user id is NOT cached (live compute
  before any Redis touch). `WidgetCache::remember()`/`::key()` now take
  an optional trailing `$user`; `DashboardsController::renderWidget`
  passes `$this->Auth->user()` through. `NON_DATA_KEYS` (`alias`,
  `refresh_delay`) are still stripped from the hash (DD-20).
- **The board, classified + cached at 1h:**
  - **Global key (user-independent):** `UsageDataWidget`,
    `OrgContributionToplistWidget`, `UserContributionToplistWidget`
    (its `checkPermissions()` gates *visibility* in `loadWidget` before
    the cache; content is the same global toplist for all permitted
    viewers), `OrganisationMapWidget`, `ThreatActorCountryMapWidget`.
    `AttributeGeoMapWidget` was already cached (DD-19/20).
  - **Per-user key (`cache_scope='user'`):** `TrendingAttributesWidget`
    (perm_site_admin/org_id branch), `TrendingTagsWidget`
    (`filterEventIds($user)`), `NewUsersWidget` (email redaction by role).
  - **Excluded per the user** (left live): `NewOrgsWidget` ("Latest new
    members"), `APIActivityWidget`, `LoginsWidget`. ("Event stream" was
    named but isn't on the admin board.)
- `WidgetCacheTest` is 14/14 (PHPUnit **8.5** — `assertRegExp`, not
  `assertMatchesRegularExpression`).

### Default (built-in) dashboard templates (DD-22)
- **The `dashboards` table IS the template store** (`uuid`, `name`,
  `description`, `value` = layout JSON, `default` = the *single* global
  default board, `selectable` = visible to others, `user_id` = owner,
  `restrict_to_org_id`/`_role_id`/`_permission_flag` = per-template ACL).
  **No `version` column** — that's why re-ingest is overwrite-by-uuid.
- **Ship + ingest:** manifests at
  `app/files/dashboard-templates/<slug>/template.json` (`uuid` fixed,
  `name`, `description`, `selectable`, optional `restrict_to_*`, `value`
  = widget-instance array). `Dashboard::importTemplatesFromDirectory()`
  globs them, `__importTemplate()` upserts on the fixed `uuid` (forces
  `user_id=0`, `selectable` default 1, `default=0`; **no version gate**,
  idempotent — re-run keeps the same row). Read-only reference data, so
  overwrite loses nothing user-authored (a user's board is a separate
  `UserSetting`; clones are separate rows).
- **Triggers (both site-admin):** `DashboardsController::
  importDefaultTemplates()` (POST; ACL `array()` = site-admin) surfaced
  as a gallery "Import starter templates" button; **and** a new
  `DashboardShell` → `app/Console/cake Dashboard importDefaultTemplates`.
- **Gallery:** built-ins (`user_id===0`) get a new **"Starter templates"**
  bucket (`listTemplates` routes them there before mine/featured/shared;
  view renders the section + the admin import button). No ACL/schema work
  needed — the existing `listTemplates`/`getDashboardTemplate` ACL already
  supports an instance-wide `selectable` template, and
  `restrict_to_permission_flag='perm_site_admin'` scopes one to admins.
- **`.gitignore` gotcha:** `app/files/*` is ignore-all; the shipped data
  dirs are submodules with `!` exceptions. `dashboard-templates` is a
  **plain in-repo dir** (not a submodule), so it needed its own
  `!/app/files/dashboard-templates` + `/*` exception pair to be tracked.
- **Three layouts shipped** (Overview sample built in 1982f415d was then
  removed): **Analyst** (TrendingAttributes/Tags, Attribute+ThreatActor
  geo maps, RecentSightings; open), **Administrator** (UsageData,
  NewUsers, AuthenticationFailure, MispStatus, Logins, APIActivity;
  `restrict_to_permission_flag='perm_site_admin'`), **Community**
  (OrganisationMap, UsageData, Org/UserContributionToplist, OrgsEvolution,
  SharingGraph; open). Each widget carries `config.alias` + `{x,y,w,h}`.
- **Apply path is unchanged:** `resetFromTemplate(uuid)` →
  `getDashboardTemplate` (ACL) → `LayoutFixup::applyReadFixups` (mints
  instance_ids, normalises positions) → writes the user's board.

## Open follow-ups (in the progress tracker; none blocking)

- **Default templates — live non-admin ACL check.** That the
  Administrator starter is hidden from non-admins relies on the unchanged
  `restrict_to_permission_flag` query; not verified with a live non-admin
  (no non-admin API key — `advanced_authkeys` is on, minting one means
  replicating MISP's hash scheme + state mutation). A browser two-user
  check is the gold standard, deferred to the user.
- **Default templates — auto-ingest on MISP update/install.** Currently
  on-demand only (admin button / CLI), matching "ingest on demand". Wiring
  into the update job is a follow-up.
- **Default templates — prune orphaned built-ins.** Re-ingest doesn't
  delete rows whose files were removed (same as warninglists); the Overview
  removal was handled manually (`DELETE … WHERE uuid=…`).
- **Regenerate `asn-country.json` on mmdb update** (DD-12 follow-up).
- **ACL-enforced switchable path** for the geo widget (DD-11 follow-up).
- **org/COVID maps palette opt-in** (projection already covered by DD-17).
- More new widget types / features — user may enumerate.
- **Phase 6 merge — the USER does this, not us.**

## Live test instance (verified up this session)

- URL `http://localhost:5007/dashboards` (302 without a session);
  `http://localhost:5007/dashboards/listTemplates` = the gallery.
- Admin user id 1 (`admin@admin.test`), pw `Password12345`,
  **on the Overmind theme**. Its saved board has 15 widgets (the ones the
  caching work classified). Built-in templates now live as rows #12
  Administrator / #13 Analyst / #14 Community (`user_id=0`).
- Admin API key `dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC`.
- DB: `mysql -u misp -pPassword1234 misp`. Redis: `redis-cli -n 13`.
- Non-admin users exist (e.g. id 185 `user@test.test`, org 1) but have no
  usable API key under `advanced_authkeys`.

### Reusable verification recipes
```bash
KEY=dHVxEx4WhIwRdS6QDVsBmW9PE6pOkmgIH1FPQWiC
# Cache keys (global = no u-segment; per-user = u<id>:):
redis-cli -n 13 KEYS 'misp:*_cache*'          # use KEYS in scripts, not --scan
# Render a widget (creates/reads its cache key):
curl -s -X POST -H "Authorization: $KEY" -H "Accept: application/json" \
  --data-urlencode "widget=<Name>Widget" --data-urlencode "config={}" \
  http://localhost:5007/dashboards/renderWidget
# Ingest built-in templates (idempotent):
app/Console/cake Dashboard importDefaultTemplates
mysql -u misp -pPassword1234 misp -e \
  "SELECT id,name,user_id,selectable,restrict_to_permission_flag FROM dashboards WHERE user_id=0;"
# Session HTML (gallery / board) needs the login dance (reference-misp-
# login-dance memory): GET .../dashboards/listTemplates, grep the section.
```

## Convention reminders

- **Commit per progress-tracker task; never `git add -A`; explicit
  `git add` + `git status --short` first; sign (`%G?`=U).** GPG stayed
  warm all session (`git commit -S -F /tmp/msg`).
- **New web-served files: `chgrp www-data`** (widget/helper/shell classes,
  shipped `app/files/` data — these inherit www-data via setgid on
  `app/files`, but verify). **Test files stay `iglocska:iglocska`**.
- **New `app/files/` data dir → add a `.gitignore` `!` exception** (the
  dir is ignored by `/app/files/*` otherwise; see DD-22).
- **Hard-refresh after CSS/JS edits** (`?v=185` buster doesn't bump
  per-file). PHP/PHP-template/manifest changes need only a reload.
- **Record meaningful decisions as DD-NN + a PRD §15 row.** Overturned
  decisions get a follow-up DD, never an in-place edit (DD-21 extends
  DD-20; DD-22 is new).
- **Render-kind glyph rule** (CLAUDE.md): only new `$render` values need a
  glyph. Nothing this session added a render kind.
- User wants **rigorous pushback + genuine forks via AskUserQuestion**
  (this session: the ACL-leak audit that split the board into safe/unsafe
  widgets; the 3 template forks). When the user questions a premise,
  re-verify rather than defend.

## Quick-start for the next session

1. Read `dashboard-prd.md` §15 + `dashboard-design-decisions.md` DD-21,
   DD-22 + this file. Skim `dashboard-progress.md` post-5.5 sections.
2. Verify instance: `curl -s http://localhost:5007/dashboards -o /dev/null
   -w "%{http_code}\n"` → 302.
3. **No task is mandated.** Both enumerated post-5.5 features (board
   caching, default templates) are done. The user may pick a follow-up
   above, a new widget/feature, or the merge.
4. If touching `WidgetCache`/caching: re-read the ACL-leak gate above
   (config-only vs `cache_scope='user'`) — it's the easy-to-trip rule.
   If touching the templates: the store is the `dashboards` table (no
   version column → overwrite-by-uuid), built-ins are `user_id=0`, and
   ingest doesn't prune.
5. Do NOT start the merge — the user does that.
