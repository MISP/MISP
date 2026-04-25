# Event Template Library — Product Requirements Document

**Status:** Draft v0.1 (for discussion, not yet approved)
**Author:** Andras Iklody + Claude
**Target branch:** `templating` (or a fresh `template-library` branched off it once Phase 0 closes)
**Depends on:** event-templating v1 (Phases 0–4 of [`event-templating-prd.md`](event-templating-prd.md)) — must be merged or live on the same branch.
**Implementation tracker:** [`event-template-library-progress.md`](event-template-library-progress.md) — live checklist of tasks per phase. See §13 for the phase summary; task-level detail lives in the tracker.

---

## 1. Context and problem

Event templating v1 (just landed on branch `templating`) gives every MISP
instance the *machinery* to author templates, but ships zero content.
Operators get an empty index on first boot and have to either build a
template from scratch in the visual builder or import one a colleague
sent them.

Two consequences:

- Onboarding stalls. A new operator who clicks "Event Templates" sees
  the empty-state we just polished, with no actionable starting point.
- Common incident playbooks (spearphishing triage, ransomware,
  credential exposure) get re-authored from scratch on every instance,
  diverging in shape and quality.

Other MISP content categories solved this by shipping a **shared,
versioned, community-maintained content repo**, submoduled into MISP
core. `misp-objects`, `misp-galaxy`, `misp-taxonomies`, and
`misp-warninglists` all follow the same pattern: a separate GitHub
repo under the MISP org, JSON documents validated by a schema living
alongside the data, and a loader inside MISP core that upserts the
content into the DB on operator request.

This PRD applies the same pattern to event templates.

## 2. Goals / non-goals

### Goals

- **G1.** Stand up `MISP/misp-event-templates` as a standalone repo
  with the same shape and tooling conventions as `misp-objects` /
  `misp-galaxy`: README, CONTRIBUTE, LICENSE, JSON schema,
  per-template directories, validation scripts.
- **G2.** Ship a starter catalogue covering the most common SOC
  playbooks so a fresh MISP install has usable content out of the box.
- **G3.** Wire MISP core to the new submodule: loader, REST endpoint,
  UI button on the event-templates index, both themes.
- **G4.** Define an upgrade story for when an upstream template bumps
  versions and the operator has either left the local copy alone or
  edited it locally.
- **G5.** Keep the standalone repo independently usable: someone with
  a different threat-intel platform can still fetch the JSON and use
  it as content reference, exactly like `misp-objects` is consumed
  outside MISP core.

### Non-goals (v1 of this project)

- **No automated continuous sync** between operator MISP instances and
  the upstream library. The operator triggers updates explicitly,
  matching how `misp-objects` and friends work.
- **No template marketplace** with ratings, comments, or per-template
  authorship metadata beyond a top-level `authors` field. That belongs
  in a future phase or a separate project.
- **No template editor in the standalone repo.** Authors edit JSON in
  their text editor (or build in MISP and export the JSON to commit).
  The MISP-core builder is the authoring UI.
- **No cross-instance template sync via the MISP sync graph.** That
  remains future work as listed in `event-templating-prd.md` §15.
- **No legacy-templates copy tool integration.** Phase 5 of
  `event-templating-prd.md` covers copying *operator-local* legacy
  templates into the v2 system; the library project is about
  *upstream-curated* content. Different problem; doesn't share scope.

## 3. Personas and key user journeys

### Personas

- **Library author** — community member or MISP project member who
  contributes a template to `MISP/misp-event-templates` via PR. Knows
  MISP, knows the targeted incident type, willing to write JSON in
  their editor.
- **MISP operator (site admin)** — installs MISP, runs `git submodule
  update`, clicks the "Update from library" button. Decides whether
  to enable each library template for their organisation.
- **Template user** — same as in `event-templating-prd.md`. Cares
  only about which templates appear in the picker, not where they
  came from.

### Journeys

**J1 — A library author contributes a template.** Clones
`MISP/misp-event-templates`, copies an existing folder under
`templates/` as a starting point, edits `definition.json` (changes
uuid, name, restructures), runs `validate_all.sh` locally, opens a
PR. Reviewers verify the schema validates, the targeted incident
type is genuinely common, and there's no overlap with an existing
template. Merged.

**J2 — An operator updates the library.** After `git pull` +
`git submodule update`, they hit **Update from library** on the
event-templates index. The loader walks `app/files/misp-event-templates/templates/`,
validates each `definition.json`, and upserts by uuid+version.
A summary report shows what was newly installed, what was upgraded,
and what was skipped (operator-edited rows where the upstream version
also bumped — see §5.3 upgrade semantics). Operators flip the
`active` flag to make a template visible to template users.

**J3 — A new operator boots a fresh MISP.** First entry into the
event-templates index triggers an automatic library check, just like
`ObjectTemplate::checkAndUpdate` does for object templates. The user
sees the catalogue inactive-by-default, ready to be enabled.

## 4. Terminology

- **Library** — the standalone JSON-document repo and its checked-in
  templates.
- **Library template** — a template whose origin is a `definition.json`
  inside the library, identified by its uuid which matches between the
  on-disk JSON and the `event_templates` row.
- **Local template** — a template authored on the operator's MISP
  instance, either via the builder or imported once. No corresponding
  on-disk JSON in the library.
- **Operator-edited library template** — a library template that was
  imported, then subsequently edited on the operator's instance. Has a
  matching uuid in the library but a different definition.

## 5. Functional requirements

### 5.1 Library repository structure

```
misp-event-templates/
├── README.md                       # what's here, how to use it
├── CONTRIBUTE.md                   # how to contribute a template
├── LICENSE.md                      # CC0, matching misp-galaxy / misp-objects
├── schema_event_template.json      # mirror of app/files/schemas/event-template-v1.schema.json
├── templates/
│   ├── spearphishing-email/
│   │   └── definition.json
│   ├── ransomware-incident/
│   │   └── definition.json
│   └── ...
├── validate_all.sh                 # walks templates/ and validates each
└── jq_all_the_things.sh            # canonicalise JSON formatting
```

- **F1.1** Per-template directory under `templates/` rather than a
  flat-file layout. Matches `misp-objects/objects/<name>/definition.json`.
  Leaves room for per-template README, screenshots, example events,
  or test fixtures later without a layout change.
- **F1.2** `schema_event_template.json` is a mirror of MISP core's
  `app/files/schemas/event-template-v1.schema.json`. The library repo
  is the schema of record for users who consume the JSON without
  MISP; MISP core's copy is what the running instance validates
  against. They drift apart only across MISP minor versions; a
  `schema_version` field in every `definition.json` plus a
  `compatible_misp_version` field at the top level lets the loader
  refuse incompatible templates with a clear error.
- **F1.3** Every `definition.json` is a valid v1 event template per
  `event-templating-prd.md` §7, plus library-specific top-level
  fields:
  - `library_metadata.compatible_misp_version` — minimum MISP version.
  - `library_metadata.authors` — array of `{name, contact?}`.
  - `library_metadata.tags` — free-form keywords for catalogue
    filtering (e.g. `["incident-response", "email"]`).
- **F1.4** `validate_all.sh` walks `templates/*/definition.json`,
  runs each through a jsonschema CLI against
  `schema_event_template.json`, plus a uniqueness check across uuids
  and template names. Exit non-zero on any failure. Suitable for CI.
- **F1.5** `jq_all_the_things.sh` canonicalises every JSON file
  under `templates/` (sort keys, fixed indent). Run as a pre-commit
  by contributors so diffs stay readable.

### 5.2 MISP core integration

- **F2.1** The repo is registered as a submodule at
  `app/files/misp-event-templates/` in MISP core's `.gitmodules`,
  pointing at the library repo's `main` branch. Same shape as the
  existing `misp-objects` registration.
- **F2.2** New `EventTemplate::updateFromLibrary($user, $force = false)`
  method on the existing `EventTemplate` model. Walks
  `app/files/misp-event-templates/templates/*/definition.json`, runs
  each through the existing `EventTemplateValidator`, and upserts
  rows by uuid. Returns a structured summary
  `['installed' => [...], 'upgraded' => [...], 'skipped' => [...], 'failed' => [...]]`.
- **F2.3** New `EventTemplatesController::update($force = false)`
  controller action exposing the above via REST and UI:
  `POST /event_templates/update` (REST, returns the summary as JSON)
  and a UI button on the event-templates index that triggers the
  same path and renders the summary.
- **F2.4** The controller action is gated on site-admin. Library
  updates affect all orgs on the instance; only site admin should
  trigger them.
- **F2.5** First-touch auto-update — if `event_templates` is empty
  on the first hit of the index page, run a silent update from the
  library. Same pattern as `ObjectTemplate::checkAndUpdate`.

### 5.3 Update / upgrade semantics

The interesting case is when an upstream template bumps versions
*and* the operator has edited the local copy.

- **F3.1** Every library template carries a `version` integer. The
  loader compares it to the local `event_templates.version`.
- **F3.2** Operator-edit detection is by content hash of the
  decoded definition (excluding ownership envelope: org_id,
  creator_user_id, created, modified, active). When the local hash
  differs from the library hash for the prior version (computed by
  re-validating the in-repo previous version, or stored in the
  template row as `library_synced_hash`), the loader treats the row
  as operator-edited.
- **F3.3** Three update behaviours per row, decided by content
  comparison:
  - **install** — uuid not present locally → insert.
  - **upgrade-clean** — present locally, library version higher,
    local hash matches the library's prior-version hash (i.e. no
    operator edits) → overwrite.
  - **skip-edited** — present locally, library version higher,
    operator-edited → skip with a clear summary entry. Operator must
    pass `?force=1` to overwrite, or use the existing
    `event_templates/import?mode=duplicate_as_new` flow to take the
    upstream copy as a fresh row alongside their edits.
- **F3.4** No silent deletes. Templates removed upstream are *not*
  removed from the operator's DB. The summary report flags them as
  "no longer in library" so the operator can decide.
- **F3.5** Library imports default to `active = 0` and
  `distribution = 1`. Operator manually flips `active` per template
  to expose it to template users. Defaults documented in §15
  resolutions.

### 5.4 Coexistence with the existing import flow

- **F4.1** Library updates and one-off JSON imports both round-trip
  through the same `EventTemplateImporter` validation. No duplicate
  validation logic.
- **F4.2** A template imported once via `event_templates/import`
  (manual upload of a JSON file) does not become a library template
  unless it happens to share a uuid with one already in the library.
  Same model row, but the `library_synced_hash` column is null until
  the next library update reconciles them.
- **F4.3** The user-facing event-templates index distinguishes
  library-sourced rows from local rows via a new column or badge
  (e.g. an icon on the row when `library_synced_hash IS NOT NULL`).
  No functional difference for template users — only operators care.

## 6. Data model changes

A single new column on `event_templates`:

```sql
ALTER TABLE event_templates
  ADD COLUMN library_synced_hash VARCHAR(64) NULL DEFAULT NULL
  AFTER definition;
```

- `NULL` — local template, never reconciled with the library.
- `<sha256>` — last library hash this row was reconciled to.
  Compared on the next update to detect operator edits.

No other schema changes. The `version` column already exists per
event-templating-prd.md §6.2 and is reused.

## 7. JSON schema additions

The library schema extends the core schema with one optional top-level
key:

```jsonc
{
  "library_metadata": {
    "compatible_misp_version": "2.5.0",
    "authors": [
      {"name": "MISP Project", "contact": "info@misp-project.org"}
    ],
    "tags": ["incident-response", "email", "phishing"]
  },
  "schema_version": 1,
  "uuid": "...",
  // ... rest as per event-templating-prd.md §7
}
```

`library_metadata` is ignored when the JSON is imported via the
non-library flow. The library loader uses it for compatibility
gating and the catalogue browser (future polish).

## 8. Permissions

- **Update from library** (REST + UI) — site admin only. Affects
  all orgs.
- **Read library templates after install** — same rules as any
  event template, per `event-templating-prd.md` §8 (org + community
  visibility).

## 9. REST API

| Method | Path | Description |
|---|---|---|
| `POST` | `/event_templates/update` | Walk the library, run the upsert, return the summary. Site admin. Optional `?force=1` to override skip-edited. |
| `GET` | `/event_templates/library_status` | Returns a structured diff between the on-disk library and the DB without applying any change. Useful for dry-run / status views. |

The existing `/event_templates/import` endpoint stays as-is for
one-off uploads that don't go through the library.

## 10. UI / UX

### 10.1 Index toolbar

Both themes get a new "Update from library" button next to the
existing Import button on the event-templates index. Site admins
only — gated on the same ACL the REST endpoint uses.

### 10.2 Update result page

Renders the structured summary with sections for installed /
upgraded / skipped / failed / no-longer-upstream. Each row is
linkable to the template's view page. Summary copy explains the
skip-edited semantics so the operator understands what to do next.

### 10.3 Library badge on index rows

Templates with a non-null `library_synced_hash` get a small badge
or icon on the index — same visual treatment as MISP's existing
"system tag" indicators. No behavioural difference.

### 10.4 First-touch silent update

If `event_templates` is empty on the operator's first visit to the
index, run a silent library update before rendering. Surface a
small flash message ("Loaded N templates from the library") so the
operator notices what happened. Matches `ObjectTemplate::checkAndUpdate`.

## 11. Library / tech choices

- **Submodule branch:** `main` of `MISP/misp-event-templates`, same
  as `misp-objects` and `misp-galaxy`.
- **License:** CC0, same as the sibling content repos. Templates are
  declarations, not creative work; permissive licensing maximises
  community contribution.
- **Validation tooling:** standard `jq` + `python -m jsonschema` (or
  `ajv-cli` if jsonschema-cli is dropped as a dep), invoked from
  `validate_all.sh`. Same approach as the sibling repos.
- **CI:** GitHub Actions on the standalone repo. PR fails if
  `validate_all.sh` exits non-zero. No deploy step — this repo just
  sits there.

## 12. Coexistence with the existing import flow

The library mechanism is **additive** to the existing
`/event_templates/import` endpoint. Operators can:

- Update from the library to pull the curated catalogue.
- Import a one-off JSON file (e.g. shared by a peer org via Slack).
- Both, freely. The two paths never conflict because uuids are
  unique and the importer's `mode` (fail / overwrite /
  duplicate_as_new) handles collision the same way regardless of
  origin.

## 13. Phased delivery plan

High-level phases below. **Task-level breakdown lives in
[`event-template-library-progress.md`](event-template-library-progress.md).**

| Phase | Scope | Exit criteria |
|---|---|---|
| **0 — Spec** | This PRD approved, four open questions in §15 closed, schema mirror plan locked. | Sign-off to build. |
| **1 — Repo** | Stand up `MISP/misp-event-templates`: README, CONTRIBUTE, LICENSE, schema mirror, validate_all.sh, jq_all_the_things.sh, two reference templates. CI green on the repo. | Repo public, CI passing, two templates validate. |
| **2 — Loader** | `EventTemplate::updateFromLibrary`, `EventTemplatesController::update`, REST endpoints, hash-based edit detection, `library_synced_hash` migration. Integration tests. | Loader works end to end against a checked-out submodule on a real DB. |
| **3 — UI** | Index toolbar button (both themes), update result page (both themes), library badge on rows (both themes), first-touch silent update. | Operator can drive the full flow from the UI on both themes. |
| **4 — Catalogue** | Grow the standalone repo to the seven-template starter set (see §15 resolution). Each template peer-reviewed. | Seven templates merged into the library repo and round-tripped through MISP. |
| **5 — Docs** | Library README, CONTRIBUTE.md, MISP-side admin docs explaining the update flow, public release notes. | Operator can find their way through the flow without asking us. |

Phases 1–4 are the v1 shipping target. Phase 5 is concurrent polish.
Phases run **strictly sequentially**, ralph-loop driven, one task at
a time. No parallel code work. Same protocol as the
event-templating workflow.

## 14. Out of scope / future work

- **Continuous sync.** Operators trigger updates explicitly. No
  cron, no auto-pull.
- **Template marketplace.** Ratings, comments, multi-author
  curation. Belongs in a separate project if ever undertaken.
- **In-MISP catalogue browser.** Browsing the on-disk library
  before importing — discoverable as an inactive list with a "Pull
  this one" action. Useful but not blocking; deferred.
- **Per-template translations.** Library templates ship in English;
  i18n is future work.
- **Template version diff UI.** Showing what changed between
  v3 and v4 of an upstream template. Computable from two snapshots;
  build it when the catalogue is large enough to need it.
- **Cross-instance sync of library templates** via the MISP sync
  graph. Overlaps with the broader cross-instance template sync
  noted in `event-templating-prd.md` §15.

## 15. Open questions

Four design decisions need closure before Phase 0 sign-off. Pre-filled
with the recommended default; flip any of them and resolve here.

1. **Default `active` for library-imported templates** — *Recommended:
   `0` (inactive)*. Operators get agency before community-authored
   templates show up in their team's picker. Argument for `1`: zero
   manual step on first install. Argument for `0`: predictable
   behaviour, no surprise rows leaking into a team's workflow.
2. **Default `distribution` for library-imported templates** —
   *Recommended: `1` (community)*. Library templates target community
   use by definition; org-only would be surprising for shipped
   content. Argument for `0`: stay private until operator decides.
3. **Upgrade behaviour when upstream version bumps and operator has
   edited locally** — *Recommended: refuse + require explicit
   `force=1`*. Mirrors the import endpoint's existing `mode`
   semantics. Argument for silent-overwrite: matches how object
   templates work. Argument for refuse: event templates are far more
   likely to be operator-customised; silent overwrite would lose work.
4. **First batch of starter templates** — *Recommended: spearphishing
   email, ransomware incident, credential exposure, suspicious-domain
   triage, malware-sample submission, vulnerability disclosure,
   supply-chain compromise*. Seven covers ~80% of recurring SOC
   playbooks; community can grow it. Argument to start smaller (just
   2–3): faster Phase 1, lets us validate the loader before investing
   in catalogue depth. Argument to start with seven: makes the
   release notes meaningful and gives operators a usable catalogue
   from day one.

*Resolved 2026-04-25 (scoping):* heavyweight option chosen — new PRD,
new tracker, six-phase delivery, mirroring the event-templating v1
workflow. Branch off `templating` once Phase 0 closes.
