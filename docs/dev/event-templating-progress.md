# Event Templating v2 — Implementation Progress

**Companion to:** [`event-templating-prd.md`](event-templating-prd.md).
**Purpose:** live checklist of implementation tasks. The PRD is the *spec*; this file is the *tracker*. Check items off as they land on branch `templating`. When a phase is complete, set its status line and the phase-complete checkbox.

## Legend

- `- [ ]` — not started
- `- [~]` — in progress (replace the space with `~` manually)
- `- [x]` — complete
- `⛔` — blocked (append reason inline)

Each task is sized to be a single PR or a small cluster of commits. **Tasks and phases run strictly sequentially** — one item at a time, top to bottom within a phase, and one phase at a time. Implementation is driven by a ralph loop; no parallel code work. (Research and information lookups during a task may still be parallelised; the constraint applies to writing code.)

---

## Commit protocol

This workflow runs inside a ralph loop and will produce many commits. To keep the history readable and the feature reviewable, every completed task follows the protocol below. **This protocol is the user's pre-authorisation to commit during the event-templating workflow** — no per-task approval is required, provided every rule here is honoured.

### 1. One task, one commit (usually)

- The default unit of work is **one checkbox in this file → one commit**.
- If two adjacent checkboxes are tightly coupled (e.g. a migration and the model it introduces, a controller action and its route wiring) they may be combined into a single commit. Err on the side of smaller commits.
- Never batch unrelated tasks into the same commit. Never batch commits across phases.

### 2. What goes into the commit

Each commit includes:

1. The code/config/view/migration changes that implement the task.
2. The checkbox flipped from `- [ ]` (or `- [~]`) to `- [x]` in this file.
3. When a phase-capstone task is being closed, update that phase's `Status:` line in this file as well.
4. Any tests introduced or updated for the task.
5. Nothing else. No unrelated cleanups, no opportunistic refactors, no "while I was here" edits. Surface those as new tasks if they need doing.

### 3. Commit message format

Follow MISP's existing `gitchangelog` convention (see `CLAUDE.md`):

```
new: [event-template] Short subject line describing the change

Longer body explaining *why* this change and what it enables.
Reference the PRD section and the progress-tracker checkbox so
reviewers can navigate to the spec.

PRD: docs/dev/event-templating-prd.md §<N>.<N>
Task: docs/dev/event-templating-progress.md — Phase <N> / <task title>

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
```

- **Prefix:** `new:` for new functionality, `fix:` for bug fixes, `chg:` for refactors/internal changes. Spec/doc-only commits that advance the tracker use `chg:`.
- **Category tag:** `[event-template]` on every commit in this workflow. Sub-scope in parentheses is fine when useful (e.g. `[event-template(builder)]`, `[event-template(migrations)]`).
- **Subject:** ≤ 72 chars, imperative mood.
- **Body:** always include the PRD and tracker references shown above. This is the primary navigation aid for reviewers — do not omit.
- **Trailer:** the `Co-Authored-By: Claude Opus 4.7 (1M context)` line is mandatory per the repo's commit rules.

### 4. Pre-commit checks

Before running `git commit`:

- Lint: `./app/Vendor/bin/parallel-lint --exclude app/Lib/cakephp/ --exclude app/Vendor/ -e php,ctp app/` passes with zero errors.
- If the task introduced or touched PHPUnit tests: `./app/Vendor/bin/phpunit app/Test/` for the affected suite passes.
- Migrations run cleanly on a fresh schema (when applicable to the task).
- No secrets, `.env` files, large binaries, or `app/tmp/` artefacts staged.
- Staging is explicit: `git add <paths>` — never `git add -A` or `git add .`.

If any check fails, **do not commit**. Fix the root cause, re-stage, and create a new commit. Never use `--amend`, `--no-verify`, or `--no-gpg-sign` in this workflow.

### 5. What not to do

- Do not push to a remote unless explicitly asked.
- Do not open a PR unless explicitly asked.
- Do not squash or rewrite history retroactively. The linear commit log mirrors the checklist — that is intentional.
- Do not commit work for a task that is not the next unchecked item in the current phase. Sequential, top-to-bottom, one phase at a time.

### 6. Example

A commit for task 1.1 item "Migration: create `event_templates` table":

```
new: [event-template(migrations)] Add event_templates table

Introduces the storage table for v2 event templates. Schema matches
PRD §6.2 — relational envelope (id, uuid, org_id, name, active, version,
timestamps) with a MEDIUMTEXT `definition` column holding the JSON
document described in §7.

PRD: docs/dev/event-templating-prd.md §6.2
Task: docs/dev/event-templating-progress.md — Phase 1 / Migration: create `event_templates` table

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
```

Staged in this commit:
- the migration SQL / migration file,
- the progress-tracker checkbox flipped to `- [x]` for that line.

Nothing else.

---

## Phase 0 — Spec finalisation

**Status:** complete
**Exit criteria:** PRD approved; remaining open questions closed; JSON schema file drafted.

- [x] Draft PRD v0.1 (see `event-templating-prd.md`)
- [x] Library choices locked in (SortableJS, Alpine.js, server-only validation)
- [x] Terminology normalised (template creator / template user)
- [x] Field labels and help text elevated to first-class requirement
- [x] User sign-off on PRD v0.1
- [x] Close open question §16.1 — legacy UI untouched, removal out of scope for this project
- [x] Close open question §16.2 — reuse existing `perm_template` flag; no rename, no new flag
- [x] Close open question §16.3 — add `league/commonmark` composer dep, render server-side with raw-HTML disallowed
- [x] Close open question §16.4 — two distribution values (0 = org only, 1 = community); default 0
- [x] Close open question §16.5 — reuse MISP attachment limit; no per-template override
- [x] Close open question §16.6 — site admins see and can edit all templates on the instance
- [x] Close open question §16.7 — version bump + full JSON snapshot per edit; no per-field diff
- [x] Close open question §16.8 — manual `active` flag only; no cron/retention

- [x] **Phase 0 complete**

---

## Phase 1 — Backend

**Status:** complete
**Exit criteria:** every endpoint in PRD §9 functional; transactional event instantiation works end-to-end; integration tests green against a real DB.

### 1.1 Database

- [x] Migration: create `event_templates` table (schema in PRD §6.2)
- [x] Migration: create `event_template_object_dependencies` table (schema in PRD §6.2)
- [x] Migration: rename `event_templates.share_within_org` to `event_templates.distribution` (PRD §6.2, §8 — two values: 0 = org only, 1 = community)
- [x] Indexes validated (`uuid`, `org_id`, `name`, `active` on `event_templates`; `event_template_id`, `object_template_uuid` on the dependencies table)

### 1.2 JSON schema file

- [x] Create `app/files/schemas/event-template-v1.schema.json` covering everything in PRD §7
- [x] Include per-element-type subschemas (`section`, `text_block`, `attribute_field`, `object_field`, `object_field.relations[]`, `tag_field`, `galaxy_field`, `file_field`, `object_reference`)
- [x] Require non-empty `label` on every interactive element
- [x] Validate `info_template` variable grammar

### 1.3 Models

- [x] `EventTemplate` model: associations, beforeSave (regenerate dependencies, bump version), afterFind (decode JSON)
- [x] `EventTemplate::validateDefinition($definition)` — runs JSON-schema + semantic validation (§5.1 F1.9)
- [x] `EventTemplate::extractObjectDependencies($definition)` — rebuilds `event_template_object_dependencies` rows
- [x] `EventTemplateObjectDependency` model
- [x] Audit-log hooks on template CRUD (PRD §5.3 F3.4)

### 1.4 Services / libs

- [x] Add `league/commonmark` and `justinrainbow/json-schema` to `app/composer.json`. MISP's standard upgrade path does not run `composer install`; admins must run `cd app && composer install` manually after upgrading (PRD §11.2). Document pinned versions in the PR body.
- [x] Dependency-check infrastructure: `EventTemplateDependencies::missing()` + `EventTemplateDependencyMissingException`. Libs and controllers that need the deps call `requireAll()` / `requireSome()` and surface a "contact your administrator" message rather than a raw exception.
- [x] `EventTemplateMarkdownRenderer` lib: thin wrapper around `league/commonmark` configured with `html_input => strip` and `allow_unsafe_links => false`; used for template `description`, `text_block.content`, `help`, and `help_override`.
- [x] `EventTemplateValidator` lib: JSON-schema validation (server-only) + semantic checks (attribute type/category validity against `MispAttribute::typeDefinitions`, object template existence + version compat, object_reference endpoints exist, no duplicate element ids, info_template variables reference real ids). `EventTemplate::validateDefinition()` delegates to it.
- [x] `EventTemplateInstantiator` lib: transactional event creation from filled values. Inputs: decoded definition + user-submitted values + auth user. Output: `{ event_id, event_uuid }` or `EventTemplateInstantiationException` with structured errors. Rolls back on any failure; verifies post-`_add` that no attributes or objects were silently dropped before committing (PRD §5.2 F2.8/F2.10). `file_field` user input is rejected in v1 — file upload wiring lands in Phase 2 (see Phase 2.3).
- [x] `EventTemplateInfoRenderer` lib: variable substitution (`{{date}}`, `{{now}}`, `{{user}}`, `{{field:<id>}}`) with safe fallbacks
- [x] `EventTemplateExporter` / `EventTemplateImporter` libs: JSON round-trip per PRD §13. Exporter omits ownership columns (creator_user_id, org_id) — new owner is the importing user. Importer validates the envelope, runs the full `EventTemplateValidator` (structural + semantic, incl. object-template dependency check), and handles uuid collisions via `mode` option: `fail` (default), `overwrite` (preserves original ownership), `duplicate_as_new` (fresh uuid, importer's org/user).

### 1.5 Controller and routes

- [x] `EventTemplatesController` with all §9 actions: `index`, `view`, `add`, `edit`, `delete`, `duplicate`, `export`, `import`, `instantiate`, `validate_definition`
- [x] Route setup in `app/Config/routes.php` — default CakePHP conventional routing (`/event_templates/<action>/<id>`) covers all §9 endpoints; no bespoke entries required for v1
- [x] Authorisation enforced per PRD §8 on every action — role gates in `ACLComponent::$aclList['eventTemplates']`, row-scoped conditions in the controller's `__visibilityConditions()` / `__writeConditions()` helpers
- [x] REST responses use `RestResponseComponent` conventions (envelope, error shape) — `viewData` for success, `saveFailResponse` for validation/import/instantiation failures, 503 JSON envelope on missing-composer-dep guard

### 1.6 Tests

- [x] Unit tests for `EventTemplateValidator` (happy path + every failure mode) — `app/Test/EventTemplateValidatorTest.php` (21 passing + 2 documented-skipped schema gaps)
- [x] Unit tests for `InfoTemplateRenderer` — `app/Test/EventTemplateInfoRendererTest.php` (19 tests)
- [x] Unit tests for `EventTemplateInstantiator` (rollback on partial failure) — `app/Test/EventTemplateInstantiatorTest.php` covers the pre-DB failure modes (invalid definition, file_field rejection, unknown ids, mandatory-empty, multi-error aggregation); transactional rollback and post-hoc drop detection are covered by the integration suite against a live MISP
- [x] Integration tests for every REST endpoint (hitting a real DB) — `tests/testlive_event_templates.py` → `EventTemplatesRestTests` (8 tests): index, view, add, edit, delete, duplicate, validate_definition, instantiate (success and file_field rejection)
- [x] Import/export round-trip test: export → wipe → import → deep-equal — `EventTemplatesImportExportTests` (6 tests): export shape, fail-mode create + collision, overwrite, duplicate_as_new, headline round-trip
- [x] Object-template-dependency tracking test: save template, verify rows; edit template, verify rows updated; delete template, verify rows removed — `EventTemplatesObjectDependencyTrackingTests` (5 tests): save, dedup, edit-add, edit-remove, delete-cascade (DB-level assertion; requires DB_PASS env)

- [x] **Phase 1 complete**

---

## Phase 2 — Default-theme UI

**Status:** complete
**Depends on:** Phase 1 complete.
**Exit criteria:** template creator can build and save a non-trivial template; template user can create an event from it end-to-end in the classic theme.

### 2.1 Views

- [x] `app/View/EventTemplates/index.ctp` — list view (IndexTable-based)
- [x] `app/View/EventTemplates/view.ctp` — read-only detail (viewMetaTable + JSON dump)
- [x] `app/View/EventTemplates/add.ctp` + `edit.ctp` — builder (shared partial `Elements/eventTemplates/builder/shell.ctp`)
- [x] `app/View/EventTemplates/preview.ctp` — creator's preview of the user form (yellow banner, submit disabled)
- [x] `app/View/EventTemplates/user_form.ctp` — the form the template user fills in
- [x] `app/View/EventTemplates/import.ctp` — import form (genericForm + file upload + mode selector)
- [x] `app/View/Elements/eventTemplates/builder/` — properties panel partials (one per element type)
- [x] `app/View/Elements/eventTemplates/userForm/` — render partials (one per element type; section/text_block/attribute/object/tag/galaxy/file — object_reference is not user-facing)
- [x] `app/View/Elements/eventTemplates/templatePickerModal.ctp` — used from events index

### 2.2 Builder JS (classic theme)

- [x] Vanilla JS state manager for the template definition (one object, re-renders canvas on change)
- [x] jQuery UI sortable wiring for element reordering (flat in v1; nested-inside-sections reorder is a follow-up)
- [x] Properties panel: editing any field updates the state and re-renders
- [x] Object template picker (modal, searchable)
- [x] Tag taxonomy picker for `tag_field.restrict_taxonomies` (shared multi-picker modal)
- [x] Galaxy-type picker for `galaxy_field.restrict_galaxy_types` (shared multi-picker modal)
- [x] Inline validation: surface server errors from `/event_templates/validate_definition`
- [x] Save flow (POST to `add` / PUT to `edit`)

### 2.3 Template-user form JS (classic theme)

- [x] Field-type renderers matching each element type (DOM level) — `Elements/eventTemplates/userForm/*.ctp`
- [x] Repeatable fields: add/remove entry buttons
- [x] Client-side mandatory-field guard (disable submit until satisfied)
- [~] Tag and galaxy picker inline integration — tag picker shipped (fetch-on-first-open of `/tags/index.json` + client-side filter by `restrict_taxonomies`). Galaxy cluster picker deferred as a follow-up (needs ajax pagination over the ~10k+ cluster space); galaxy_field remains CSV for now.
- [x] File upload: plain `<input type="file">` + client-side base64 encode in the JSON payload (drag-drop + progress bar are a polish follow-up)
- [x] **Backend**: `EventTemplateInstantiator` accepts `file_field` uploads as base64-encoded `{filename, data}` objects; produces `attachment` or `malware-sample` attributes routed through `onDemandEncrypt` for the malware-sample case.
- [x] Submit flow: POST to `/event_templates/instantiate/{id}`, redirect to event on success, render errors on failure

### 2.4 Nav

- [x] Side-menu entry for Event Templates (gated on read access) — global_menu.ctp + side_menu.ctp
- [x] "Add Event → From Template" button wired on events index — ListTopBar toolbar button next to the filter control, gated on eventTemplates/instantiate + eventTemplates/index ACL; click opens a Bootstrap-2 modal fed by /event_templates/index.json (cached for page lifetime) with a live filter across name/description/org. Full entry-point polish (Add-Event button primacy, per-theme shortcuts) stays on Phase 4.

- [x] **Phase 2 complete**

---

## Phase 3 — Overmind-theme UI

**Status:** not started
**Depends on:** Phase 2 complete (strictly sequential — do not start before Phase 2 is fully checked off).
**Exit criteria:** parity with Phase 2 in the Overmind theme.

### 3.1 Assets

- [x] Vendor SortableJS (pinned version) in `app/webroot/js/vendor/sortablejs/`
- [x] Vendor Alpine.js 3.x (pinned version) in `app/webroot/js/vendor/alpinejs/`
- [x] Asset loading gated on the builder view only (not in the global Overmind asset set)
- [x] License attribution in NOTICE / dependency manifest

### 3.2 Views

- [x] `app/View/Themed/Overmind/EventTemplates/index.ctp` (BS5 card/table)
- [x] `app/View/Themed/Overmind/EventTemplates/view.ctp`
- [x] `app/View/Themed/Overmind/EventTemplates/add.ctp` + `edit.ctp` (builder with Alpine.js markup)
- [x] `app/View/Themed/Overmind/EventTemplates/preview.ctp`
- [x] `app/View/Themed/Overmind/EventTemplates/user_form.ctp`
- [x] `app/View/Themed/Overmind/EventTemplates/import.ctp`
- [x] Overmind-flavoured element partials for builder and user form

### 3.3 Builder JS (Overmind)

- [x] Alpine.js component(s) driving the builder state
- [x] SortableJS wiring for nested drag-and-drop
- [x] Tom Select pickers for object template, tag taxonomy, galaxy type
- [ ] Inline server-error surfacing

### 3.4 Template-user form JS (Overmind)

- [ ] Field-type renderers for Overmind (BS5 markup)
- [ ] Tom Select-based inline tag and galaxy cluster pickers
- [ ] `GET /galaxy_clusters/search?galaxy_type=…&q=…` lean endpoint consumed async
- [ ] File upload with BS5 progress UI

- [ ] **Phase 3 complete**

---

## Phase 4 — Entry points and polish

**Status:** not started
**Depends on:** Phase 2 and/or Phase 3 complete (theme-specific polish).
**Exit criteria:** feature is discoverable; a new template user can find it without being told where.

- [ ] "Add Event → From Template" primary button on events index (both themes)
- [ ] Template picker renders name, description, last-updated, creator org; searchable
- [ ] Events created from a template record `template_uuid` + `template_version` in event metadata (location TBD: tag, event note, or dedicated column — decide during implementation)
- [ ] Audit log entry on "event created from template" (PRD §5.3 F3.4)
- [ ] Preview mode wired from builder for both themes
- [ ] Import/export UI flows (download button on view, upload form on index)
- [ ] Empty-state and error-state UX (no templates yet, no compatible object templates, etc.)
- [ ] User-facing documentation: creator guide and user quickstart

- [ ] **Phase 4 complete (v1 shipping target reached)**

---

## Phase 5 — Copy tool from legacy Templates

**Status:** not started
**Depends on:** Phase 4 complete.
**Exit criteria:** operators can copy their existing legacy templates into the v2 system with a single CLI command. Legacy data is read-only to the tool; nothing is modified, renamed, or deleted on the legacy side.

- [ ] `app/Console/Command/EventTemplateShell.php` with `copyFromLegacy` action
- [ ] Copy logic: read legacy `Template` → create matching `event_templates` row with synthesised v1 definition; `template_elements` → `section`/`text_block`/`attribute_field`/`file_field` elements; legacy `complex` attribute flag → best-effort `repeatable: true` + warning; `template_tags` → `event_defaults.tags`. Legacy rows are never written to.
- [ ] Per-template warnings and a summary report emitted
- [ ] Dry-run mode (`--dry-run`)
- [ ] Idempotency: legacy-template id recorded in the v2 template's audit metadata; re-running skips previously-copied templates by default, `--force` overrides
- [ ] Integration test: seed legacy templates, run tool, assert v2 result matches, assert legacy rows unchanged
- [ ] Release notes entry

- [ ] **Phase 5 complete**

---

*Legacy system removal is out of scope for this project — see PRD §12 and §15. The old Templates system and its `perm_template` flag remain untouched and in service indefinitely.*

---

## Change log for this tracker

- 2026-04-22 — initial plan drafted.
