# Event Template Library — Implementation Progress

**Companion to:** [`event-template-library-prd.md`](event-template-library-prd.md).
**Purpose:** live checklist of implementation tasks for the
`misp-event-templates` library project. The PRD is the *spec*; this
file is the *tracker*. Check items off as they land on branch
`templating` (or a fresh `template-library` branch once Phase 0 closes).

## Legend

- `- [ ]` — not started
- `- [~]` — in progress (replace the space with `~` manually)
- `- [x]` — complete
- `⛔` — blocked (append reason inline)

Each task is sized to be a single PR or a small cluster of commits.
**Tasks and phases run strictly sequentially** — one item at a time,
top to bottom within a phase, and one phase at a time. Implementation
is driven by a ralph loop; no parallel code work. (Research and
information lookups during a task may still be parallelised; the
constraint applies to writing code.)

---

## Commit protocol

This workflow runs inside a ralph loop and produces many commits.
**This protocol is the user's pre-authorisation to commit during the
event-template-library workflow** — no per-task approval is required,
provided every rule here is honoured. Same shape as the event-templating
workflow's protocol.

### 1. One task, one commit (usually)

- Default unit of work: **one checkbox in this file → one commit**.
- Adjacent tightly-coupled checkboxes (migration + model that depends
  on it; controller action + its route wiring) may be combined.
- Never batch unrelated tasks. Never batch across phases.

### 2. What goes into the commit

1. The code/config/view/migration changes for the task.
2. The checkbox flipped from `- [ ]` (or `- [~]`) to `- [x]`.
3. Phase capstone: update the phase's `Status:` line.
4. Tests introduced/updated for the task.
5. Nothing else.

### 3. Commit message format

```
new: [event-template-library] Short subject

Longer body explaining *why* and what it enables. Reference the PRD
section and the progress-tracker checkbox.

PRD: docs/dev/event-template-library-prd.md §<N>.<N>
Task: docs/dev/event-template-library-progress.md — Phase <N> / <task title>

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
```

- **Prefix:** `new:` for new functionality, `fix:` for bug fixes,
  `chg:` for refactors / spec edits / tracker advances.
- **Category tag:** `[event-template-library]` on every commit. Sub-scope
  in parentheses is fine when useful (e.g.
  `[event-template-library(loader)]`, `[event-template-library(catalogue)]`).
- **Co-Authored-By:** mandatory.

Two repos are in play during this workflow:

- **MISP core** (this repo) — `[event-template-library]` prefix, branch
  `templating` or fresh `template-library` branch.
- **`misp-event-templates`** (the standalone library repo) — same
  prefix, branch `main`. Tracker checkboxes that produce commits in
  the library repo are explicitly noted; the SHA references in this
  tracker should disambiguate when necessary.

### 4. Pre-commit checks

- Lint (MISP core): `./app/Vendor/bin/parallel-lint --exclude
  app/Lib/cakephp/ --exclude app/Vendor/ -e php,ctp app/`.
- Validate (library repo): `./validate_all.sh` exits zero.
- Migrations run cleanly on a fresh schema.
- No secrets, .env, large binaries, app/tmp/ artefacts.
- Staging is explicit: `git add <paths>`.

If any check fails, **do not commit**. Fix root cause, re-stage, new
commit. Never `--amend` / `--no-verify` / `--no-gpg-sign`.

### 5. What not to do

- No push to remote unless explicitly asked.
- No PR unless explicitly asked.
- No history rewrites.
- No working out-of-order.

---

## Phase 0 — Spec finalisation

**Status:** complete
**Exit criteria:** PRD approved; four open questions in PRD §15
closed with explicit decisions; library schema mirror plan locked;
target branch decided.

- [x] Draft PRD v0.1 (see `event-template-library-prd.md`)
- [x] Close open question §15.1 — default `active = 0` for library imports
- [x] Close open question §15.2 — default `distribution = 1` for library imports
- [x] Close open question §15.3 — explicit `default` flag replaces hash-based edit detection (§5.3)
- [x] Close open question §15.4 — seven starter templates
- [x] Close open question §15.5 — stay on `templating`
- [x] Close open question §15.6 — public repo URL `https://github.com/MISP/misp-event-templates` (operator-created, empty)
- [x] User sign-off on PRD v0.1

- [x] **Phase 0 complete**

---

## Phase 1 — Standalone repo skeleton

**Status:** not started
**Depends on:** Phase 0 complete.
**Exit criteria:** `MISP/misp-event-templates` exists publicly with
README/CONTRIBUTE/LICENSE/schema/validate_all.sh, two reference
templates committed and validating, CI green on the repo.

### 1.1 Repo standup

- [ ] Local-stage the repo skeleton in a sibling directory (NOT yet
      submoduled into MISP core)
- [ ] `README.md` — what's here, who it's for, how to use it
- [ ] `CONTRIBUTE.md` — how to author and submit a template
- [ ] `LICENSE.md` — CC0 (matches misp-galaxy / misp-objects)
- [ ] `schema_event_template.json` — mirror of MISP core's
      `app/files/schemas/event-template-v1.schema.json`, plus the
      `library_metadata` extension defined in PRD §7

### 1.2 Tooling

- [ ] `validate_all.sh` — walk `templates/*/definition.json`, validate
      each against `schema_event_template.json`, check uuid + name
      uniqueness, exit non-zero on any failure
- [ ] `jq_all_the_things.sh` — canonical JSON formatting hook
- [ ] GitHub Actions workflow at `.github/workflows/validate.yml`
      that runs `validate_all.sh` on every PR

### 1.3 Reference templates

- [ ] First reference template: `templates/spearphishing-email/definition.json`
      — peer-reviewed, validates, includes `library_metadata`
- [ ] Second reference template: `templates/ransomware-incident/definition.json`

### 1.4 Public push

- [ ] Push the repo to `MISP/misp-event-templates` on GitHub (operator
      action — Claude cannot push to a repo it doesn't own; surfaces a
      clear handoff)
- [ ] Confirm CI green on `main`

- [ ] **Phase 1 complete**

---

## Phase 2 — MISP core loader

**Status:** not started
**Depends on:** Phase 1 complete (the submodule must point at a real
publicly-fetchable repo).
**Exit criteria:** Loader walks the submodule, validates, upserts
correctly, hash-based edit detection works, integration tests green
against a real DB.

### 2.1 Migration

- [x] Migration: add `event_templates.default` column (TINYINT(1) NOT NULL DEFAULT 0, PRD §6). Backticked in SQL because `default` is a MySQL reserved word. Added as DB_CHANGES case 150 in `app/Model/AppModel.php`.
- [x] Migration tested on the live DB at localhost:5007 — column applied, db_version bumped 149 → 150, model schema cache regenerated to include the column. Existing 463 rows untouched (the column carries its DEFAULT 0 retroactively).

### 2.2 Submodule registration

- [x] Add `app/files/misp-event-templates/` entry to `.gitmodules` pointing at `https://github.com/MISP/misp-event-templates#main` — HTTPS URL (matching every other content submodule's convention) so users without a GitHub account can fetch.
- [x] Add un-ignore entries to `.gitignore` so the submodule path is tracked.
- [x] Initial submodule checkout pinned to Phase-1 head SHA `99f97d57af8836f5660ea7c429bf9964f4d80e53`.

### 2.3 Loader

- [x] `EventTemplate::updateFromLibrary($user)` — walks the submodule path, validates each `definition.json` via the existing `EventTemplateValidator`, routes each row to install / updated / skipped_current / skipped_forked / failed (PRD §5.3). Library imports get `default = 1`, `active = 0`, `distribution = 1`, importing user/org as owner. Updates preserve id + ownership + active flag. Content-equal rows are reported as `skipped_current` to keep the summary truthful. `default = 0` rows are reported as `skipped_forked` and never touched.
- [x] Importer + exporter round-trip the `default` flag — `EventTemplateImporter` checks `template.default` (envelope) then `template.definition.default` (bare JSON, library shape) and persists either to the row; `EventTemplateExporter` includes `default` in the envelope so a re-import preserves it. Builder properties-panel toggle deferred to Phase 3 (UI).
- [x] Core schema extended (`app/files/schemas/event-template-v1.schema.json`) with optional `default` and `library_metadata` top-level keys so library JSONs validate without stripping. Both fields are optional — pre-existing v1 templates still validate (verified live against template id=463).

### 2.4 Controller / REST

- [x] `EventTemplatesController::update()` — site-admin gated, POST-only, calls the loader and renders / returns the summary. Live-verified end-to-end against the live instance: install / skipped_current (idempotent re-run) / skipped_forked (operator-flipped row) / updated (drift overwrite preserving id+ownership) all surfaced correctly in the JSON envelope.
- [x] `EventTemplatesController::library_status()` — dry-run snapshot of on-disk library vs local DB rows (no writes, GET). Returns slug + uuid + name per template plus the local row's id/active/default if installed.
- [x] ACL list entries in `ACLComponent::$aclList['eventTemplates']` for `update` and `library_status` (empty array — site-admin only). Touch on the shared ACL component is established acceptable per the existing protocol.
- [x] REST envelope: when `IndexFilter::isRest()` true, `RestResponse::viewData()` JSON-encodes the summary directly. HTML branch renders the placeholder views below.
- [x] Placeholder HTML views shipped on both themes (default + Overmind): `EventTemplates/update.ctp` and `EventTemplates/library_status.ctp`. Phase 3 replaces these with proper styled summaries.
- [x] Overmind BS5 layout whitelist (`Themed/Overmind/Layouts/default.ctp`) updated to include `update` and `library_status` so they render under the BS5 stack.

### 2.5 First-touch auto-update hook

- [x] `EventTemplate::populateIfEmpty($user)` — mirrors `ObjectTemplate::populateIfEmpty()` exactly. Calls `updateFromLibrary` only if `hasAny()` returns false. Returns the loader summary or null.
- [x] Hooked into `EventTemplatesController::index()` — auto-trigger gated on `perm_site_admin` (library updates affect every org on the instance, so non-admins shouldn't trigger silent installs). Smoke-tested that the hook is silent on a non-empty table (live instance has ~7 templates, index renders normally with no flash).
- [x] Flash message surfaces what was installed ("Loaded N event template(s) from the bundled library. They are inactive by default…") so the operator knows the table just gained content.

### 2.6 Tests

- [ ] Unit tests for the loader's install / update / skip-forked
      routing based on the `default` flag + version comparison
- [ ] Integration test: empty DB → run update → seven templates
      installed with `default = 1`; flip one to `default = 0`;
      bump that template's library version; run update → forked
      one is skipped, others update silently

- [ ] **Phase 2 complete**

---

## Phase 3 — UI integration (both themes)

**Status:** not started
**Depends on:** Phase 2 complete.
**Exit criteria:** site admins can drive the full flow — update,
view summary, see library badges — from the UI on both themes.

### 3.1 Default theme (BS2)

- [ ] "Update from library" button on the event-templates index
      toolbar, gated on the new ACL entry, sits next to Import
- [ ] Update result page rendering installed / updated / skipped-forked /
      failed sections with copy explaining the `default` flag mechanic
- [ ] Default-template badge column on the index for rows with
      `default = 1`
- [ ] Builder banner near the save bar warning that edits to a
      `default = 1` row will be overwritten on the next library
      update unless the operator flips the flag (PRD §10.4)
- [ ] Properties-panel toggle exposing the `default` flag to the
      builder

### 3.2 Overmind theme (BS5)

- [ ] "Update from library" entry in `headerActions` on the
      event-templates index, same ACL gate
- [ ] BS5-flavoured update result view (cards / sections per
      outcome category)
- [ ] Default-template badge in the IndexTable card / table fields
- [ ] Builder warning + properties-panel toggle (parity with the
      default theme)

### 3.3 First-touch auto-update flash

- [ ] Wire the controller's index action to the auto-update hook
      from Phase 2.5; surface the flash on both themes

- [ ] **Phase 3 complete**

---

## Phase 4 — Starter catalogue

**Status:** not started
**Depends on:** Phase 3 complete (so each template can be smoke-tested
through the full flow).
**Exit criteria:** seven peer-reviewed templates merged into the
library repo, all rendering correctly through the user form on both
themes.

- [ ] Template: `spearphishing-email` (already shipped Phase 1.3 as
      reference; review for catalogue-quality and bump the version
      if needed)
- [ ] Template: `ransomware-incident` (same)
- [ ] Template: `credential-exposure`
- [ ] Template: `suspicious-domain-triage`
- [ ] Template: `malware-sample-submission`
- [ ] Template: `vulnerability-disclosure`
- [ ] Template: `supply-chain-compromise`
- [ ] Each template smoke-tested: import via library update, render
      the user form, fill mandatory fields, instantiate, verify the
      resulting event has the expected attributes / objects /
      tags / clusters / object references

- [ ] **Phase 4 complete (v1 shipping target reached)**

---

## Phase 5 — Docs and release polish

**Status:** not started
**Concurrent with:** Phase 4 (can land in parallel — these tasks
don't touch the same files).
**Exit criteria:** operators and library authors can find their
way through the workflow without asking us.

- [ ] Library `README.md` final pass — make sure it describes both
      MISP-driven and external use
- [ ] Library `CONTRIBUTE.md` — JSON authoring conventions, schema
      summary, validation script usage, PR review checklist
- [ ] MISP-side admin doc at `docs/event-template-library-admin.md`
      — explaining `git submodule update` + the update endpoint +
      the skip-edited semantics
- [ ] Release notes entry in MISP core's changelog
- [ ] Cross-link from `docs/event-templates-creator-guide.md` to
      "the curated library is at MISP/misp-event-templates"

- [ ] **Phase 5 complete**

---

*Phase 6 — and any continuous-sync, marketplace, or in-MISP
catalogue-browser work — is out of scope for this project per PRD §14.*

---

## Change log for this tracker

- 2026-04-25 — initial plan drafted.
