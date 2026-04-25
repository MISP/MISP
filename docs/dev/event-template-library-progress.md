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

**Status:** in progress
**Exit criteria:** PRD approved; four open questions in PRD §15
closed with explicit decisions; library schema mirror plan locked;
target branch decided.

- [x] Draft PRD v0.1 (see `event-template-library-prd.md`)
- [ ] Close open question §15.1 — default `active` for library imports
- [ ] Close open question §15.2 — default `distribution` for library imports
- [ ] Close open question §15.3 — upgrade behaviour on operator edits
- [ ] Close open question §15.4 — first batch of starter templates
- [ ] Decide target branch: stay on `templating` or branch off to `template-library`
- [ ] User sign-off on PRD v0.1

- [ ] **Phase 0 complete**

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

- [ ] Migration: add `event_templates.library_synced_hash` column
      (PRD §6)
- [ ] Migration tested on a fresh schema and on an existing DB with
      hand-rolled v1 templates

### 2.2 Submodule registration

- [ ] Add `app/files/misp-event-templates/` entry to `.gitmodules`
      pointing at `MISP/misp-event-templates#main`
- [ ] Initial submodule checkout committed at the Phase-1 head SHA

### 2.3 Loader

- [ ] `EventTemplate::updateFromLibrary($user, $force = false)` —
      walks the submodule path, validates each `definition.json` via
      the existing `EventTemplateValidator`, computes the content
      hash (excluding ownership envelope), routes each row to
      install / upgrade-clean / skip-edited / failed
- [ ] Helper `EventTemplate::computeLibraryHash(array $definition)`
      — deterministic hash over the schema-relevant fields
- [ ] Summary structure documented and round-tripped through unit
      tests

### 2.4 Controller / REST

- [ ] `EventTemplatesController::update($force = false)` — site-admin
      gated, calls the loader, renders or returns the summary
- [ ] `EventTemplatesController::library_status()` — dry-run diff,
      same gate, same shape minus the writes
- [ ] ACL list entries in `ACLComponent::$aclList['eventTemplates']`
      for `update` and `library_status`
- [ ] REST envelope conforms to `RestResponseComponent` conventions

### 2.5 First-touch auto-update hook

- [ ] `EventTemplate::checkAndUpdate()` — analogous to
      `ObjectTemplate::checkAndUpdate`, called from
      `EventTemplatesController::index` when the table is empty
- [ ] Flash message surfaces what happened ("Loaded N templates from
      the library")

### 2.6 Tests

- [ ] Unit tests for `computeLibraryHash` — deterministic, ignores
      ownership envelope
- [ ] Unit tests for the loader's install / upgrade-clean /
      skip-edited routing
- [ ] Integration test: empty DB → run update → seven templates
      installed; mutate one; bump library version; run update →
      that one is skipped, others upgrade

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
- [ ] Update result page rendering installed / upgraded / skipped /
      failed sections with copy explaining the skip-edited semantics
- [ ] Library badge column on the index for rows with non-null
      `library_synced_hash`

### 3.2 Overmind theme (BS5)

- [ ] "Update from library" entry in `headerActions` on the
      event-templates index, same ACL gate
- [ ] BS5-flavoured update result view (cards / sections per
      outcome category)
- [ ] Library badge in the IndexTable card / table fields

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
