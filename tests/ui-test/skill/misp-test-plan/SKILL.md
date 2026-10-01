---
name: misp-test-plan
description: Turn a MISP web UI bug (-> bug + matching E2E test) or an E2E test (-> test only) the user describes (often informally, in any language) and write it, in the exact structure, directly into the local files in tests/ui-test/ of the MISP repository (tests in feature/page folders like event/add/fields.md, bugs in bugs.md; copied into HedgeDoc), in English. Use whenever the user reports a MISP/Overmind bug ("j'ai un bug", "nouveau bug", "ajoute ce bug"), describes a test to add ("nouveau test", "ajoute un test", "test e2e"), pastes a MISP error page, or asks for the test plan / bug report structure.
---

# MISP Web UI – Test Plan & Results

The user tests the MISP web UI (Overmind theme, misp-docker) and keeps HedgeDoc documents with two kinds of entries: **Bugs** and **E2E UI Tests**. The document is later replayed by an AI, so the structure must be identical every time.

Write the markdown in **English**. Talk to the user in their own language.

## Hard rules (never break them)

1. **Follow the templates below exactly.** Same heading levels (`#`, `###`, `####`), same order, same bold labels, same punctuation (`**Expected result**:` for bugs, `**Expected:**` for tests), same `<a id>` placement (on the line right **after** the `###` heading).
2. **Add nothing** (except the optional `**Seeded data:**` line when you created the test data yourself — then always add it): no extra sections, no extra fields, no emojis, no image placeholders, no "Back to top" link, no Playwright section, no comments. Only exception: if the user gives an image URL, put `![](URL)` on its own line right after the line it illustrates.
3. **Forget nothing**: every field of the template is present. If information is missing:
   - Bug `Status` → `Open` (unless told otherwise). `Owner` → leave the cell empty. `Version` → the MISP version from Environment; if unknown, ask the user.
   - `Notes` → `None`.
   - `Likely cause` → only what was actually investigated (logs, code, repro). Otherwise write `Unknown`. Never guess.
   - Do not invent error text, versions or values.
4. **Roles** are only: `user`, `site-admin`, `org-admin`. Put the role in backticks in the login step (`Log in to MISP as \`site-admin\`.`). When the organisation matters (cross-organisation tests), add it: `Log in to MISP as \`user\` of the organisation \`QA-Org-B\`.` Test organisations: `ADMIN` (default) and `QA-Org-B`; accounts are listed in the README (never write passwords or keys in the repo).
5. **Steps**: short plain sentences, one action per line, numbered. UI buttons/links in **bold** with their visible label. URLs/paths in backticks. Use concrete values when the user gives them.
6. **Numbering**: bugs are numbered `1, 2, 3…`; anchor = `bug-N`. Tests are numbered too; anchor = short kebab-case slug of the test name (`event-add`, `attribute-delete`). If the next number is unknown, ask the user or read it from what they pasted.
7. **What to produce depends on what the user gives:**
   - **The user reports a bug** → produce **BOTH**: the bug (template 1) **AND** an E2E test that reproduces it (template 2). The test's steps follow the bug's steps with concrete values, and its **Expected:** is the correct behaviour (the bug's Expected result).
   - **The user gives a test** → produce **ONLY** the test (template 2). No bug.
8. **Output = write directly into the local files** in `tests/ui-test/ (in the MISP repository)`. The files can be copy-pasted into HedgeDoc.
   - **Tests are organised by feature folder → page subfolder → topic file**, e.g.:
     ```
     ui-test/
       README.md                   (how it works, for other testers)
       bugs.md                     (all bugs + # Recommendations)
       tools/seed_events.py        (resets a LOCAL instance and seeds the events of the tricky tests, tag qa:<test-slug>)
       skill/misp-test-plan/       (portable copy of this skill)
       event/
         index/   filters.md, selection.md      (Events list page)
         add/     fields.md, validation.md      (Add Event form)
         edit/    edit.md                       (Edit Event form)
         view/    actions.md, performance.md    (event detail page: publish, delete, tags…, large events)
       taxonomy/  index/actions.md, view/tags.md, tagging/exclusive.md
       galaxy/    index/galaxies.md, cluster/clusters.md, cluster/relations.md
       object/    add/add.md, view/objects.md, templates/templates.md
       attribute/ add/add.md, add/batch.md, add/attachment.md, view/attributes.md, index/search.md
       tag/       index/tags.md, local/local.md, collection/collections.md
       proposal/  add/add.md, index/index.md, review/review.md, cross-org/cross-org.md
       event/roles/permissions.md, tag/roles/permissions.md, admin/users/org-admin.md, warninglist/index/filters.md
     ```
     Put a new test in the file matching its page and topic. If none fits, create a new topic file (or a new feature folder like `attribute/index/…`) with template 0a. Numbering restarts at 1 in each file.
   - **All bugs go in `bugs.md`** (template 0b), never in a feature file.
   - **Recommendations / suggestions** ("ce serait cool de…", "recommandation") go in the `# Recommendations` section at the very bottom of `bugs.md` (template 3). No table row, no E2E test.
   - **Never mention the seed script (`tools/seed_events.py`) or any tool inside a test.** Steps and `**Seeded data:**` describe the data itself (e.g. "create an event with 2,000 `ip-dst` attributes"), so anyone can reproduce the test by hand.
   - **Shared cause → list every place**: when a bug comes from a shared mechanism (same UI component, same form pattern, same DB charset/limit…), search the code/DB for every other place using it and add to **Notes** `**Also affects:** <pages/forms/fields>` (say "not yet checked one by one" when only found in the code). Verify the most common one when possible.
   - **Read the target file(s) first** and take the next free number from their table.
   - **A. Row** → add it as the last row of the file's table.
   - **B. Section** → add it at the end of the file. One blank line between sections.
   - A bug report = 4 insertions: bug row + bug section in `bugs.md`, test row + test section in the matching feature file. A test = 2 insertions in the feature file.
   - **Never delete or modify existing content**, unless the user explicitly asks.
   - In chat, say briefly what was added (file, numbers, titles). Do not repeat the markdown unless asked.
   - If the user pastes a newer version of a file, overwrite that file with it first, then add.
9. Fix typos in what you write (e.g. `side-admin` → `site-admin`), but never change the meaning and never touch existing content of the file.
10. **Seeded data**: when a tricky test needs data on a local instance, add it to `tools/seed_events.py` with the tag `qa:<test-slug>` (same as the test anchor), then run `seed_events.py --reports-only` so every seeded event gets an Event Report `Test – <test name>` (GitHub link to the test + description + steps + expected + seeded data).

## Template 0a – Test file (e.g. `event/add/fields.md`), only when creating it

````markdown
# MISP Web UI – <Feature Page – Topic> Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [<Test name>](#<test-slug>) | |

---


# E2E Tests

<test sections>
````

## Template 0b – `bugs.md` (already exists; only if it must be recreated)

````markdown
# MISP Web UI – Bugs  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 

## Bugs

| # | Bug | Status | Version | Owner | 
|---|-----|--------| ------- | ----- |
| 1 | [<Bug title>](#bug-1) | Open | v2.5.48 | |

---


# Bugs
<bug sections>
````

## Template 1 – Bug

**A. Row** (in the `## Bugs` table of `bugs.md`):

````markdown
| N | [<Bug title>](#bug-N) | <Open/Fixed/...> | <vX.Y.Z> | <Owner or empty> |
````

**B. Section** (end of `bugs.md`):

````markdown
### Bug N – <Bug title>
<a id="bug-N"></a>

**Environment:** MISP <vX.Y.Z> (misp-docker) · Overmind UI theme

#### Steps to reproduce
1. <action>
2. <action>
3. <action>

- **Expected result**: <one sentence>
- **Actual result**: <one sentence>
- **Notes**: <when it happens / when it does not, or None>
- **Likely cause**: <investigated cause, or Unknown>
````

## Template 2 – E2E UI Test

**A. Row** (in the `## E2E UI Tests` table of the feature file):

````markdown
| N | [<Test name>](#<test-slug>) | <Owner or empty> |
````

**B. Section** (end of the feature file):

````markdown
### <Test name>
<a id="<test-slug>"></a>

<One-line description of the flow>

1. Log in to MISP as `<role>`.
2. Go to <path>.
3. Click **<button label>** button
4. <action>
5. <action>
6. Submit

**Expected:** <one sentence: what happens and which page opens>
````

Optional, only when the test data was created on a local instance (e.g. by `tools/seed_events.py`), one line right after **Expected:**:

````markdown
**Seeded data:** <events created (name, #id), their `qa:<test-slug>` tag, the steps done to create them, and what the server showed (accepted / refused + message)>
````

The `#id` values come from the last seed run on the tester's instance; they change when the script is run again — use the `qa:<test-slug>` tag to find the events.

## Template 3 – Recommendation (bottom of `bugs.md`, under `# Recommendations`)

Create the `# Recommendations` heading once if missing; then append, numbered 1, 2, 3…

````markdown
### Recommendation N – <Short title>

<a id="recommendation-N"></a>

**Environment:** MISP <vX.Y.Z> (misp-docker) · Overmind UI theme

- **Current behaviour**: <one sentence>
- **Proposal**: <one or two sentences>
- **Benefit**: <one sentence>
````

## Reference example (the user's validated version)

Bug row: `| 1 | [CSRF error when creating an event with a future date](#bug-1) | Fixed | v2.5.48 | Thomas |`

```markdown
### Bug 1 – CSRF error when creating an event with a future date
<a id="bug-1"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce
1. On the Events list page, click **Create an event**.
2. Enter a title.
3. Set a date later than today (e.g. 2030).
4. Submit the form.

- **Expected result**: The event is created.
- **Actual result**: CSRF error - event not created
- **Notes**: It only happens when the date is changed. With the default date (today), the event is created normally.
- **Likely cause**: The date is stored in a hidden form field that CakePHP locks. When the date picker changes its value, MISP rejects the form as tampered and shows a misleading CSRF error.
```

Test row: `| 1 | [Event add](#event-add) | |`

```markdown
### Event add
<a id="event-add"></a>

Simple Event creation flow with custom date

1. Log in to MISP as `site-admin`.
2. Go to /events/index.
3. Click **Create an event** button
4. Pick a title
5. Change the date to before than today
6. Submit

**Expected:** the event is created and its events/view page opens.
```
