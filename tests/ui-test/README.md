# MISP Web UI tests

Plain-language test cases and bug reports for the MISP web UI (Overmind theme).

Every test is written as short numbered steps (where to go, what to click, what to type) so that
**a person or an AI agent can replay it exactly**. The files are plain Markdown and can be pasted
into HedgeDoc as they are.

## Folder structure

```
ui-test/
  README.md                 this file
  bugs.md                   all bugs + "# Recommendations" at the bottom
  event/                    one folder per feature
    index/                  one subfolder per page (Events list)
      filters.md            one file per topic
      selection.md
    add/                    Add Event form
      fields.md             normal creation cases
      validation.md         refused / edge-case input
    edit/                   Edit Event form
      edit.md
    view/                   event detail page
      actions.md            publish, delete, tags, extends…
      performance.md        large events
  taxonomy/
    index/actions.md        enable/disable, required, update
    view/tags.md            enable all tags, disable one tag
    tagging/exclusive.md    exclusive taxonomies (tlp)
  galaxy/
    index/galaxies.md       custom galaxy, disable, delete, import
    cluster/clusters.md     add, fork, rename, delete/restore, publish
    cluster/relations.md    relationships between clusters
  object/
    add/add.md              Add Object form: requirements, invalid values, duplicates
    view/objects.md         event Objects tab: edit, delete, filter, correlation
    templates/templates.md  object templates: deactivate, update, search
  attribute/
    add/add.md              Add Attribute form: validation, normalisation, duplicates, first seen
    add/batch.md            batch import
    add/attachment.md       attachments and malware samples
    view/attributes.md      event Attributes tab: edit, delete/restore, filter
    index/search.md         Attributes list across events
  tag/
    index/tags.md           tags: add, duplicates, length, colour, rename/delete while used, hidden, exportable
    local/local.md          local tags and local-only tags
    collection/collections.md  tag collections
  proposal/
    add/add.md              propose a change or a deletion
    index/index.md          Proposals list (/shadow_attributes/index)
    review/review.md        accept, discard, accept twice, attribute deleted meanwhile
    cross-org/cross-org.md  proposals between two organisations
  event/roles/permissions.md   visibility, edit and publish rights per role and organisation
  tag/roles/permissions.md     global/local tags across organisations, restricted tags, tag editor
  admin/users/org-admin.md     Org Admin limited to its own organisation
  admin/users/users.md         site admin: add, disable, role change
  admin/organisations/organisations.md  delete while used, emoji
  admin/settings/settings.md   settings validation, diagnostics, admin pages
  warninglist/index/filters.md Warninglists list filters
  import-export/
    freetext/freetext.md    freetext import
    import/import.md        Import Event (MISP JSON, STIX)
    export/export.md        Download as, CSV, STIX, cached exports
  sharing-group/
    index/sharing-groups.md create, emoji, edit by a member, delete while used
    visibility/visibility.md who sees events and attributes in a sharing group
  event-report/
    add/add.md              write reports: Markdown, HTML/scripts, big content, references
    extract/extract.md      extract indicators, replacements, import from URL, PDF
  sighting/add/sightings.md   sightings: add, false positive, by value, other org, future date, delete
  correlation/correlations/correlations.md  correlations, exclusions, top correlations
  account/
    keys/auth-keys.md       read-only key, allowed IPs, expiration, own keys only
    password/password.md    password rules
    login/login.md          wrong password, brute force protection, logout
  general/emoji/emoji.md       emoji in every text field (Bug 7)
  event-template/
    index/templates.md      active/inactive, duplicate, delete, library update, import/export
    form/instantiate.md     create an event from a template
    builder/builder.md      build a template
  tools/
    seed_events.py          resets a LOCAL instance and creates the events used by the tests
    check_list_selection.js checks Bugs 2 and 5 on list pages in a headless browser (Playwright)
  skill/
    misp-test-plan/SKILL.md Claude Code skill that writes tests and bugs in this exact format
```

Where to put something:

| You have… | Put it in |
|---|---|
| A test | The file matching its **feature / page / topic** (e.g. a test on the Events list filters → `event/index/filters.md`). If no file fits, create one (template below). |
| A bug | `bugs.md`, **and** a test that reproduces it in the matching test file. |
| An idea / improvement | `bugs.md`, section `# Recommendations` at the bottom. No test needed. |

New feature (e.g. attributes)? Create `attribute/<page>/<topic>.md` with the same layout.

## Rules

- Write in **English**, short plain sentences, **one action per step**.
- UI buttons, links and fields in **bold** with their visible label (`**Add Event**`, `**Event Info**`).
- URLs and values in `backticks` (`/events/index`, `QA minimal event`).
- Roles are only `user`, `site-admin`, `org-admin`. When the organisation matters, the login step says it:
  ``Log in to MISP as `user` of the organisation `QA-Org-B`.``
- Every test ends with one `**Expected:**` line that can be checked (what is shown, which page opens).
- Never mention `tools/seed_events.py` (or any tool) inside a test: describe the data to create
  instead (e.g. "create an event with 2,000 `ip-dst` attributes").
- Do not add extra sections, fields or emojis. Do not remove a field: if something is unknown use
  `Notes: None` / `Likely cause: Unknown` (never guess a cause).
- Numbering restarts at 1 in each file. Add new rows at the end of the table and new sections at the
  end of the file. Do not renumber or edit other people's entries.
- Test something that makes sense: basic flows and cases that can break (validation, limits,
  concurrency, odd URLs). Do not write "click the button and check the modal opens" tests.

## Templates

### Test file (only when creating a new file)

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

### Test

Row in the file's table:

```markdown
| N | [<Test name>](#<test-slug>) | <Owner or empty> |
```

Section at the end of the file (`<test-slug>` = short kebab-case name, unique in the repo):

```markdown
### <Test name>
<a id="<test-slug>"></a>

<One-line description of the flow>

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **Add Event** button
4. <action>
5. <action>

**Expected:** <one sentence: what happens and which page opens>
```

Optional, only when the test data was created on a local instance, one line right after **Expected:**:

```markdown
**Seeded data:** <events created (name, #id), their `qa:<test-slug>` tag, the steps done to create them, and what the server showed (accepted / refused + message)>
```

The `#id` values come from the last seed run on the tester's instance; they change when the script is run again — use the `qa:<test-slug>` tag to find the events.

### Bug (in `bugs.md`)

Row in the `## Bugs` table:

```markdown
| N   | [<Bug title>](#bug-N) | Open | v2.5.48 | <Owner or empty> |
```

Section, after the last bug and before `# Recommendations`:

```markdown
### Bug N – <Bug title>

<a id="bug-N"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce

1. <action>
2. <action>

- **Expected result**: <one sentence>
- **Actual result**: <one sentence, exact error text if any>
- **Notes**: <when it happens / when it does not, or None>
- **Likely cause**: <only what was really investigated (logs, code), or Unknown>
```

A bug must be understandable by anyone, without the test instance: the steps create their own data
("Create an event with **Add Event** …"), with no event IDs, seeded `QA …` names or test accounts; use
`<id>` in URLs.

When the cause is a shared mechanism (same component, same form pattern, same database setting),
list in **Notes** every other place where the bug can happen, after `**Also affects:**`.

The test that reproduces the bug says so in its description: `(regression test for Bug N)`.

### Recommendation (bottom of `bugs.md`, under `# Recommendations`)

```markdown
### Recommendation N – <Short title>

<a id="recommendation-N"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

- **Current behaviour**: <one sentence>
- **Proposal**: <one or two sentences>
- **Benefit**: <one sentence>
```

## Test organisations and accounts

The role tests need two organisations on the local instance:

| Organisation | Account (email) | Role |
|---|---|---|
| `ADMIN` (default) | `admin@admin.test` | `site-admin` (admin) |
| `ADMIN` | `qa-user-a@admin.test` | `user` (User) |
| `ADMIN` | `qa-orgadmin-a@admin.test` | `org-admin` (Org Admin) |
| `QA-Org-B` (local) | `qa-user-b@qa-org-b.test` | `user` (User) |
| `QA-Org-B` (local) | `qa-orgadmin-b@qa-org-b.test` | `org-admin` (Org Admin) |

Create them once as site admin (**Administration → Add Organisation / Add User**). Keep the passwords
in a local file outside the repository — **never commit passwords or API keys**.

## Preparing a local instance (`tools/seed_events.py`)

> **Warning:** with `--yes` this script **deletes every event** of the instance it points to.
> Use it only on your own local test instance (default `https://localhost:8443`).

It deletes all events, then creates the events needed by the tricky tests. Each event gets a custom
tag `qa:<test-slug>` (e.g. `qa:event-extends-cycle`), so you can find the event for a test by
filtering the Events list on that tag. It also creates `qa:unused-tag`, attached to no event.
At the end it prints, for each case, whether the server **accepted or refused** it.

Every seeded event also gets an **Event Report** named `Test – <test name>` with the GitHub link to the
test, its description, steps, expected result and seeded data, so the reason of each event is visible
inside MISP. After adding or changing tests, refresh the reports without touching the events:

```
MISP_KEY=<your key> python3 tests/ui-test/tools/seed_events.py --reports-only
```

1. Create an API key in MISP: **My Profile → Auth keys**.
2. From the root of the MISP repository, do a dry run (lists the events, deletes nothing):
   ```
   MISP_KEY=<your key> python3 tests/ui-test/tools/seed_events.py
   ```
3. Reset and seed:
   ```
   MISP_KEY=<your key> python3 tests/ui-test/tools/seed_events.py --yes
   ```

Use `MISP_URL=https://other-host:port` to target another local instance. Only Python 3 is needed
(no extra package).

## Checking list selection in a browser (`tools/check_list_selection.js`)

Bugs 2 and 5 happen in the browser (JavaScript), so they cannot be seen through the API. This script
logs in with a headless Chromium (Playwright), and on each list page given as argument ticks a row,
switches to card view, then sorts by the first sortable column, and prints what happened:

```
MISP_EMAIL=<email> MISP_PASSWORD=<password> node tests/ui-test/tools/check_list_selection.js /events/index /tags/index
```

Each line is a JSON result, e.g. `"checkedInCard":false` (Bug 2) and `"checkedAfterSort":false` (Bug 5).

## Using the Claude Code skill

`skill/misp-test-plan/SKILL.md` teaches Claude Code this exact format. Install it once:

```
mkdir -p ~/.claude/skills && cp -r tests/ui-test/skill/misp-test-plan ~/.claude/skills/
```

Then describe a test or a bug to Claude Code in plain words, for example:

- "New bug: on the Events list, the Galaxy filter shows all events."
- "Add a test: edit an event and set a date in the future."
- "Recommendation: a Go to top button on long pages."

Claude writes the entry in the right file and format: for a bug, it adds the bug in `bugs.md`
**and** the matching test; for a test, only the test; for an idea, a recommendation.
