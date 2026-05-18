# Event Template Library — Admin Guide

This guide is for **MISP site admins** who manage the event-template
catalogue on their instance. It describes how the bundled
`misp-event-templates` library works, how to update it, how the
operator-fork flow works, and what the per-row `misp_default` flag
means.

If you are a **template creator** authoring templates in the visual
builder, see [event-templates-creator-guide](event-templates-creator-guide).
If you are a **template user** filling in a form to create an event,
see [event-templates-quickstart](event-templates-quickstart).

## What is the library

`MISP/misp-event-templates` is a community-maintained content
repository — same shape as `misp-objects`, `misp-galaxy`, and
`misp-taxonomies`. It ships with MISP as a git submodule at
`app/files/misp-event-templates/`, and it carries a curated catalogue
of event templates for common SOC playbooks.

A fresh MISP install picks up the templates automatically: the first
time a site admin hits **Event Templates → Index**, MISP walks the
submodule and installs every template it contains. From that point
on, the operator drives updates explicitly with the **Update from
library** button.

## Updating the library

The flow has two halves: pulling new content into the on-disk
submodule, then reconciling it with the database.

### 1. Pull the latest submodule content

From the MISP install directory, as the deployment user:

```bash
git submodule update --remote app/files/misp-event-templates
```

(Equivalent to a `git pull origin main` inside the submodule path.)
This brings the on-disk `templates/` directory in sync with upstream
without changing the database yet.

### 2. Reconcile with the database

Two paths:

**UI (preferred):** As a site admin, open **Event Templates →
Index** and click **Update from library**. You will see a
preview of what would change before you apply (install /
update / skip-forked buckets), then a summary view after the
run.

**REST:**

```bash
# dry-run — what would change
curl -s -H "Authorization: $KEY" -H "Accept: application/json" \
  "$URL/event_templates/library_status"

# execute the reconciliation
curl -s -X POST -H "Authorization: $KEY" -H "Accept: application/json" \
  "$URL/event_templates/update"
```

Both endpoints are gated on site-admin only — library updates affect
every org on the instance.

### What the loader does, in plain English

For each `templates/<slug>/definition.json` in the submodule, the
loader looks up the local `event_templates` row by uuid. Then:

| Local row state | Outcome |
|---|---|
| Not present | **Install** — insert with `misp_default = 1`, `active = 0`, `distribution = 1`. |
| Present, `misp_default = 1`, content matches | **Already current** — no-op. |
| Present, `misp_default = 1`, content differs | **Update** — overwrite preserving id, ownership, and the operator's active flag. |
| Present, `misp_default = 0` | **Skipped (forked)** — operator has flipped the flag off; library updates leave the row alone. |

Templates removed upstream are **not** auto-deleted from your DB.
The summary report lists them under their last-known state so you
can decide whether to delete them yourself.

## The `misp_default` flag — operator forking

Every row in `event_templates` carries a `misp_default` boolean. It
controls whether **Update from library** will touch the row.

- **`misp_default = 1`** — the row is library-managed. Each library
  update will replace its content with the upstream version. Use
  this for rows you want to keep in lockstep with the catalogue.
- **`misp_default = 0`** — the row is operator-owned. Library
  updates skip it. Use this when you have customised a library
  template for your team and want to keep your edits across upstream
  refreshes.

Rows newly installed from the library start with `misp_default = 1`.
Hand-built templates (created via **Add Event Template** in the
builder, or imported via **Import**) start with `misp_default = 0`.

### Forking a library template

In the builder, the row's properties show a **Library-managed**
checkbox alongside Active and Distribution. Uncheck it and Save.
The next library update will route the row to **Skipped (forked)**.

The amber banner at the top of the builder is a reminder: while
**Library-managed** is checked, *your edits will be overwritten* on
the next library update. Uncheck before customising for production
use.

### Re-opting-in to library updates

Re-check the **Library-managed** flag and Save. The next library
update will overwrite the row with the upstream version. (Your
local edits are not preserved by re-opting-in — that is the whole
point of the forked / managed distinction.)

## What about templates I author myself

Templates authored in your local builder are operator-owned by
default (`misp_default = 0`). They never appear in the library
update flow. Library updates only ever touch rows that were either
installed by a library run or have been explicitly flagged
`misp_default = 1`.

## After the update — making templates available to your team

Library imports default to `active = 0`. This is deliberate: the
site admin previews each template before exposing it to the team's
template-picker. Open the row, decide whether the structure fits
your workflow, then flip Active to 1.

The `Source` column on the events-templates index distinguishes
library-managed rows (`Library` badge) from locally-authored ones
(`local` label).

## Troubleshooting

**"submodule directory not present at …"** — run `git submodule
update --init app/files/misp-event-templates`. The submodule path
must be present and contain `templates/` for the update to do
anything.

**"definition.json is not valid JSON"** — usually means the
submodule is in a partial-clone state. Re-init.

**"schema/semantic validation failed: …"** — an upstream template
was authored with an attribute category/type combination that
your MISP version's `MispAttribute::typeDefinitions` does not
recognise, or it references a `misp-objects` template you don't
have installed at the pinned version. The error message names the
slug. File an issue against
[MISP/misp-event-templates](https://github.com/MISP/misp-event-templates)
or update your `misp-objects` submodule and retry.

**Library update returns no `installed` rows on a fresh install**
— check the submodule has actually been initialised. `ls
app/files/misp-event-templates/templates` should list the seven
starter templates.

**Library `misp_default` column missing from REST responses after
running the rename migration** — clear Cake's persistent method
cache once: `rm -f
app/tmp/cache/persistent/myapp_cake_core_method_cache`. Cake
memoises the SELECT column list per model and adding a column
doesn't invalidate it automatically.

## Contributing back

Improvements to the catalogue are welcome upstream. The submodule
points at `https://github.com/MISP/misp-event-templates` (HTTPS, no
GitHub account needed to fetch). To contribute, fork the repo, add
your template under `templates/<slug>/definition.json`, run
`./jq_all_the_things.sh && ./validate_all.sh`, and open a PR. See
that repo's CONTRIBUTE.md for the full authoring conventions.
