# Event Templates — Creator Guide

This guide is for **template creators**: users with the
`perm_template` role flag, responsible for authoring templates that
their team will use to scaffold consistent events for recurring
incident types.

If you are a *template user* (filling in a form to create an event),
see [event-templates-quickstart](event-templates-quickstart).

## What an event template is

An event template is a saved, versioned **definition** of how an
event for a particular incident type should be structured. It tells
the template user exactly which fields to extract from the source
material, which MISP types each maps to, which tags and galaxy
clusters to apply, and any default event-level settings.

Templates are stored as a JSON document on the `event_templates`
row, edited in a visual builder, and exposed via REST under
`/event_templates`.

The original goal — and the most important habit to keep in mind
when authoring — is **not just picking MISP types but explaining to
the template user what to put in each field and why**. Every
interactive element carries a creator-authored label and an optional
help text that renders alongside the input on the user form.

## Creating a template

1. Open **Event Templates** from the navigation (Data ▸ Templates ▸
   Event Templates on Overmind, or the side menu on the default
   theme).
2. Click **Add Event Template**.
3. Set **Name** (mandatory) and **Description** (optional, Markdown).
4. Drag element types from the left rail into the canvas in the
   centre. Click any element to edit its properties on the right.
5. Set **event-level defaults** at the top of the page (info
   template, distribution, threat level, analysis, default tags,
   default galaxy clusters).
6. Click **Save**. The server validates the definition; errors are
   surfaced inline.

You can come back and edit the template at any time. Each save
bumps the template's `version` integer and writes a full snapshot
to the audit log.

## Element types

| Type | Purpose |
|---|---|
| **Section** | Visual grouping for the user form; carries a label and optional help text. No data. |
| **Text block** | Static instructional prose for the user. Markdown, rendered safely (raw HTML stripped, unsafe URI schemes filtered). No label. |
| **Attribute field** | Single MISP attribute. Pick **category** + **type**, optionally set `to_ids` default, mandatory flag, repeatable flag, comment template, and a default value. |
| **Object field** | Full MISP object. Pick the object template; the builder pins its current version. Per object-relation: override mandatory, set a default, hide the relation, override its label, override its help text. The whole object can be made repeatable. |
| **Tag field** | Tag picker for the user. Restrict to one or more taxonomies, set mandatory, single vs. multi. |
| **Galaxy field** | Galaxy cluster picker for the user. Restrict to one or more galaxy types, set mandatory, single vs. multi. |
| **File field** | File upload that becomes an `attachment` or `malware-sample` attribute (creator chooses `as`). |
| **Object reference** | Declares a relationship between two `object_field`s; materialised at event creation. Not user-facing. |

Every interactive element gets a stable **id** (auto-generated, but
editable). Ids are used in `info_template` variable substitution,
`object_reference` endpoints, and any future conditional logic.

## Labels and help text

Labels are **plain text and mandatory** for every interactive
element. Help text is optional and supports Markdown.

For object fields specifically, you can override the per-relation
label and help text — this is how you tell the user "Sender address
— exactly as it appears in the From: header, do not normalise"
instead of just letting them see MISP's terse built-in description.

Help text renders inline alongside the field on the user form.
Investing time here pays off every time a user hits the template.

## Event-level defaults

Set on the template itself; applied automatically when an event is
created from this template.

- **Info field pattern** — Variable substitution supported:
  - `{{date}}` — `Y-m-d` of event creation.
  - `{{now}}` — ISO-8601 timestamp.
  - `{{user}}` — template user's email.
  - `{{field:<element_id>}}` — value entered into another field
    (first value if repeatable/multi).

  Example: `Spearphishing — {{date}} — {{field:sender}}`

  Unknown or unfilled variables render as empty strings. Malformed
  `{{...}}` expressions fail validation at save time.

- **Distribution / sharing group** — pick a default. The user can
  override unless you mark it `locked`.
- **Threat level / analysis** — same.
- **Default tags** — applied unconditionally on creation.
- **Default galaxy clusters** — same.

Locked defaults render read-only on the user form.

## Object references

To declare a structured relationship between two object fields
(e.g. "this email *has-attachment* this file"), drop in an
**object reference** element after both endpoints exist. Pick:

- **From** — source object field id.
- **To** — target object field id.
- **Relationship type** — pulled from MISP's known object
  relationships.
- Optional **comment**.

The reference is materialised automatically when the event is
created. If either endpoint is repeatable and the user adds multiple
instances, only the first instance of each side is wired up — add
more `object_reference` elements explicitly for additional pairs.

## Validation behaviour

Save runs the server-side validator. It enforces:

- non-empty label on every interactive element;
- no duplicate element ids;
- valid attribute category + type combinations (against MISP's
  built-in `MispAttribute::typeDefinitions`);
- every referenced object template exists on this instance at the
  pinned-or-higher version;
- every `object_reference` endpoint points to an existing
  `object_field` element id;
- `{{...}}` info-template variables refer to real ids.

Validation runs on every save and on the **Validate** button in the
builder; both surface the same structured errors. There is no
client-side schema validation in v1 — the server is authoritative.

## Preview

Click **Preview** in the builder to open the user form in a new
tab. The preview shows the form exactly as the template user will
see it, with the submit button disabled and a yellow banner
indicating preview mode. Preview reflects the **last saved** version
of the template — save first to preview unsaved changes.

## Permissions and distribution

- **Author / edit / delete a template** — requires the
  `perm_template` role flag, plus belonging to the template's
  `org_id` (site admins can edit any).
- **See a template** — own org's templates plus any template
  marked `distribution = community`.
- **Use a template (create event from)** — requires `perm_add`,
  plus visibility of the template per the rule above.

`distribution` has two values in v1:
- **0 — Org only.** Visible only to your organisation. Default.
- **1 — Community.** Visible to every user on this MISP instance.

There is no cross-instance sync of templates in v1.

## Exporting and importing

- **Export** — From the template view page or per-row on the index,
  the **Export** button downloads a self-contained JSON document
  including the template envelope and full definition. Object
  templates referenced by the template are embedded by reference
  (uuid + pinned version), not by value — the importer must already
  have those object templates installed.

- **Import** — From the index toolbar, **Import** opens a form to
  upload a JSON file. Validation runs the full pipeline (structural
  + semantic, including object-template dependency check). UUID
  collisions: pass `mode=overwrite` to replace, `mode=duplicate_as_new`
  to mint a fresh uuid; default behaviour is to fail with a clear
  error.

- **Duplicate** — From the index, the per-row Duplicate action
  clones a template into your org with a fresh uuid.

## Audit log

The audit log captures:

- **Template CRUD** — full JSON snapshot on every save (`add` / `edit`),
  delete (`delete`), and undelete (`undelete`).
- **Event creation from template** — an `instantiate` row tying the
  new event back to the template (model `EventTemplate`, model_id
  template id, event_id new event id, change payload with
  uuid + version + name).

This is the canonical "what template was used to create this event"
record in v1. The originating template is **not** persisted on the
event row itself.

## REST API

Every UI flow has a REST equivalent under `/event_templates`. See
PRD §9 for the full list. The builder uses
`POST /event_templates/validate_definition` to surface server errors
inline; `POST /event_templates/instantiate/{id}` is what the user
form posts to.

## The shared library

There is a community-curated catalogue of event templates at
[MISP/misp-event-templates](https://github.com/MISP/misp-event-templates),
shipped with MISP as a submodule at
`app/files/misp-event-templates/`. Site admins drive it via the
**Update from library** button on the events-templates index — see
the [event-template library admin guide](event-template-library-admin)
for the operator-side flow.

If you author a template that you think other teams could use,
consider contributing it upstream — the bar is "a template several
SOC teams could plausibly want." See that repo's `CONTRIBUTE.md`
for the authoring conventions and PR review checklist.
