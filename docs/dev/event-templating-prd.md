# Event Templating v2 — Product Requirements Document

**Status:** Draft v0.1 (for discussion, not yet approved)
**Author:** Andras Iklody + Claude
**Target branch:** `templating`
**Supersedes:** the legacy Templates system (`app/Controller/TemplatesController.php`, `app/Model/Template.php` and siblings), circa 2015, currently unmaintained.
**Implementation tracker:** [`event-templating-progress.md`](event-templating-progress.md) — live checklist of tasks per phase. See §14 for the phase summary; task-level detail lives in the tracker.

---

## 1. Context and problem

MISP has an event templating feature intended to let template creators encode playbooks for common incident types — e.g. a "spearphishing email" template that tells a template user exactly which fields to extract and what MISP type each maps to.

The feature has not been substantively updated in ~10 years. It predates **MISP Objects**, has no support for **tags/galaxies**, has no **REST API**, ships a clunky multi-step populate wizard built on jQuery UI with iframe file uploads, and is invisible to most new users (surfaced only as a sidebar link on the event view page). The data model is a three-table polymorphism (`template_elements` + one of `template_element_attributes` / `_texts` / `_files`) with no concept of structured objects.

At the same time, the feature still solves a real problem: **onboarding users into consistent IOC extraction from recurring incident types**, and demand for a modernised version is recurring.

This PRD covers a **ground-up rework**. The existing system will be deprecated and removed in a phased fashion (see §12).

## 2. Goals / non-goals

### Goals

- **G1.** Template creators can build rich templates in a modern visual editor, including attribute fields, full MISP objects, tag pickers, galaxy pickers, object references, and event-level defaults (tags, galaxy clusters, info-field patterns, threat level, analysis level, distribution). Every field is nameable and annotatable with explanatory text that renders to the template user.
- **G2.** Template users can create an event *from* a template as a first-class, single-page workflow — not a post-create populate step.
- **G3.** The rework supports both the default (Bootstrap 2.3.2) and Overmind (Bootstrap 5.3.8) themes, with look-and-feel native to each.
- **G4.** Templates are fully exposed via REST (CRUD + export/import + "instantiate as event").
- **G5.** Templates are exportable/importable as a **self-contained JSON document**, including references to the MISP object template versions they depend on.
- **G6.** Templates are org-scoped and optionally shared within the org. No cross-instance sync in v1.

### Non-goals (v1)

- Cross-MISP-instance sync of templates (like galaxies/object templates). Templates are local.
- A public/community registry of templates.
- Conditional field logic ("show field X if field Y filled") — explicitly deferred to v2.
- Computed fields beyond the natural "hash a file on upload" behaviour.
- A scripting/macro language inside templates.
- Migration tooling for the *data entered* by old templates into new ones. (The old populate flow did not persist its own state — it just produced event attributes, which are unaffected.)

## 3. Personas and key user journeys

### Personas

- **Template creator**: has `perm_template_editor`, knows MISP taxonomy and objects, builds templates for their team's recurring workloads.
- **Template user**: doesn't need `perm_template_editor`; needs `perm_add` (event creation). Uses templates to produce consistent events for an incident type without needing to know the full MISP type tree.
- **Site admin**: can manage all templates regardless of org.

### Journeys

**J1 — A template creator builds a template.** Creator opens *Event Templates → New*, names and describes the template. Sets event-level defaults (default TLP tag, default threat level, an info-field pattern `"Spearphishing — {{date}} — {{field:sender}}"`). Drags in a "section: Email headers" with attribute fields for sender, subject, received-from IP — each with a human-readable label and an explanatory help text aimed at the eventual template user. Drags in an `email` MISP object field, marks `from`, `subject`, `eml` as required-to-fill, and writes a short explanation on each relation so the user knows exactly what to paste. Drags in a repeatable `file-attachment` object field and declares an *object reference* from email to attachment (`has_attachment`). Adds a taxonomy-restricted tag picker (TLP + kill-chain only). Saves.

**J2 — A template user creates an event from a template.** User clicks *Add Event → From Template* on the events index, picks "Spearphishing email triage", lands on a single-page form with sections, inline pickers, and the creator's explanations alongside every field. Fills what they can. Mandatory fields are enforced client- and server-side. Clicks *Create event*. The server creates the event with the templated tags/clusters/info field, all attributes, all objects (with pre-set defaults and any user input), object references, and applies the template's own audit trail entry. The user lands on the resulting event.

**J3 — Import/export.** A template creator exports a template as JSON. Another org admin imports that JSON on a different MISP instance. On import, the system verifies required MISP object templates are installed with a compatible version; if not, it reports the gap and refuses to import (or imports in a disabled state — see §13).

## 4. Terminology

- **Event template** — the saved, versioned definition used to scaffold an event. The new concept introduced by this PRD.
- **Object template** — existing MISP concept for a structured object schema (e.g. `email`, `file`). Not changed by this PRD; event templates *reference* object templates.
- **Template definition** — the JSON document that describes a template's structure and defaults. Stored on the event template row.
- **Element** — a single node inside a template's structure (an attribute field, an object field, a section header, a tag picker, etc.).
- **Template creator / template user** — user creating the template / user filling it in to produce an event.

## 5. Functional requirements

### 5.1 Template creation

- **F1.1** Create, update, delete, list, and duplicate templates.
- **F1.2** Visual builder with drag-and-drop reordering, including inside sections.
- **F1.3** **Every interactive element carries a creator-authored label and an optional explanatory help text.** This is a first-class requirement, preserved from the legacy system and reinforced here: the template creator's job is not just to pick MISP types but to *explain to the template user what to put in each field and why*. Labels are plain text and mandatory; help text supports Markdown and is optional. For `object_field` elements, the creator can additionally provide per-relation label and help overrides so each sub-field of the object is individually explained. Help text renders inline alongside the field in the template user's form.
- **F1.4** Supported element types in v1 (each with label + help unless marked otherwise):
  - `section` — visual grouping with a label and optional help text (no data).
  - `text_block` — static instructional prose (Markdown, rendered safely on the user side). No label; content is the body.
  - `attribute_field` — single MISP attribute. Creator picks category + type, can set `to_ids` default, mandatory flag, repeatable flag, comment template, optional prefilled/default value. Label + help apply.
  - `object_field` — full MISP object. Creator picks object template (by name, with the pinned version recorded). Creator supplies a label and help text for the whole object. Then, per object-relation:
    - override mandatory (must-fill for the template user),
    - set a default value,
    - hide the relation from the template user entirely (creator-side override),
    - override the relation's label (what the user sees),
    - override/add help text for the relation (explanation for the user),
    - mark repeatable for the whole object (user can add N instances).
  - `tag_field` — tag picker for the template user. Creator can restrict to one or more taxonomies, set mandatory, single vs. multi. Label + help apply.
  - `galaxy_field` — galaxy cluster picker. Creator can restrict to one or more galaxy types, set mandatory, single vs. multi. Label + help apply.
  - `file_field` — file upload that becomes a `malware-sample` or `attachment` attribute (creator chooses). Label + help apply.
  - `object_reference` — declares a relationship between two `object_field`s that will be materialised when the event is created. Creator picks source field, target field, and MISP object-relationship type. Not user-facing.
- **F1.5** Event-level defaults baked into the template:
  - Default `info` field pattern, with variable substitution: `{{date}}`, `{{now}}`, `{{user}}`, `{{field:<id>}}` (pulls the user-filled value of another field by stable id).
  - Default `distribution`, `sharing_group_id` (if distribution = sharing group), `threat_level_id`, `analysis`.
  - Default event-level tags (applied unconditionally on creation).
  - Default event-level galaxy clusters.
  - All defaults are overridable by the template user at creation time unless the creator locks them (`locked: true`).
- **F1.6** Each element gets a stable, creator-assigned or autogenerated **id** (used in info-pattern variables, `object_reference` endpoints, and future conditional logic).
- **F1.7** Template-level metadata: name, description (Markdown, rendered to users on the template picker and at the top of the user form), org, `share_within_org` flag, `active` flag.
- **F1.8** Preview mode: the creator sees the user-facing form exactly as the template user will see it, including all labels and help text, without submitting.
- **F1.9** Validation on save: no duplicate element ids, every interactive element has a non-empty label, valid attribute category+type combinations, every `object_reference` points to existing object-field ids, every referenced object template exists on this instance at the pinned (or higher-compatible) version.

### 5.2 Template usage

- **F2.1** New entry point: `Add Event → From Template` alongside the existing `Add Event` on the events index page (and in the Overmind navigation).
- **F2.2** Template picker: searchable list of templates visible to the user (own org + site-admin scope). Shows name, description, last-updated, creator org.
- **F2.3** Single-page user form rendered from the template definition. Fields are grouped by section. Each field renders its creator-authored label and help text inline; per-relation labels and help appear alongside the corresponding sub-fields of an object.
- **F2.4** Inline pickers:
  - tag fields use the existing tag picker pattern, restricted to the creator-declared taxonomies;
  - galaxy fields use a new inline galaxy-cluster picker (see §10.3), restricted to the creator-declared galaxy types.
- **F2.5** Mandatory fields are enforced: submit button disabled until all are filled, with inline error messages on attempted submit.
- **F2.6** Repeatable fields: user can add/remove additional entries up to a declared max (default unlimited).
- **F2.7** File uploads are modern: `fetch` + `FormData`, progress bar, drag-to-drop zone, no iframes.
- **F2.8** Submit path: single server call, wrapped in a DB transaction, that creates the event, all attributes, all objects with their relations, all object references, applies tags and clusters, and returns either the created event id or a structured error list.
- **F2.9** On success, redirect to the event view.
- **F2.10** On partial failure, the transaction rolls back; no half-created event.

### 5.3 Management

- **F3.1** `perm_template_editor` role flag (rename of legacy `perm_template`, see §12).
- **F3.2** Site admins see and manage all templates.
- **F3.3** Templates can be active/inactive without being deleted.
- **F3.4** Audit log entries are written on template CRUD and on "event created from template" (capturing the template uuid + version used).

## 6. Data model

### 6.1 Storage choice: JSON-document with a thin relational envelope

**Decision:** store the template *structure* (elements, defaults, metadata-beyond-the-basics) as a single JSON document on the template row. A minimal set of columns remain relational for query, auth and list views.

**Rationale:**

| Concern | Relational fan-out | JSON-document |
|---|---|---|
| Heterogeneous element types (attribute, object, section, tag, galaxy, reference, file, future conditionals) | Many tables with polymorphic joins — what the legacy system already did, painfully. | One shape per element type, naturally expressible in JSON Schema. |
| Schema evolution (v1 → adds conditionals, computed fields, repeatable groups) | `ALTER TABLE` per change, per-row backfill | bump a `schema_version` field in the document |
| Import/export as JSON (required) | Custom serialiser + deserialiser | The DB value **is** the export payload |
| Cross-element queries (e.g. "find all templates that use object X") | Trivial with joins | Requires either in-memory scan (fine at expected scale) or a denormalised sidecar index |
| Integrity (e.g. "foreign key" from element to object template) | Enforced at DB level | Enforced in application validation on save |
| Consistency with rest of MISP | Relational is the norm | `Workflow` already stores its graph as JSON; this is a similar fit |

**Expected scale:** tens to low hundreds of templates per instance, tens of elements per template. Any query across templates is admin-tier, not hot-path. A JSON blob is appropriate.

**What stays relational:** the envelope columns needed for listing, filtering, and auth, so we don't have to parse JSON for every index row. Object-template dependencies are also tracked relationally for cheap "which templates break if I uninstall object X" queries — this is the denormalised sidecar.

### 6.2 Tables

```sql
CREATE TABLE event_templates (
  id              INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  uuid            VARCHAR(40)      NOT NULL,
  name            VARCHAR(255)     NOT NULL,
  description     TEXT             NULL,
  org_id          INT(11) UNSIGNED NOT NULL,
  creator_user_id INT(11) UNSIGNED NOT NULL,
  share_within_org TINYINT(1)      NOT NULL DEFAULT 0,
  active          TINYINT(1)       NOT NULL DEFAULT 1,
  version         INT(11) UNSIGNED NOT NULL DEFAULT 1,
  definition      MEDIUMTEXT       NOT NULL,    -- JSON document (§7)
  created         DATETIME         NOT NULL,
  modified        DATETIME         NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uuid (uuid),
  KEY org_id (org_id),
  KEY name (name),
  KEY active (active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE event_template_object_dependencies (
  id                    INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  event_template_id     INT(11) UNSIGNED NOT NULL,
  object_template_uuid  VARCHAR(40)      NOT NULL,
  object_template_name  VARCHAR(255)     NOT NULL,
  pinned_version        INT(11) UNSIGNED NOT NULL,
  PRIMARY KEY (id),
  KEY event_template_id (event_template_id),
  KEY object_template_uuid (object_template_uuid)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

Dependencies in `event_template_object_dependencies` are regenerated from `definition` on every save — the JSON is the source of truth.

The `version` column increments on every structural edit. This gives us a simple "what version of the template was used to create this event" audit trail (stored in event metadata on creation).

## 7. Template definition JSON schema

The JSON schema below is the v1 target. Full schema lives in `app/files/schemas/event-template-v1.schema.json` (to be created) and is validated on every save.

```jsonc
{
  "schema_version": 1,
  "uuid": "b3c9a7c2-1f2a-4f5b-9b4e-a1e5b0c9e6a2",
  "name": "Spearphishing email triage",
  "description": "Extract IOCs from a flagged email, structured for downstream detection.",
  "event_defaults": {
    "info_template": "Spearphishing — {{date}} — {{field:sender}}",
    "distribution": 1,
    "sharing_group_id": null,
    "threat_level_id": 2,
    "analysis": 0,
    "tags": [
      { "name": "tlp:amber", "locked": true }
    ],
    "galaxy_clusters": [
      { "galaxy_type": "threat-actor", "value": "APT28", "locked": false }
    ]
  },
  "structure": [
    {
      "type": "section",
      "id": "s_headers",
      "label": "Email headers",
      "help": "Data visible in the raw email headers."
    },
    {
      "type": "attribute_field",
      "id": "sender",
      "parent": "s_headers",
      "label": "Sender email",
      "help": "The From: header.",
      "mandatory": true,
      "repeatable": false,
      "misp": {
        "category": "Payload delivery",
        "type": "email-src",
        "to_ids_default": true,
        "comment_template": "From: header",
        "default_value": null
      }
    },
    {
      "type": "object_field",
      "id": "obj_email",
      "parent": "s_headers",
      "label": "Full email object",
      "help": "Structured email details.",
      "mandatory": false,
      "repeatable": false,
      "object_template": {
        "uuid": "a0c666e0-fc67-4...",
        "name": "email",
        "pinned_version": 12
      },
      "relations": [
        { "object_relation": "from",    "mandatory": true,  "default_value": null, "hidden": false, "label_override": "Sender address",    "help_override": "Exactly as it appears in the From: header — do not normalise." },
        { "object_relation": "subject", "mandatory": true,  "default_value": null, "hidden": false, "label_override": null,                "help_override": "Full subject line, verbatim." },
        { "object_relation": "eml",     "mandatory": false, "default_value": null, "hidden": false, "label_override": "Full .eml file",    "help_override": "Attach the raw message if available. Optional but strongly encouraged." }
      ]
    },
    {
      "type": "object_field",
      "id": "obj_attachment",
      "label": "Attachments",
      "help": "Files that were attached to the email, if any.",
      "mandatory": false,
      "repeatable": true,
      "object_template": { "uuid": "...", "name": "file", "pinned_version": 25 },
      "relations": [
        { "object_relation": "filename", "mandatory": true,  "hidden": false, "label_override": null, "help_override": "Original filename as seen in the attachment." },
        { "object_relation": "sha256",   "mandatory": false, "hidden": false, "label_override": null, "help_override": null }
      ]
    },
    {
      "type": "object_reference",
      "id": "ref_1",
      "from": "obj_email",
      "to":   "obj_attachment",
      "relationship_type": "has-attachment",
      "comment": null
    },
    {
      "type": "tag_field",
      "id": "tags_campaign",
      "label": "Campaign tags",
      "restrict_taxonomies": ["tlp", "kill-chain"],
      "multiple": true,
      "mandatory": false
    },
    {
      "type": "galaxy_field",
      "id": "gal_actor",
      "label": "Suspected threat actor",
      "restrict_galaxy_types": ["threat-actor"],
      "multiple": false,
      "mandatory": false
    },
    {
      "type": "file_field",
      "id": "f_samples",
      "label": "Malware samples",
      "as": "malware-sample",
      "repeatable": true,
      "mandatory": false
    },
    {
      "type": "text_block",
      "id": "note_1",
      "content": "Do not forget to check DKIM/SPF in the raw headers."
    }
  ]
}
```

### 7.1 Variable substitution in `info_template`

Allowed expressions:
- `{{date}}` — `Y-m-d` of event creation
- `{{now}}` — ISO-8601 timestamp
- `{{user}}` — template user's email
- `{{field:<element_id>}}` — value entered into that field (first value if repeatable/multi)

Unknown or unfilled variables render as empty strings. Malformed `{{...}}` expressions fail validation at template save time.

### 7.2 Labels and help text

Every interactive element has a `label` (plain text, required, non-empty) and an optional `help` (Markdown, rendered safely). For `object_field` elements, each entry in `relations[]` may additionally carry `label_override` and `help_override` — when present they replace the object-template's own attribute name and description in the user form. When absent, the user form falls back to the object template's built-in attribute description. `label_override` is plain text; `help_override` is Markdown. This is the primary mechanism by which a template creator explains to the template user what to put into each field and why.

## 8. Permissions and distribution

- **Template-creator permission:** new role flag `perm_template_editor` (existing `perm_template` is migrated, see §12).
- **Read access:** user's org templates + templates with `share_within_org = 1` from other orgs in the same MISP instance. Site admin sees all.
- **Write access:** template creator must belong to the template's `org_id`, have `perm_template_editor`, and not be read-only. Site admin can always write.
- **Use (create event from):** any user with `perm_add` (event creation) who can read the template.
- **Distribution in v1:** per-org only. Cross-instance sync is out of scope.

## 9. REST API

All endpoints live under `/event_templates`.

| Method | Path | Description |
|---|---|---|
| `GET`    | `/event_templates` | List templates visible to user (filterable: `active`, `org_id`, `q`). Supports `application/json` and HTML. |
| `GET`    | `/event_templates/view/{id}` | Fetch one template including full `definition`. |
| `POST`   | `/event_templates/add` | Create a template. Body = full JSON definition + envelope fields. |
| `PUT`    | `/event_templates/edit/{id}` | Update. Bumps `version`. |
| `DELETE` | `/event_templates/delete/{id}` | Delete. |
| `POST`   | `/event_templates/duplicate/{id}` | Clone into a new template under the caller's org. |
| `GET`    | `/event_templates/export/{id}` | Returns the template JSON as `application/json` attachment. |
| `POST`   | `/event_templates/import` | Import a JSON file (multipart or raw JSON). Validates object-template deps. |
| `POST`   | `/event_templates/instantiate/{id}` | Body = user-filled values. Creates event transactionally. Returns `{ event_id, event_uuid }` or structured errors. |
| `POST`   | `/event_templates/validate_definition` | Validates a definition without saving (used by the builder). |

Authorisation is enforced on each route per §8. All responses conform to the existing `RestResponseComponent` conventions (envelope, error shape, pagination headers).

## 10. UI / UX

Two frontends, same backend. Each uses its theme's native idioms.

### 10.1 Builder (template-creator-facing, shared logic)

A single page, split:
- Left rail: list of element types to drag into the canvas, plus a properties panel for the currently selected element.
- Centre: the template canvas — sections expand/collapse, children shown nested, drag handles on each element. Click an element to edit it in the right panel.
- Right rail (collapsible): element properties form.
- Top bar: name, description, save, preview, export, active toggle.

Interaction model:
- Drag-and-drop reorder inside and across sections.
- Click-to-edit properties on the right.
- Inline validation errors (duplicate id, missing object template, etc.) shown on the element and summarised at the top.

### 10.2 Template-user form

Single page. Sections render as Bootstrap panels/cards (per theme). Each field is rendered by a type-specific partial that shows the creator's label and help text alongside the input. Mandatory markers, repeatable add/remove buttons. Submit button at the bottom; client-side validation blocks submission on missing mandatory fields, server-side validation returns authoritative errors on failure.

### 10.3 Theme variants

**Default theme (Bootstrap 2.3.2 + jQuery 3.6.1 + Chosen.js).** Views under `app/View/EventTemplates/` and elements under `app/View/Elements/eventTemplates/`. Follows existing MISP conventions (`.ctp` files, jQuery-driven, Chosen for multi-selects). Builder uses jQuery UI sortable (already bundled) for drag-and-drop — not SortableJS, to avoid a new dep on the default theme.

**Overmind theme (Bootstrap 5.3.8 + jQuery 3.6.1 + Tom Select).** Views under `app/View/Themed/Overmind/EventTemplates/`. Uses BS5 cards/buttons/forms, Tom Select for multi-selects. Builder uses SortableJS for drag-and-drop (Overmind is the "modern" path; SortableJS gives cleaner nested-list UX and mobile support).

Both frontends share the same REST backend and the same JSON definition shape. No component sharing beyond that.

### 10.4 Inline pickers (shared concern)

- **Tag picker:** reuse the existing `popoverPopup`/`selectTaxonomy` flow on the default theme; on Overmind, provide a Tom Select-based inline picker filtered to the creator's taxonomy restrictions.
- **Galaxy cluster picker:** new inline picker component in both themes. On the default theme, a modal with type-filtered cluster search (reusing the existing `/galaxies/view` AJAX). On Overmind, a Tom Select-based async picker hitting a new lean endpoint `GET /galaxy_clusters/search?galaxy_type=…&q=…`. Both are filtered to the creator's declared galaxy types.
- **Object template picker (builder only):** searchable list of locally installed object templates, showing name, meta-category, version. Used only by template creators in the builder.

## 11. Library and tech choices

Guiding principle: **don't introduce a new library if an equivalent is already in the codebase for that theme**; don't force either theme out of its native idiom.

| Concern | Default theme | Overmind | Rationale |
|---|---|---|---|
| Base CSS | Bootstrap 2.3.2 | Bootstrap 5.3.8 | Already in place; consistent with other views. |
| DOM / events | jQuery 3.6.1 | jQuery 3.6.1 | Already in place; no framework rewrite. |
| Multi-select | Chosen.js (present) | Tom Select (present) | Already in place per theme. |
| Drag and drop (builder) | jQuery UI Sortable (present, used by the legacy templates UI) | SortableJS (**new dep, ~40 KB**) | Classic theme keeps jQuery UI (zero new deps). Overmind gets SortableJS for modern nested-list UX; it has no runtime deps. |
| Reactive builder state | *None* — vanilla JS state object + imperative rerender | Alpine.js 3.x (**new dep, ~15 KB, loaded only on the builder view**) | The builder manages a small nested state tree. On the classic theme, vanilla JS is consistent with the rest of the app. On Overmind, Alpine.js makes the markup-driven reactivity in the properties panel much cleaner without imposing a full framework; it coexists with jQuery and Bootstrap 5. Asset inclusion is scoped to the builder view only (no global load). |
| JSON-schema validation | server-only | server-only | Authoritative validation runs in PHP on every save and on `validate_definition`. Builder surfaces the errors returned from the server; no client-side schema lib. |
| File upload UX | native `<input type=file>` + `fetch` + `FormData` | same | No new libs. |
| Markdown rendering (description, text_block, help text) | existing server-side renderer (Parsedown is used elsewhere in MISP) | same | Reuse what MISP already has. **TBD:** confirm which Markdown lib MISP currently uses. |

### 11.1 New dependencies — locked in

1. **SortableJS** — Overmind theme only, builder view only. MIT. ~40 KB min+gz. Latest release v1.15.7 (2026-02-11, one release cycle ago). No entries in the GitHub Advisory Database. No entries in Snyk's vulnerability DB for the package or any prior version. ~3.4 M weekly npm downloads, actively maintained (no archived/unmaintained signal).
2. **Alpine.js 3** — Overmind theme only, builder view only. MIT. ~15 KB min+gz. Loaded only on the event-template builder view (asset include gated on the action), not bundled into the global Overmind asset set.

No client-side JSON-schema validation in v1 — validation is server-side via `validate_definition` and the save endpoints.

## 12. Migration from the legacy Templates system

The legacy system spans: `Template`, `TemplateElement`, `TemplateElementAttribute`, `TemplateElementText`, `TemplateElementFile`, `TemplateTag` models; `TemplatesController`, `TemplateElementsController`; 15+ view files; `perm_template` role flag.

### Proposed plan

1. **Ship v2 side-by-side** under a new route (`/event_templates`), new controller, new models, new permission flag `perm_template_editor`. Zero impact on the legacy code path.
2. **Migrate `perm_template` → `perm_template_editor`** via a one-shot DB migration: every role with `perm_template = 1` also gets `perm_template_editor = 1`. Both flags coexist until step 5.
3. **Offer a one-shot migration CLI** (`app/Console/cake EventTemplate migrateFromLegacy`) that converts each legacy template row into a v2 JSON definition, preserving element ordering, mandatory flags, and tags. Files and texts map cleanly. The legacy "complex type" attribute flag maps to `repeatable: true` on a best-effort basis. Report any that can't be migrated cleanly.
4. **Add a UI notice** on the legacy Templates pages pointing users to the new UI and the migration CLI.
5. **Remove the legacy system in a follow-up release** (after a full release cycle with both in place). This includes: legacy routes, controllers, models, views, tables (`templates`, `template_elements`, `template_element_*`, `template_tags`), and `perm_template`.

Open question (see §16): does the user want the legacy UI removed immediately, or kept read-only through one release cycle?

## 13. Import / export

### Export

`GET /event_templates/export/{id}` returns a JSON document:

```jsonc
{
  "_meta": {
    "misp_version": "2.5.x",
    "exported_at": "2026-04-22T10:00:00Z",
    "event_template_schema_version": 1
  },
  "template": {
    "uuid": "…",
    "name": "…",
    "description": "…",
    "version": 3,
    "share_within_org": false,
    "active": true,
    "definition": { … full §7 JSON … }
  }
}
```

Object-template dependencies are embedded by reference (uuid + pinned version), not by value. Importers must have the object template already installed.

### Import

`POST /event_templates/import` accepts the same JSON. Validation pipeline:

1. JSON-schema validation against `event-template-v1.schema.json`.
2. For each `object_field`: verify the referenced object template exists on this instance and its version ≥ `pinned_version`. On version mismatch, report precisely which objects are missing/outdated.
3. UUID collision handling: if an event template with that uuid already exists, caller must pass `?mode=overwrite` or `?mode=duplicate_as_new` (fresh uuid).
4. The importer is assigned as creator. Template is assigned to importer's org.
5. On any failure, no DB state changes.

## 14. Phased delivery plan

High-level phases below. **Task-level breakdown and live progress tracking lives in [`event-templating-progress.md`](event-templating-progress.md).** Check items off there as they land on branch `templating`. Do not duplicate task-level detail into this PRD — this document is the spec and should describe *what* we are building, not how far along we are. The tracker also defines the **commit protocol** (message format, scope per commit, pre-commit checks) that must be followed for every task in the workflow.

| Phase | Scope | Exit criteria |
|---|---|---|
| **0 — Spec** | This PRD approved, JSON schema finalised, library choices locked in, open questions closed. | Sign-off to build. |
| **1 — Backend** | Models, migrations, JSON schema file, REST endpoints (all of §9), validation, audit log hooks, "instantiate as event" transactional creation. Integration tests hitting a real DB. | All §9 endpoints functional, integration tests green. |
| **2 — Default-theme UI** | Builder + template-user form in classic theme. Tag picker integration. Galaxy picker (modal). | Creator and user flows demoable end-to-end in default theme. |
| **3 — Overmind-theme UI** | Builder + template-user form in Overmind theme, including SortableJS, Tom Select pickers, Alpine.js. | Parity with phase 2 in Overmind. |
| **4 — Entry points and polish** | "Add Event → From Template" in event index and navigation. Events created from templates carry audit metadata. Preview mode. Import/export UI flows. | Feature is discoverable without explaining it to a new user. |
| **5 — Migration** | Legacy data migration CLI. Sunset notice on legacy UI. `perm_template_editor` flag migration. | Legacy templates can be converted to v2 with `cake` shell. |
| **6 — Removal** *(separate release)* | Delete legacy controllers, models, views, tables, `perm_template`. | Legacy code gone, no orphaned routes. |

Phases 1–4 are the v1 shipping target. 5 and 6 are follow-ups. Phases and tasks run **strictly sequentially** — implementation will proceed through a ralph-loop driver, one task at a time. No parallel code work.

## 15. Out of scope / future work

- **v2.0: conditional visibility.** `visible_if` predicates on elements, referencing sibling field ids. (Design space: boolean expressions over field values, or a simpler "X is filled" gate.)
- **v2.0: computed fields.** E.g. "sha256 of the uploaded file" as a first-class derived field, not relying on object-internal logic.
- **v2.0: repeatable sections** (today only single fields or full objects are repeatable).
- **v3.0: cross-instance sync** of templates via the sharing graph (or a public-feed-style mechanism).
- **v3.0: template library / starter pack** shipped with MISP, covering common incident types.
- **Template versioning and diff UI** (show what changed between versions 2 and 3 of a template).
- **Usage analytics** ("how many events have been created from this template in the last 30 days").

## 16. Open questions

*Resolved 2026-04-22:* SortableJS approved for Overmind builder; Alpine.js approved for Overmind builder with asset loading scoped to the builder view only; client-side JSON-schema validation dropped in favour of server-only.

1. **Legacy UI during the transition** (§12): keep it read-only through one release cycle, or remove it in the same release that ships v2?
2. **`perm_template` → `perm_template_editor` rename:** keep the legacy flag name to avoid disrupting existing roles, or take the chance to rename now?
3. **Markdown renderer** used elsewhere in MISP for `text_block` / help text: which lib, and is it XSS-safe out of the box? (TBD on inspection.)
4. **Default distribution for new templates:** inherit from `Config.default_event_distribution`, or hard-code org-only in v1?
5. **File upload size limit** for the `file_field` template-user flow: reuse the existing MISP attachment limit, or allow a creator-declared per-template override?
6. **"Site admin sees all templates":** confirm this matches the access model you want, or should site admins only see their own org's templates by default (with an admin override view)?
7. **Audit log granularity:** do you want per-field change tracking on template edits, or just "template edited, version 3 → 4" with the full JSON in the log?
8. **Cron / retention:** any need to auto-archive inactive templates, or purely a manual `active` flag?
