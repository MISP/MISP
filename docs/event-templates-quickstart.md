# Event Templates — User Quickstart

Event templates let you create a MISP event from a pre-built form,
without having to know the full MISP type tree. Someone in your team
(a *template creator*) has authored a template for a recurring incident
type — your job, as a *template user*, is to fill it in.

## Creating an event from a template

1. Open the **Events** index in MISP.
2. Click **From template** in the toolbar (next to **Add Event**).
3. Pick a template from the list. Templates are searchable by name,
   description, or organisation.
4. Fill in the fields presented. Each field shows:
   - a **label** the template creator wrote;
   - optional **help text** explaining what to put in;
   - a red asterisk (`*`) if the field is **mandatory**.
5. Click **Create event**.

You will be redirected to the resulting event view. The event already
carries the template's default tags, galaxy clusters, info field
pattern, threat level, distribution, and analysis level — plus all
the attributes, MISP objects, and object references the template
declared. You can edit any of it from the standard event view
afterwards.

## Field types you may encounter

| Type | What you do |
|---|---|
| **Section** | Visual grouping; no input. |
| **Text block** | Static instruction from the creator; no input. |
| **Attribute field** | Single MISP attribute. Type one value. |
| **Object field** | Full MISP object (e.g. `email`, `file`). Expand to fill its sub-fields. |
| **Tag field** | Pick one or more tags from the allowed taxonomies. |
| **Galaxy field** | Pick one or more galaxy clusters from the allowed types. |
| **File field** | Upload one or more files. Each becomes an `attachment` or `malware-sample` attribute. |

Some object fields are **repeatable** — you can add or remove
instances using the buttons next to them. Sub-fields inside an object
may also be marked mandatory; the **Create event** button stays
disabled until every mandatory field is filled.

## Errors

- **"Mandatory field … is empty"** — fill the named field and try again.
- **"Referenced object template is not installed on this instance"** — the
  template references a MISP object template your instance does not
  have. Contact a site admin to install or upgrade it; the rest of
  the form is still usable but the affected object will be skipped.
- **"Some attributes or objects were dropped during event creation"** —
  the event was rolled back. The error message lists the offending
  rows; usually a value failed MISP's per-type validator (bad URL,
  malformed IP, etc.). Fix and re-submit.

If the **From template** button is missing on the events index, your
account does not have permission to create events from templates —
ask your administrator for the `perm_add` user role.
