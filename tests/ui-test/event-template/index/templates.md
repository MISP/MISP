# MISP Web UI – Event Template Index – Templates Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Template active – offered in Add Event](#event-template-active-offered) | |
| 2 | [Template inactive – not usable by its URL](#event-template-inactive-url) | |
| 3 | [Template duplicate](#event-template-duplicate) | |
| 4 | [Template delete – library template](#event-template-delete-library) | |
| 5 | [Template library update – edited template](#event-template-update-forked) | |
| 6 | [Template export and import – same UUID](#event-template-import-conflict) | |
| 7 | [Template import – invalid JSON](#event-template-import-invalid) | |

---


# E2E Tests

### Template active – offered in Add Event
<a id="event-template-active-offered"></a>

An active template is offered in Add Event, and nothing is offered when no template is active

1. Log in to MISP as `site-admin`.
2. Go to `/event_templates/index`.
3. Check that every template is inactive (the library templates are inactive by default).
4. Go to `/events/index` and click **Add Event**.
5. Go back to `/event_templates/index` and make `Suspicious domain triage` **Active**.
6. Go to `/events/index` and click **Add Event**.
7. Click **Use a template**.
8. Make `Suspicious domain triage` inactive again.

**Expected:** with no active template, Add Event shows no **Use a template** block; with `Suspicious domain triage` active, the block is shown and the picker offers `Suspicious domain triage`.

**Seeded data:** No data needed. Checked on the Add Event page as `qa-orgadmin-a`: no **Use a template** block while all 10 templates were inactive, block shown once `Suspicious domain triage` was made active (then made inactive again).

### Template inactive – not usable by its URL
<a id="event-template-inactive-url"></a>

An inactive template cannot be used by opening its URL (regression test for Bug 11)

1. Log in to MISP as `user` of the organisation `ADMIN`.
2. Go to `/event_templates/index`.
3. Check that `Suspicious domain triage` is inactive.
4. Go to `/event_templates/instantiate/<id>` (`<id>` = ID of `Suspicious domain triage` in `/event_templates/index`).
5. Fill the mandatory fields (`domain` = `qa-inactive.example`, `date_observed` = today, `tlp` = `tlp:green`) and click **Create event**.

**Expected:** the form is refused (the template is inactive) and no event is created.

**Seeded data:** The template `Suspicious domain triage` is inactive. Through the API, `qa-user-a` (role `User`) posted the mandatory values to `/event_templates/instantiate/<id>` (`<id>` = ID of `Suspicious domain triage` in `/event_templates/index`) and the event `Suspicious domain — qa-inactive.example` (tag `qa:event-template-inactive-url`) was created.

### Template duplicate
<a id="event-template-duplicate"></a>

Duplicating a library template gives an editable copy

1. Log in to MISP as `site-admin`.
2. Go to `/event_templates/index`.
3. Click **Duplicate** on `Suspicious domain triage`.
4. Open the copy and click **Edit**.

**Expected:** a template `Suspicious domain triage (copy)` is created, it is **Active**, it is not marked **Library-managed**, and it can be edited.

### Template delete – library template
<a id="event-template-delete-library"></a>

Deleting a library-managed template warns that the library update brings it back

1. Log in to MISP as `site-admin`.
2. Go to `/event_templates/index`.
3. Click **Delete** on `UAV observation`.
4. Read the confirmation message and confirm.
5. Click **Update from library**.

**Expected:** the confirmation says the template is library-managed and will come back with the next library update; after **Update from library**, `UAV observation` is listed as **Installed** and is back in the list.

### Template library update – edited template
<a id="event-template-update-forked"></a>

Editing a library template: warned overwrite, and kept only when it is no longer library-managed

1. Log in to MISP as `site-admin`.
2. Go to `/event_templates/index`.
3. Click **Edit** on `Vulnerability disclosure` and read the **Library-managed template** notice.
4. Change its description to `QA edited`, keep **Library-managed** ticked and save.
5. Click **Update from library**.
6. Click **Edit** on `Vulnerability disclosure` again, change its description to `QA edited`, untick **Library-managed** and save.
7. Click **Update from library**.

**Expected:** the notice says the next update overwrites the edits unless **Library-managed** is unticked; after step 5 the template is listed as **Updated** and its description is back to the library one; after step 7 it is listed under **Skipped (forked)** and keeps `QA edited`.

**Seeded data:** No data needed. Through the API: description of `Vulnerability disclosure` changed to `QA edited description` with **Library-managed** still on, then `/event_templates/update` listed it under `updated` and restored the library description (version 3), as the notice announces.

### Template export and import – same UUID
<a id="event-template-import-conflict"></a>

Re-importing an exported template with the three conflict modes

1. Log in to MISP as `site-admin`.
2. Go to `/event_templates/index`.
3. Click **Export** on `Credential exposure` and copy the JSON.
4. Click **Import Template**, paste the JSON in **Template Document**, keep `fail — abort the import (default)` and click **Import**.
5. Import the same JSON with `duplicate_as_new — assign a fresh UUID and save as new`.
6. Import the same JSON with `overwrite — replace in place, preserve original ownership`.

**Expected:** with `fail` the import is refused because the UUID exists; with `duplicate_as_new` a second `Credential exposure` with a new UUID is created; with `overwrite` the existing template is replaced and no new one is added.

### Template import – invalid JSON
<a id="event-template-import-invalid"></a>

Importing text that is not JSON

1. Log in to MISP as `site-admin`.
2. Go to `/event_templates/index`.
3. Click **Import Template**.
4. Paste `{ not json` in **Template Document** and click **Import**.

**Expected:** nothing is imported and the message "Could not import:" with "Could not parse import payload as JSON." is shown.
