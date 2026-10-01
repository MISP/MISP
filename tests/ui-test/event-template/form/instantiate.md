# MISP Web UI – Event Template Form – Create Event Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Template form – create an event](#event-template-create) | |
| 2 | [Template form – mandatory field empty](#event-template-mandatory) | |
| 3 | [Template form – invalid value](#event-template-invalid-value) | |
| 4 | [Template form – preview](#event-template-preview) | |
| 5 | [Template form – user of another organisation](#event-template-other-org) | |
| 6 | [Template form – page shown after creation](#event-template-redirect) | |

---


# E2E Tests

### Template form – create an event
<a id="event-template-create"></a>

Creating an event from a template with all mandatory fields

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Go to `/events/index`, click **Add Event**, click **Use a template** and choose `Suspicious domain triage` (make it **Active** first in `/event_templates/index` if needed).
4. Fill `domain` = `qa-template.example`, the observation date = today and `tlp` = `tlp:green`.
5. Go through the steps with **Next** and click **Create event**.

**Expected:** the message "Event created from template." is shown and the new event contains the domain `qa-template.example` and the tag `tlp:green`.

### Template form – mandatory field empty
<a id="event-template-mandatory"></a>

A step with an empty mandatory field cannot be passed

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Go to `/events/index`, click **Add Event**, click **Use a template** and choose `Suspicious domain triage` (make it **Active** first in `/event_templates/index` if needed).
4. Leave `domain` empty.
5. Click **Next**.

**Expected:** the step is not passed and the empty field is listed under **Mandatory fields in this step**.

### Template form – invalid value
<a id="event-template-invalid-value"></a>

A value refused by the server shows the reason and keeps what was typed

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Go to `/events/index`, click **Add Event**, click **Use a template** and choose `Suspicious domain triage` (make it **Active** first in `/event_templates/index` if needed).
4. Type `not a domain!` in `domain`, fill the other mandatory fields and click **Create event**.

**Expected:** no event is created, the message names the invalid field (`domain`) and why, and the form keeps the typed values.

**Seeded data:** No data needed. Through the API, `not a domain!` in `domain` was refused and nothing was created (rollback works), but the only reasons given are "Some attributes or objects were dropped during event creation." and "expected 2 top-level attribute(s), saved 1 — see audit log for dropped rows" (see Bug 12). The form sends the request in JavaScript and shows the errors in a panel, so the typed values stay on the page.

### Template form – preview
<a id="event-template-preview"></a>

The preview walks through the form without creating anything

1. Log in to MISP as `site-admin`.
2. Go to `/event_templates/index`.
3. Click **View** on `Suspicious domain triage` and open the preview.
4. Fill the fields and go to the last step.

**Expected:** the page says "Preview mode", the create button is **Create event (disabled in preview)**, and no event is created.

### Template form – user of another organisation
<a id="event-template-other-org"></a>

A user of another organisation can use a community template

1. Log in to MISP as `user` of the organisation `QA-Org-B`.
2. Go to `/events/index`.
3. Go to `/events/index`, click **Add Event**, click **Use a template** and choose `Suspicious domain triage` (it must be **Active**).
4. Fill the mandatory fields and click **Create event**.

**Expected:** the event is created and belongs to `QA-Org-B`, not to the organisation that owns the template.

### Template form – page shown after creation
<a id="event-template-redirect"></a>

After creating an event from a template, the Overmind event page opens (regression test for Bug 13)

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **Add Event**, click **Use a template** and choose `Suspicious domain triage` (make it **Active** first in `/event_templates/index` if needed).
4. Fill the mandatory fields and click **Create event**.

**Expected:** the new event opens at `/events/view2/<id>` in the Overmind layout, not at `/events/view/<id>`.
