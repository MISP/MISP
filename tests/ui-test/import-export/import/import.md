# MISP Web UI – Import Export – Import Event Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Import – MISP JSON](#import-misp-json) | |
| 2 | [Import – event already present](#import-duplicate) | |
| 3 | [Import – invalid file](#import-invalid) | |
| 4 | [Import – take ownership](#import-take-ownership) | |
| 5 | [Import – STIX 2](#import-stix2) | |

---


# E2E Tests

### Import – MISP JSON
<a id="import-misp-json"></a>

Importing a MISP JSON export creates the event

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Export any event as MISP JSON from another instance (or take a MISP JSON file whose UUID is not on this instance).
4. Click **Import Event** (`/events/add_misp_export`).
5. Paste the JSON in **Paste a MISP export** and click **Import MISP file**.

**Expected:** the event is created with its attributes, objects and tags.

### Import – event already present
<a id="import-duplicate"></a>

Importing an event that already exists on the instance

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open `QA export csv formula`, use **Download as** → MISP JSON.
4. Go to **Import Event** and import the downloaded file.

**Expected:** the import is refused with a clear message that the event already exists (the API answers "Event already exists, if you would like to edit it, use the url in the location header."); no duplicate event.

**Seeded data:** `QA export csv formula` (#108, tag `qa:export-csv-formula`). Through the API, adding its exported JSON again is refused with HTTP 404 and that message.

### Import – invalid file
<a id="import-invalid"></a>

Importing text that is not a MISP document

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **Import Event**.
4. Paste `{ not json` in **Paste a MISP export** and click **Import MISP file**.

**Expected:** nothing is imported and a clear message says the JSON is invalid.

**Seeded data:** Through the API, `/events/add_misp_export` with `{ not json` answers "Invalid JSON input. Make sure that the JSON input is a correctly formatted JSON string…".

### Import – take ownership
<a id="import-take-ownership"></a>

Importing with Take ownership of the event

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **Import Event**.
4. Paste a MISP JSON export created by another organisation, tick **Take ownership of the event** and import.

**Expected:** the imported event belongs to your organisation (**Creator Org** = your organisation).

### Import – STIX 2
<a id="import-stix2"></a>

Importing a STIX 2.x bundle

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **Import Event**, choose **STIX 2.x JSON — lossy**.
4. Upload a STIX 2.1 bundle with one `indicator` for `198.51.100.126` and import.

**Expected:** an event is created with an attribute `198.51.100.126`; no error page.
