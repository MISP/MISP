# MISP Web UI – Import Export – Export Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Export – MISP JSON](#export-misp-json) | |
| 2 | [Export – CSV formulas](#export-csv-formula) | |
| 3 | [Export – STIX 2](#export-stix2) | |
| 4 | [Export – several events](#export-selected) | |
| 5 | [Export – cached exports](#export-cached) | |

---


# E2E Tests

### Export – MISP JSON
<a id="export-misp-json"></a>

Downloading an event as MISP JSON

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open `QA export csv formula` and use **Download as** → MISP JSON.
4. Open the downloaded file.

**Expected:** the file is valid JSON and contains the event and all its attributes.

**Seeded data:** `QA export csv formula`. Through the API, the JSON export answers in about 0.2 s.

### Export – CSV formulas
<a id="export-csv-formula"></a>

Values starting with = or + are neutralised in the CSV export (regression test for Bug 14)

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open `QA export csv formula` and use **Download as** → **CSV (NOT FOR EXCEL)**.
4. Open the file in a text editor.

**Expected:** the comments `=HYPERLINK("http://qa-csv.example","click")` and `+cmd|calc` are written so that a spreadsheet does not run them (e.g. prefixed with `'`).

**Seeded data:** `QA export csv formula` (tag `qa:export-csv-formula`) has two attributes with these comments. Through the API, the CSV export writes them unchanged (see Bug 14).

### Export – STIX 2
<a id="export-stix2"></a>

Downloading an event as STIX 2

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open `QA export csv formula` and use **Download as** → STIX 2.

**Expected:** a valid STIX 2 bundle is downloaded; no error page.

**Seeded data:** Through the API, the STIX 2 export of `QA export csv formula` answers in about 2.2 s (21 kB).

### Export – several events
<a id="export-selected"></a>

Exporting several selected events in one document

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Tick two events and click **Export** in the selection toolbar.
4. In **Export Format** choose MISP JSON and click **Export**.

**Expected:** one document with the two events is downloaded.

### Export – cached exports
<a id="export-cached"></a>

Generating a cached export

1. Log in to MISP as `site-admin`.
2. Go to `/events/export`.
3. Click **Generate** on the CSV export.
4. Wait and reload the page.

**Expected:** the export shows **Up to date** and can be downloaded; if the workers are down, the warning "Warning, the background worker is not responding!" is shown.
