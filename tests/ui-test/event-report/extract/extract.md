# MISP Web UI – Event Report – Extract and Import Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Report – extract indicators](#report-extract) | |
| 2 | [Report – replacements are reviewed](#report-extract-review) | |
| 3 | [Report – import from URL disabled](#report-import-url-off) | |
| 4 | [Report – download as PDF](#report-pdf) | |
| 5 | [Report – old rendered view](#report-view-rendered) | |

---


# E2E Tests

### Report – extract indicators
<a id="report-extract"></a>

Indicators written in a report become attributes

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the event `QA event reports` and go to its event reports.
4. Open `<b>QA report</b> 🚀` and use the extraction of all entities.

**Expected:** the attributes `198.51.100.151`, `qa-report.example` and `44d88612fea8a8f36de82e1278abb02f` are added to the event.

**Seeded data:** Through the API (`extractAllFromReport`), these 3 attributes were added to `QA event reports` in 1.5 s.

### Report – replacements are reviewed
<a id="report-extract-review"></a>

Words of the report are not replaced by references without review

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the event `QA event reports` and go to its event reports.
4. Open `<b>QA report</b> 🚀`, run the extraction and look at the proposed replacements before applying them.

**Expected:** each replacement is shown for review and can be refused; ordinary words of the text are not changed silently.

**Seeded data:** Through the API, `extractAllFromReport` replaced the word `XSS` of the title `# QA XSS report` by `@[tag](misp-galaxy:veris-framework="XSS")` (a galaxy cluster with the same name) directly in the stored content.

### Report – import from URL disabled
<a id="report-import-url-off"></a>

Import from URL is refused when the setting is off

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the event `QA event reports` and go to its event reports.
4. Look for the import of a report from a URL and try it with `https://qa-report.example/page`.

**Expected:** the import is not offered, or it is refused with "This function can only be used with the setting `Security.eventreport_enable_arbitrary_urls` turned on."

### Report – download as PDF
<a id="report-pdf"></a>

Downloading a report as PDF

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the event `QA event reports` and go to its event reports.
4. Open `QA markdown` (see "Report – Markdown") and download it as PDF.

**Expected:** a readable PDF of the report is downloaded; no error page.

### Report – old rendered view
<a id="report-view-rendered"></a>

The rendered-report URL does not give an internal error

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Go to `/eventReports/viewRendered/<report id>` (ID of any event report, e.g. `<b>QA report</b> 🚀`).

**Expected:** the report is shown, or the page is not found; no "An Internal Error Has Occurred." page.

**Seeded data:** Checked as `qa-orgadmin-a`: HTTP 500, error.log `MissingViewException: View file "EventReports/view_rendered.ctp" is missing.`
