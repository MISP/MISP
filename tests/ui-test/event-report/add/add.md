# MISP Web UI – Event Report – Write Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Report – Markdown](#report-markdown) | |
| 2 | [Report – HTML and scripts](#report-xss) | |
| 3 | [Report – name with HTML and emoji](#report-name) | |
| 4 | [Report – very large content](#report-large) | |
| 5 | [Report – reference to an attribute](#report-reference) | |
| 6 | [Report – delete and restore](#report-delete-restore) | |
| 7 | [Report – page shown after creating](#report-add-redirect) | |

---


# E2E Tests

### Report – Markdown
<a id="report-markdown"></a>

A report written in Markdown is rendered

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the event `QA event reports` and go to its event reports.
4. Add an event report `QA markdown` with a title, a bullet list and a table, and save.

**Expected:** the report view shows the title, the list and the table formatted (not the raw Markdown).

### Report – HTML and scripts
<a id="report-xss"></a>

HTML and scripts in a report are shown as text and never run

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the event `QA event reports` and go to its event reports.
4. Open the report `<b>QA report</b> 🚀`.
5. Click the link `click me`.

**Expected:** no alert pops up; `<script>…</script>` and `<img … onerror=…>` are shown as text; `click me` does not run JavaScript.

**Seeded data:** `QA event reports` has the report `<b>QA report</b> 🚀` (tag of the event `qa:report-xss`) whose content contains `<script>alert('qa-script')</script>`, `<img src=x onerror=…>`, `[click me](javascript:…)` and `![img](javascript:…)`. Checked as `qa-orgadmin-a`: the report page and the event page send the content escaped (`<\/script>` inside JSON) and the Markdown renderer runs with HTML off; the final rendering is still to check in a browser.

### Report – name with HTML and emoji
<a id="report-name"></a>

A report name with HTML tags and an emoji

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the event `QA event reports` and go to its event reports.
4. Look at the name of the report `<b>QA report</b> 🚀` in the list and in its tab.

**Expected:** the name is shown exactly as typed, `<b>` visible as text and not as bold, with the emoji.

**Seeded data:** Saved through the API without error (the `event_reports` table is `utf8mb4`); the pages send the name escaped.

### Report – very large content
<a id="report-large"></a>

A report of 3 MB stays usable

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the event `QA event reports` and go to its event reports.
4. Open the report `QA big report`.
5. Scroll to the end and edit one word, then save.

**Expected:** the report opens and saves in a few seconds, without freezing the browser.

**Seeded data:** `QA event reports` has `QA big report` (about 3 MB). Through the API it was saved in 0.3 s and read back in 0.3 s; in a browser (Playwright) the report page shows its text after about 4.4 s.

### Report – reference to an attribute
<a id="report-reference"></a>

A reference to an attribute is shown as a link to that attribute

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the event `QA event reports` and go to its event reports.
4. Open the report `<b>QA report</b> 🚀` and find the line `Reference:`.

**Expected:** the reference shows the attribute `198.51.100.150` (value and type) and opens it on click.

**Seeded data:** The report contains `@[attribute](<uuid of 198.51.100.150>)`.

### Report – delete and restore
<a id="report-delete-restore"></a>

A deleted report can be restored

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the event `QA event reports` and go to its event reports.
4. Add a report `QA to delete`, delete it (soft delete) and confirm.
5. Show the deleted reports and restore `QA to delete`.

**Expected:** after the delete the report is marked deleted; after the restore it is back and readable.

### Report – page shown after creating
<a id="report-add-redirect"></a>

After creating an event report, the Overmind event page stays open (regression test for Bug 14)

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA report redirect` with **Add Event** and stay on its detail page.
4. Open the **Reports** tab, create a report `QA report` with some text and submit it.

**Expected:** the page is still `/events/view2/<id>` (Overmind layout) on the **Reports** tab and shows `QA report`; it does not go to `/events/view/<id>`.
