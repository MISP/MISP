# MISP Web UI – User Workflows – Search Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Events list – search by tag](#wf-search-tag) | |
| 2 | [Events list – My events](#wf-my-events) | |
| 3 | [Events list – Org events](#wf-org-events) | |
| 4 | [Events list – sort by a column](#wf-sort) | |
| 5 | [Export several selected events](#wf-export-selected) | |
| 6 | [Create an event from a template](#wf-template) | |
| 7 | [Search an attribute by value](#wf-attribute-search) | |
| 8 | [Quick search of an event](#wf-quick-search) | |
| 9 | [Navigate through correlations](#wf-correlation-navigation) | |

---


# E2E Tests

### Events list – search by tag
<a id="wf-search-tag"></a>

Filtering the Events list on a tag

- **Role:** `user` of the organisation `ADMIN`
- **Test data (before):** two events created through the API: `QA wf tagged {timestamp}` with the tag `tlp:green`, `QA wf untagged {timestamp}` without tag
- **Cleanup (after):** delete both events

1. Open `/events/index`.
2. Click the **button** "More filters".
3. Choose `tlp:green` in the **combobox** "Tags".
4. Click the **button** "Apply filters".

**Expected:**
- The URL contains `searchtag:`.
- The **row** `QA wf tagged {timestamp}` is visible.
- The **row** `QA wf untagged {timestamp}` is **not** visible.

### Events list – My events
<a id="wf-my-events"></a>

Showing only the events created by me

- **Role:** `user` of the organisation `ADMIN`
- **Test data (before):** one event `QA wf mine {timestamp}` created by this user, and one event `QA wf other {timestamp}` created by `org-admin` of `ADMIN`, through the API
- **Cleanup (after):** delete both events

1. Open `/events/index`.
2. Click the **button** "My events".

**Expected:**
- The **row** `QA wf mine {timestamp}` is visible.
- The **row** `QA wf other {timestamp}` is **not** visible.

### Events list – Org events
<a id="wf-org-events"></a>

Showing only the events of my organisation

- **Role:** `user` of the organisation `ADMIN`
- **Test data (before):** one event `QA wf org A {timestamp}` (organisation `ADMIN`) and one event `QA wf org B {timestamp}` (organisation `QA-Org-B`, distribution **This community only**), through the API
- **Cleanup (after):** delete both events

1. Open `/events/index`.
2. Check that both rows are visible.
3. Click the **button** "Org events".

**Expected:**
- The **row** `QA wf org A {timestamp}` is visible.
- The **row** `QA wf org B {timestamp}` is **not** visible.

### Events list – sort by a column
<a id="wf-sort"></a>

Sorting the Events list by a column

- **Role:** `user` of the organisation `ADMIN`
- **Test data (before):** three events `QA wf sort 1 {timestamp}`, `QA wf sort 2 {timestamp}`, `QA wf sort 3 {timestamp}` created in this order through the API
- **Cleanup (after):** delete the three events

1. Open `/events/index`.
2. Click the **column header** "ID".
3. Click the **column header** "ID" again.

**Expected:**
- After step 2 the rows are in increasing ID order (`QA wf sort 1` before `QA wf sort 3`).
- After step 3 they are in decreasing ID order (`QA wf sort 3` before `QA wf sort 1`).
- The URL contains `sort:` and `direction:`.

### Export several selected events
<a id="wf-export-selected"></a>

Exporting several events in one document from the selection

- **Role:** `user` of the organisation `ADMIN`
- **Test data (before):** two events `QA wf export 1 {timestamp}` and `QA wf export 2 {timestamp}` with one attribute each, through the API
- **Cleanup (after):** delete both events and the downloaded file

1. Open `/events/index`.
2. Tick the **checkbox** of `QA wf export 1 {timestamp}` and of `QA wf export 2 {timestamp}`.
3. Check that the selection bar shows "Selected items: 2".
4. Click the **button** "Export" in the selection bar.
5. In the **Export Events** window, choose **MISP JSON** in **Export Format** and click the **button** "Export".

**Expected:**
- One file is downloaded.
- The file contains both `QA wf export 1 {timestamp}` and `QA wf export 2 {timestamp}` with their attributes.

### Create an event from a template
<a id="wf-template"></a>

Creating an event with the guided event template form

- **Role:** `user` of the organisation `ADMIN`
- **Test data (before):** the event template `Suspicious domain triage` is **Active** (set by a site admin)
- **Cleanup (after):** delete the event created by the template
- **Known bugs on the way:** Bug 9 (after creation the old event page `/events/view/<id>` opens)

1. Open `/events/index`.
2. Click the **button** "Add Event".
3. Click the **button** "Use a template".
4. In the **Create Event from Template** window, click `Suspicious domain triage`.
5. Type `qa-wf-template.example` in the **textbox** "Domain" and `2026-10-01T10:00:00Z` in the **textbox** "Date observed".
6. Click the **button** "Next" until the last step, choose `tlp:green` for the TLP and click the **button** "Create event".

**Expected:**
- A new event `Suspicious domain — qa-wf-template.example` is created.
- It contains the domain `qa-wf-template.example` and the tag `tlp:green`.
- The URL is `/events/view2/<id>`.

### Search an attribute by value
<a id="wf-attribute-search"></a>

Finding in which events a value is already known

- **Role:** `user` of the organisation `ADMIN`
- **Test data (before):** two events `QA wf known 1 {timestamp}` and `QA wf known 2 {timestamp}`, both with the attribute `203.0.113.80` (`ip-dst`), and a third event `QA wf other value {timestamp}` with `203.0.113.81`, created through the API
- **Cleanup (after):** delete the three events

1. Open `/attributes/index`.
2. Type `203.0.113.80` in the **textbox** "Filter by attribute value".
3. Press Enter.

**Expected:**
- Exactly **2** rows are listed, both with the value `203.0.113.80`.
- Their **Event ID** column points to `QA wf known 1 {timestamp}` and `QA wf known 2 {timestamp}`.
- `203.0.113.81` is **not** listed.

### Quick search of an event
<a id="wf-quick-search"></a>

Finding an event by a part of its name

- **Role:** `user` of the organisation `ADMIN`
- **Test data (before):** two events `QA wf quick alpha {timestamp}` and `QA wf quick beta {timestamp}`, created through the API
- **Cleanup (after):** delete both events

1. Open `/events/index`.
2. Type `quick alpha {timestamp}` in the **textbox** "Search by info, ID or UUID".
3. Press Enter.

**Expected:**
- The **row** `QA wf quick alpha {timestamp}` is visible.
- The **row** `QA wf quick beta {timestamp}` is **not** visible.
- The list stays on `/events/index` (with the search in the URL).

### Navigate through correlations
<a id="wf-correlation-navigation"></a>

Going from one event to a related event through a shared value

- **Role:** `user` of the organisation `ADMIN`
- **Test data (before):** two events `QA wf correl 1 {timestamp}` and `QA wf correl 2 {timestamp}`, both with the attribute `qa-wf-correl.example` (`domain`), created through the API
- **Cleanup (after):** delete both events

1. Open the event page of `QA wf correl 1 {timestamp}`.
2. Open the **tab** "Correlation".
3. Check that `QA wf correl 2 {timestamp}` is listed.
4. Click the **link** `QA wf correl 2 {timestamp}`.

**Expected:**
- The page of `QA wf correl 2 {timestamp}` opens at `/events/view2/<id>`.
- Its **tab** "Correlation" lists `QA wf correl 1 {timestamp}`.
- In its **tab** "Attributes", `qa-wf-correl.example` shows a correlation.
