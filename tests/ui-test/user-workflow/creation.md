# MISP Web UI – User Workflows – Creation and Encoding Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Event creation – info, date, distribution](#wf-event-create) | |
| 2 | [Add object – IDS and correlation on one attribute, and a relationship](#wf-object-add) | |
| 3 | [Add attribute](#wf-attribute-add) | |
| 4 | [Add tag and galaxy cluster on the event](#wf-event-tag-cluster) | |
| 5 | [Add tag and galaxy cluster on an attribute](#wf-attribute-tag-cluster) | |
| 6 | [Edit event distribution](#wf-event-distribution) | |
| 7 | [Edit object comment](#wf-object-comment) | |
| 8 | [Edit attribute IDS state](#wf-attribute-ids) | |
| 9 | [Add event report](#wf-event-report) | |
| 10 | [Add a small attachment](#wf-attachment) | |
| 11 | [Populate from MISP JSON](#wf-populate-json) | |
| 12 | [Populate from freetext import](#wf-populate-freetext) | |
| 13 | [Enrich event](#wf-enrich) | |
| 14 | [Publish event](#wf-publish) | |
| 15 | [Batch import of attributes](#wf-batch-import) | |
| 16 | [Delete and restore an attribute](#wf-delete-restore) | |

---


# E2E Tests

### Event creation – info, date, distribution
<a id="wf-event-create"></a>

Creating an event with its main fields

- **Role:** `user` of the organisation `ADMIN`
- **Test data (before):** `None`
- **Cleanup (after):** delete the event `QA wf create {timestamp}`

1. Open `/events/index`.
2. Click the **button** "Add Event".
3. In the **Add Event** window, type `QA wf create {timestamp}` in the **textbox** "Event Info".
4. Type `15/09/2026` in the **textbox** "Event Date (UTC)".
5. Choose **This community only** in **Distribution**.
6. Click the **button** "Create Event Entry".

**Expected:**
- The URL is `/events/view2/<id>`.
- The title `QA wf create {timestamp}` is visible.
- The event shows the date `2026-09-15` and the distribution **This community only**.

### Add object – IDS and correlation on one attribute, and a relationship
<a id="wf-object-add"></a>

Adding an object, changing the IDS and correlation state of one of its attributes, then relating it to another attribute

- **Role:** `user` of the organisation `ADMIN`
- **Test data (before):** event `QA wf object {timestamp}` created through the API (distribution **Your organisation only**) with the attribute `203.0.113.60` (`ip-dst`)
- **Cleanup (after):** delete the event `QA wf object {timestamp}`
- **Known bugs on the way:** Bug 4 (submitting a new object may show a CSRF error)

1. Open the event page of `QA wf object {timestamp}`.
2. Click the **button** "Add object".
3. Type `domain-ip` in the **combobox** "Template", choose `domain-ip` and click the **button** "Next".
4. Type `qa-wf-object.example` in the **textbox** "domain" and `203.0.113.61` in the **textbox** "ip".
5. On the row `ip`, turn **off** the **checkbox** "IDS" and turn **off** the **checkbox** "Correlate".
6. Click the **button** "Review", then the **button** "Submit".
7. Open the **tab** "Objects".
8. Open the **⋮** menu of `203.0.113.61` and click the **menu item** "Add relationship".
9. In the **Add Relationship** window, type `related-to` in the **textbox** "Relationship type", choose the attribute `203.0.113.60` as **Related object** and save.

**Expected:**
- The object `domain-ip` shows `qa-wf-object.example` and `203.0.113.61`.
- `203.0.113.61` has IDS **off** and correlation **off**; `qa-wf-object.example` has IDS **on** and correlation **on**.
- `203.0.113.61` shows a `related-to` relationship to `203.0.113.60`.

### Add attribute
<a id="wf-attribute-add"></a>

Adding a single attribute to an event

- **Role:** `user` of the organisation `ADMIN`
- **Test data (before):** event `QA wf attribute {timestamp}` created through the API (distribution **Your organisation only**)
- **Cleanup (after):** delete the event `QA wf attribute {timestamp}`

1. Open the event page of `QA wf attribute {timestamp}`.
2. Click the **button** "Add attribute".
3. Choose `Network activity` in the **combobox** "Category" and `domain` in the **combobox** "Type".
4. Type `qa-wf-attribute.example` in the **textbox** "Value" and tick the **checkbox** "For IDS".
5. Click the **button** "Add Attribute".

**Expected:**
- The URL is `/events/view2/<id>` on the **tab** "Attributes".
- The row `qa-wf-attribute.example` is visible with type `domain` and IDS **on**.

### Add tag and galaxy cluster on the event
<a id="wf-event-tag-cluster"></a>

Classifying an event with a tag and a galaxy cluster

- **Role:** `user` of the organisation `ADMIN`
- **Test data (before):** event `QA wf event tags {timestamp}` created through the API (distribution **Your organisation only**)
- **Cleanup (after):** delete the event `QA wf event tags {timestamp}`

1. Open the event page of `QA wf event tags {timestamp}`.
2. Click the **button** "Edit Tags".
3. Type `tlp:green` in the **textbox** "Search tags to add…", choose `tlp:green` under **Global Tags** and click the **button** "Save Tags".
4. Click the **button** "Edit Galaxy Clusters".
5. Search `Phishing`, choose the cluster `Phishing - T1566` and save.

**Expected:**
- The text "Tags updated." is visible after step 3.
- The event shows the tag `tlp:green` and the cluster `Phishing - T1566`.

### Add tag and galaxy cluster on an attribute
<a id="wf-attribute-tag-cluster"></a>

Classifying one attribute with a tag and a galaxy cluster

- **Role:** `user` of the organisation `ADMIN`
- **Test data (before):** event `QA wf attribute tags {timestamp}` created through the API (distribution **Your organisation only**) with the attribute `203.0.113.62` (`ip-dst`)
- **Cleanup (after):** delete the event `QA wf attribute tags {timestamp}`

1. Open the event page of `QA wf attribute tags {timestamp}`.
2. Open the **tab** "Attributes".
3. On the row `203.0.113.62`, click the **button** "+" of the **Tags** column, choose `tlp:amber` and save.
4. On the same row, click the **button** "+" of the **Galaxy** column, search `Phishing`, choose `Phishing - T1566` and save.

**Expected:**
- The row `203.0.113.62` shows the tag `tlp:amber` and the cluster `Phishing - T1566`.
- The event itself does not show `tlp:amber`.

### Edit event distribution
<a id="wf-event-distribution"></a>

Changing who can see an event

- **Role:** `user` of the organisation `ADMIN`
- **Test data (before):** event `QA wf distribution {timestamp}` created through the API (distribution **Your organisation only**)
- **Cleanup (after):** delete the event `QA wf distribution {timestamp}`

1. Open the event page of `QA wf distribution {timestamp}`.
2. Click the **button** "Edit Event".
3. Choose **All communities** in **Distribution**.
4. Click the **button** "Save Changes".

**Expected:**
- The URL is `/events/view2/<id>`.
- The event shows the distribution **All communities**.

### Edit object comment
<a id="wf-object-comment"></a>

Changing the comment of an object

- **Role:** `user` of the organisation `ADMIN`
- **Test data (before):** event `QA wf object comment {timestamp}` created through the API (distribution **Your organisation only**) with a `domain-ip` object `qa-wf-comment.example`
- **Cleanup (after):** delete the event `QA wf object comment {timestamp}`

1. Open the event page of `QA wf object comment {timestamp}`.
2. Open the **tab** "Objects".
3. Click the **button** "Edit object" on the object `domain-ip`.
4. Type `QA comment {timestamp}` in the **textbox** "Comment".
5. Click the **button** "Review", then the **button** "Submit".

**Expected:**
- The text "Object saved." is visible.
- The object shows the comment `QA comment {timestamp}`.

### Edit attribute IDS state
<a id="wf-attribute-ids"></a>

Turning the IDS flag of an attribute off

- **Role:** `user` of the organisation `ADMIN`
- **Test data (before):** event `QA wf ids {timestamp}` created through the API (distribution **Your organisation only**) with the attribute `203.0.113.63` (`ip-dst`, For IDS)
- **Cleanup (after):** delete the event `QA wf ids {timestamp}`

1. Open the event page of `QA wf ids {timestamp}`.
2. Open the **tab** "Attributes".
3. Click **Edit** on `203.0.113.63`.
4. Untick the **checkbox** "For IDS".
5. Click the **button** "Save Changes".

**Expected:**
- The row `203.0.113.63` shows IDS **off**.

### Add event report
<a id="wf-event-report"></a>

Writing a Markdown report on an event

- **Role:** `user` of the organisation `ADMIN`
- **Test data (before):** event `QA wf report {timestamp}` created through the API (distribution **Your organisation only**)
- **Cleanup (after):** delete the event `QA wf report {timestamp}`
- **Known bugs on the way:** Bug 10 (after saving, the old event page `/events/view/<id>` may open)

1. Open the event page of `QA wf report {timestamp}`.
2. Open the **tab** "Reports".
3. Click the **button** "Add Event Report".
4. Type `QA report {timestamp}` as name and `# Summary` / `- First finding` in **Content**.
5. Save the report.

**Expected:**
- The report `QA report {timestamp}` is listed in the **tab** "Reports".
- Opening it shows "Summary" as a heading and "First finding" as a list item.
- The page is still `/events/view2/<id>`.

### Add a small attachment
<a id="wf-attachment"></a>

Uploading a small file as an attachment

- **Role:** `user` of the organisation `ADMIN`
- **Test data (before):** event `QA wf attachment {timestamp}` created through the API (distribution **Your organisation only**); a local text file `qa-note.txt` with the content `QA attachment {timestamp}`
- **Cleanup (after):** delete the event `QA wf attachment {timestamp}`

1. Open the event page of `QA wf attachment {timestamp}`.
2. Click the **button** "Add Attachment".
3. Select `qa-note.txt` in **Files** (leave **Malware Sample** off).
4. Click the **button** "Upload".

**Expected:**
- The **tab** "Attributes" shows an `attachment` attribute `qa-note.txt`.
- Downloading it gives a file with the content `QA attachment {timestamp}`.

### Populate from MISP JSON
<a id="wf-populate-json"></a>

Adding attributes to an event from a MISP JSON document

- **Role:** `user` of the organisation `ADMIN`
- **Test data (before):** event `QA wf json {timestamp}` created through the API (distribution **Your organisation only**)
- **Cleanup (after):** delete the event `QA wf json {timestamp}`

1. Open the event page of `QA wf json {timestamp}`.
2. Open the **menu** "Populate from…" and click the **menu item** "MISP JSON".
3. Paste in the **textbox** "Paste MISP event JSON": `{"Event":{"Attribute":[{"type":"domain","category":"Network activity","value":"qa-wf-json.example","to_ids":true}]}}`
4. Click the **button** "Submit".

**Expected:**
- The **tab** "Attributes" shows `qa-wf-json.example` with type `domain` and IDS **on**.
- No new event is created (the event list does not show a second `QA wf json {timestamp}`).

### Populate from freetext import
<a id="wf-populate-freetext"></a>

Adding attributes to an event from free text

- **Role:** `user` of the organisation `ADMIN`
- **Test data (before):** event `QA wf freetext {timestamp}` created through the API (distribution **Your organisation only**)
- **Cleanup (after):** delete the event `QA wf freetext {timestamp}`

1. Open the event page of `QA wf freetext {timestamp}`.
2. Open the **menu** "Populate from…" and click the **menu item** "Freetext Import".
3. Paste `Seen: hxxp://qa-wf-freetext[.]example/login and 203.0.113[.]64` in the **textbox** of the **Freetext Import** window.
4. Click the **button** "Run Freetext Import".
5. Check that the list shows `http://qa-wf-freetext.example/login` (`url`) and `203.0.113.64` (`ip-dst`).
6. Click the **button** "Create attributes".

**Expected:**
- The **tab** "Attributes" shows `http://qa-wf-freetext.example/login` and `203.0.113.64`.

### Enrich event
<a id="wf-enrich"></a>

Running the enrichment modules on an event

- **Role:** `user` of the organisation `ADMIN`
- **Test data (before):** event `QA wf enrich {timestamp}` created through the API (distribution **Your organisation only**) with the attribute `qa-wf-enrich.example` (`domain`); at least one enrichment module enabled on the instance
- **Cleanup (after):** delete the event `QA wf enrich {timestamp}`

1. Open the event page of `QA wf enrich {timestamp}`.
2. Click the **button** "Enrich Event".
3. Choose an enabled module and start the enrichment.
4. Wait until the text "Enrichment results" is visible, or until the job is shown as finished.

**Expected:**
- The message "Enrichment runs as a background job; its results appear on the event once it completes." (or the results) is shown; no error page.
- When the job is finished, the attributes added by the module are listed in the **tab** "Attributes".

### Publish event
<a id="wf-publish"></a>

Publishing an event

- **Role:** `user` of the organisation `ADMIN` (with the publish permission, e.g. `org-admin`)
- **Test data (before):** event `QA wf publish {timestamp}` created through the API (distribution **Your organisation only**) with the attribute `203.0.113.65` (`ip-dst`)
- **Cleanup (after):** delete the event `QA wf publish {timestamp}`

1. Open the event page of `QA wf publish {timestamp}`.
2. Click the **button** "Publish Event".
3. Leave **Send notification email** off and confirm.

**Expected:**
- The URL is `/events/view2/<id>`.
- The event is shown as **Published**.

### Batch import of attributes
<a id="wf-batch-import"></a>

Adding several attributes of the same type at once

- **Role:** `user` of the organisation `ADMIN`
- **Test data (before):** event `QA wf batch {timestamp}` created through the API
- **Cleanup (after):** delete the event

1. Open the event page of `QA wf batch {timestamp}`.
2. Click the **button** "Add attribute".
3. Tick the **checkbox** "Batch Import".
4. Choose `Network activity` in the **combobox** "Category" and `ip-dst` in the **combobox** "Type".
5. Type `203.0.113.70`, `203.0.113.71` and `203.0.113.72` in the **textbox** "Value", one per line.
6. Click the **button** "Add Attribute".

**Expected:**
- The **tab** "Attributes" shows the 3 rows `203.0.113.70`, `203.0.113.71` and `203.0.113.72`, each with type `ip-dst`.
- There are exactly **3** new attributes (no empty attribute for an empty line).

### Delete and restore an attribute
<a id="wf-delete-restore"></a>

Removing a wrong attribute, then bringing it back

- **Role:** `user` of the organisation `ADMIN`
- **Test data (before):** event `QA wf restore {timestamp}` with the attributes `203.0.113.73` and `203.0.113.74` (`ip-dst`), created through the API
- **Cleanup (after):** delete the event

1. Open the event page of `QA wf restore {timestamp}` and the **tab** "Attributes".
2. Click **Delete** on `203.0.113.73`, choose the soft delete and confirm.
3. Check that the **row** `203.0.113.73` is **not** visible and `203.0.113.74` is still visible.
4. Click the **button** "Deleted".
5. Check that the **row** `203.0.113.73` is visible and marked as deleted.
6. Click **Restore** on `203.0.113.73` and confirm.
7. Click the **button** "Deleted" again to go back to the normal list.

**Expected:**
- After step 6, `203.0.113.73` is active again and visible in the normal list.
- `203.0.113.74` was never changed.
