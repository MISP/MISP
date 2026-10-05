# MISP Web UI – Use Case – Attachment Analysis Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Use case 4 – Analyse the email attachment](#use-case-attachment-analysis) | |

---


# E2E Tests

### Use case 4 – Analyse the email attachment
<a id="use-case-attachment-analysis"></a>

The second wave email had an attachment. The analyst stores it safely as a malware sample, gets its hashes and records the server it contacts. The attachment is a harmless text file that stands for the malware. Story: *Operation Fake-Parcel*, a fictional phishing campaign that sends fake parcel-delivery emails. All data is fictional and harmless (documentation IP ranges, `.example` domains).

- **Role:** `org-admin` of the organisation `ADMIN`
- **Test data (before):** event `Fake-Parcel attachment {timestamp}`, created through the API; a local text file `Delivery_Note.txt` containing `QA fake parcel attachment {timestamp}`
- **Cleanup (after):** delete the event
- **Known bugs on the way:** Bug 4 (adding the `domain-ip` object may show a CSRF error). Linking two objects together is not possible in the Overmind UI (Missing Features #1), so the link is written in the object comment.

**Phase 1 – Store the attachment safely**

1. Open the event page of `Fake-Parcel attachment {timestamp}`.
2. Click the **button** "Add Attachment".
3. Select the file `Delivery_Note.txt` in **Files** and tick the **checkbox** "Malware Sample".
4. Click the **button** "Upload".
5. Open the **tab** "Attributes" (or **Objects**) and check that a `malware-sample` for `Delivery_Note.txt` is listed with its `md5`, `sha1` and `sha256` hashes.

**Phase 2 – Record the server contacted by the attachment**

6. Click the **button** "Add object", type `domain-ip` in the **combobox** "Template", choose it and click the **button** "Next".
7. Type `update.parcel-tracking.example` in the **textbox** "domain" and `203.0.113.50` in the **textbox** "ip".
8. Type `C2 contacted by Delivery_Note.txt` in the **textbox** "Comment".
9. Click the **button** "Review", then the **button** "Submit".

**Phase 3 – Check the download is protected**

10. Download the `malware-sample` from the **tab** "Attributes".
11. Check that the downloaded file is a password-protected zip, not the plain text file.

**Expected:**
- The event has a `malware-sample` `Delivery_Note.txt` with its `md5`, `sha1` and `sha256`.
- The event has a `domain-ip` object `update.parcel-tracking.example` / `203.0.113.50` with the comment `C2 contacted by Delivery_Note.txt`.
- Downloading the sample gives a password-protected zip.
