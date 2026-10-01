# MISP Web UI – Attribute Add – Attachments Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Attachment – upload a file](#attribute-attachment-upload) | |
| 2 | [Attachment – malware sample](#attribute-attachment-malware) | |
| 3 | [Attachment – no file selected](#attribute-attachment-no-file) | |

---


# E2E Tests

### Attachment – upload a file
<a id="attribute-attachment-upload"></a>

Uploading a small file as an attachment

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA attachment` with **Add Event** and stay on its detail page.
4. Click **Add Attachment**.
5. Select a small text file `qa.txt` in **Files**.
6. Click **Upload**.
7. Download the attachment from the Attributes tab.

**Expected:** an `attachment` attribute `qa.txt` is shown, and the downloaded file is identical to the uploaded one.

### Attachment – malware sample
<a id="attribute-attachment-malware"></a>

Uploading a file as a malware sample stores it encrypted with its hashes

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA malware sample` with **Add Event** and stay on its detail page.
4. Click **Add Attachment**.
5. Select a small file `qa-sample.bin` in **Files**.
6. Tick **Malware Sample** (Encrypt and hash the uploaded file(s)).
7. Click **Upload**.

**Expected:** a `malware-sample` is saved with its md5, sha1 and sha256 hashes; downloading it gives a password-protected zip.

### Attachment – no file selected
<a id="attribute-attachment-no-file"></a>

Uploading without selecting a file

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA attachment empty` with **Add Event** and stay on its detail page.
4. Click **Add Attachment**.
5. Do not select any file.
6. Click **Upload**.

**Expected:** nothing is saved and a clear message asks to select a file; no error page.
