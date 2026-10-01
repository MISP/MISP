# MISP Web UI – Attribute Add – Batch Import Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Batch import – valid values](#attribute-batch-valid) | |
| 2 | [Batch import – some invalid values](#attribute-batch-partial) | |
| 3 | [Batch import – empty lines and spaces](#attribute-batch-blank-lines) | |
| 4 | [Batch import – same value twice](#attribute-batch-duplicates) | |

---


# E2E Tests

### Batch import – valid values
<a id="attribute-batch-valid"></a>

Adding several attributes at once, one value per line

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA batch valid` with **Add Event** and stay on its detail page.
4. Click **Add Attribute** and turn on **Batch Import**.
5. In **Category** select `Network activity` and in **Type** select `ip-dst`.
6. Type `198.51.100.40`, `198.51.100.41` and `198.51.100.42` in **Value**, one per line.
7. Click **Add Attribute** to save.

**Expected:** the three attributes are saved and shown in the Attributes tab.

### Batch import – some invalid values
<a id="attribute-batch-partial"></a>

A batch with valid and invalid values saves the valid ones and explains the others

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA batch partial` with **Add Event** and stay on its detail page.
4. Click **Add Attribute** and turn on **Batch Import**.
5. In **Category** select `Network activity` and in **Type** select `ip-dst`.
6. Type `198.51.100.43`, `999.1.1.1` and `198.51.100.44` in **Value**, one per line.
7. Click **Add Attribute** to save.

**Expected:** the two valid IPs are saved and the message says 1 attribute could not be saved, with a working link for more info (no raw text like `$flashErrorMessage`).

### Batch import – empty lines and spaces
<a id="attribute-batch-blank-lines"></a>

Empty lines and spaces in a batch do not create empty attributes

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA batch blank` with **Add Event** and stay on its detail page.
4. Click **Add Attribute** and turn on **Batch Import**.
5. In **Category** select `Network activity` and in **Type** select `ip-dst`.
6. Type `198.51.100.45`, an empty line, a line with only spaces, then `198.51.100.46` in **Value**.
7. Click **Add Attribute** to save.

**Expected:** exactly two attributes are saved; no empty attribute and no error for the blank lines.

### Batch import – same value twice
<a id="attribute-batch-duplicates"></a>

The same value twice in one batch is saved only once

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA batch duplicates` with **Add Event** and stay on its detail page.
4. Click **Add Attribute** and turn on **Batch Import**.
5. In **Category** select `Network activity` and in **Type** select `ip-dst`.
6. Type `198.51.100.47` twice in **Value**, on two lines.
7. Click **Add Attribute** to save.

**Expected:** `198.51.100.47` is saved once, and the message reports the duplicate as not saved.
