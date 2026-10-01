# MISP Web UI – Import Export – Freetext Import Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Freetext – defanged indicators](#freetext-defanged) | |
| 2 | [Freetext – punctuation and duplicates](#freetext-punctuation) | |
| 3 | [Freetext – types recognised](#freetext-types) | |
| 4 | [Freetext – no indicator](#freetext-nothing) | |
| 5 | [Freetext – bulk change before import](#freetext-bulk) | |
| 6 | [Freetext – create as proposals](#freetext-proposals) | |

---


# E2E Tests

### Freetext – defanged indicators
<a id="freetext-defanged"></a>

Defanged indicators are refanged

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA freetext defanged` with **Add Event** and stay on its detail page.
4. Click **Populate from** → **Freetext Import**.
5. Paste `hxxp://evil[.]example/login.php?id=1 and 198.51.100[.]120` and continue.

**Expected:** the resolution page proposes the `url` `http://evil.example/login.php?id=1` and the `ip-dst` `198.51.100.120`.

**Seeded data:** Checked through the API (`/events/freeTextImport`) on a temporary event: `hxxp://evil[.]example/login.php?id=1,` gave `url` `http://evil.example/login.php?id=1` (trailing comma removed) and `198.51.100[.]120:8443` gave `ip-dst|port` `198.51.100.120|8443`.

### Freetext – punctuation and duplicates
<a id="freetext-punctuation"></a>

Punctuation around indicators is removed and duplicates are kept once

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA freetext punctuation` with **Add Event** and stay on its detail page.
4. Click **Populate from** → **Freetext Import**.
5. Paste `See (https://qa-paren.example/path). Again 198.51.100.121 198.51.100.121.` and continue.

**Expected:** the resolution page proposes `https://qa-paren.example/path` (without the parenthesis) and `198.51.100.121` only once.

**Seeded data:** Checked through the API (`/events/freeTextImport`) on a temporary event: exactly these two values were returned, once each.

### Freetext – types recognised
<a id="freetext-types"></a>

IPv6, hash, email and CVE are recognised with the right type

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA freetext types` with **Add Event** and stay on its detail page.
4. Click **Populate from** → **Freetext Import**.
5. Paste `2001:db8::1 44d88612fea8a8f36de82e1278abb02f attacker@evil.example CVE-2024-3400` and continue.

**Expected:** the types proposed are `ip-dst`, `md5`, `email-src` and `vulnerability`.

**Seeded data:** Checked through the API (`/events/freeTextImport`) on a temporary event: these 4 types were returned.

### Freetext – no indicator
<a id="freetext-nothing"></a>

A text without any indicator

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA freetext nothing` with **Add Event** and stay on its detail page.
4. Click **Populate from** → **Freetext Import**.
5. Paste `nothing to see here` and continue.

**Expected:** the message "No indicators were detected in the provided text." is shown and nothing is created.

### Freetext – bulk change before import
<a id="freetext-bulk"></a>

Changing the type, comment and IDS flag of all found values at once

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA freetext bulk` with **Add Event** and stay on its detail page.
4. Click **Populate from** → **Freetext Import**.
5. Paste `198.51.100.123 198.51.100.124` and continue.
6. In **Bulk actions**, use **Change type for all** → `ip-src`, **Apply a comment to all** → `QA bulk`, and set **No IDS**.
7. Import the values.

**Expected:** both attributes are created as `ip-src`, with the comment `QA bulk` and IDS off.

### Freetext – create as proposals
<a id="freetext-proposals"></a>

Freetext values created as proposals instead of attributes

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA freetext proposals` with **Add Event** and stay on its detail page.
4. Click **Populate from** → **Freetext Import**.
5. Paste `198.51.100.125` and continue.
6. Tick **Create as proposals instead of attributes** and import.

**Expected:** no attribute is added; a proposal for `198.51.100.125` appears in `/shadow_attributes/index/all:0`.
