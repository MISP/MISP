# MISP Web UI – General – Length Limits Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Too long text in add forms](#general-limits-forms) | |
| 2 | [Correlation exclusion – too long value](#general-limits-correlation-exclusion) | |
| 3 | [Too long search](#general-limits-search) | |

---


# E2E Tests

### Too long text in add forms
<a id="general-limits-forms"></a>

Every add form refuses a too long text with a message instead of an internal error (regression test for Bug 17)

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Prepare a text of 70,000 characters.
4. Paste it, one form at a time, in: the comment of **Add Attribute**, the comment of **Add Object**, the name of a new event report, the description of a new tag collection, the name of a new custom galaxy, the name of a new organisation, the name of a new sharing group, the description of a new warninglist, the name of a new feed, the name of a new role, the comment of a new event blocklist entry, the name of a new object relationship; save each time.

**Expected:** each form refuses the text with a message about the maximum length (or the field does not accept more characters); no "An Internal Error Has Occurred." page.

**Seeded data:** No data left. Through the same routes as the forms, on 2026-10-01, each of these fields gave HTTP 500 with 70,000 characters.

### Correlation exclusion – too long value
<a id="general-limits-correlation-exclusion"></a>

A too long correlation exclusion value is refused with a message (regression test for Bug 17)

1. Log in to MISP as `site-admin`.
2. Go to `/correlation_exclusions/add`.
3. Paste a text of 70,000 characters in the value field and save.

**Expected:** the exclusion is not saved and a message says the value is too long; no "An Internal Error Has Occurred." page.

### Too long search
<a id="general-limits-search"></a>

A very long search text is refused or cut instead of breaking the request (regression test for Bug 17)

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Paste a text of 20,000 characters in **Search by info, ID or UUID** and press Enter.

**Expected:** the search box limits the length or a clear message is shown; no "414 Request-URI Too Large" error and no silent failure.

**Seeded data:** Checked in a browser on 2026-10-01: the search request got HTTP 414 from nginx and the page showed nothing.
