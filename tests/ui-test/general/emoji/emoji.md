# MISP Web UI – General – Emoji Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Emoji in every text field](#general-emoji-fields) | |

---


# E2E Tests

### Emoji in every text field
<a id="general-emoji-fields"></a>

Every form saves a text with an emoji without error (regression test for Bug 7)

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA emoji 🚀` and add an attribute `ip-dst` `198.51.100.170` with the comment `c 🚀`.
4. Add a `domain-ip` object with the domain `qa-emoji.example` and the comment `obj 🚀`.
5. Create a custom galaxy `QA galaxy 🚀`, and in another custom galaxy a cluster `QA cluster 🚀`.
6. Create an organisation `QA Org 🚀`, a sharing group `QA SG 🚀`, a tag collection `QA collection 🚀`, a feed `QA feed 🚀`, a warninglist `QA warninglist 🚀` and a role `QA role 🚀`.
7. Add an event blocklist entry with the comment `c 🚀`.
8. Delete everything created by this test.

**Expected:** every item is saved and shown with its emoji; no "An Internal Error Has Occurred." page.

**Seeded data:** No data left on the instance. Through the API on 2026-10-01, every item of steps 3 to 7 gave HTTP 500, except the Event Info `QA emoji 🚀` (saved). See Bug 7 for the full list.
