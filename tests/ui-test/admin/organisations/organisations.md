# MISP Web UI – Admin Organisations Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Organisation delete – still used](#admin-org-delete-used) | |
| 2 | [Organisation add – emoji in the name](#admin-org-emoji) | |

---


# E2E Tests

### Organisation delete – still used
<a id="admin-org-delete-used"></a>

An organisation with users or events cannot be deleted

1. Log in to MISP as `site-admin`.
2. Go to `/organisations/index`.
3. Click **Delete** on `QA-Org-B` and confirm.

**Expected:** the deletion is refused with a message that the organisation still has users and events.

**Seeded data:** `QA-Org-B` has 2 users and events. Through the API the deletion is refused with HTTP 403, but only "Could not delete Organisation" (see Recommendation 3).

### Organisation add – emoji in the name
<a id="admin-org-emoji"></a>

An organisation name with an emoji (checks Bug 7 on organisations)

1. Log in to MISP as `site-admin`.
2. Go to `/organisations/index`.
3. Click **Add Organisation**, name it `QA Org 🚀` and save.

**Expected:** no "An Internal Error Has Occurred." page; the organisation is created with its emoji (delete it afterwards).
