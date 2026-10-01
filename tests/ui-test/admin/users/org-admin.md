# MISP Web UI – Admin Users – Org Admin Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Org Admin – users list](#admin-orgadmin-users-list) | |
| 2 | [Org Admin – user of another organisation](#admin-orgadmin-edit-other-org) | |

---


# E2E Tests

### Org Admin – users list
<a id="admin-orgadmin-users-list"></a>

An organisation admin only sees the users of their organisation

1. Log in to MISP as `org-admin` of the organisation `QA-Org-B`.
2. Go to `/admin/users/index`.
3. Look at the users listed.

**Expected:** only `qa-user-b@qa-org-b.test` and `qa-orgadmin-b@qa-org-b.test` are listed.

**Seeded data:** Organisation `QA-Org-B` with 2 users. Through the API, `qa-orgadmin-b` sees exactly these 2 users.

### Org Admin – user of another organisation
<a id="admin-orgadmin-edit-other-org"></a>

An organisation admin cannot edit a user of another organisation

1. Log in to MISP as `org-admin` of the organisation `QA-Org-B`.
2. Go to `/admin/users/index`.
3. Go to `/admin/users/edit/3` (`qa-user-a@admin.test`, organisation `ADMIN`).

**Expected:** the page shows "Invalid user" and nothing can be changed.

**Seeded data:** User #3 `qa-user-a@admin.test` in `ADMIN`. Through the API, `qa-orgadmin-b` gets HTTP 404 "Invalid user".
