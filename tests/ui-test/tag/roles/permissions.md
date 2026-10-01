# MISP Web UI – Tag Roles – Permissions Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Global tag on another organisation's event](#tag-roles-global-other-org) | |
| 2 | [Local tag on another organisation's event](#tag-roles-local-other-org) | |
| 3 | [Tag restricted to an organisation](#tag-roles-restricted-org) | |
| 4 | [Tag create – User role](#tag-roles-create-user) | |

---


# E2E Tests

### Global tag on another organisation's event
<a id="tag-roles-global-other-org"></a>

Only the creator organisation can change the global tags of an event

1. Log in to MISP as `user` of the organisation `QA-Org-B`.
2. Go to `/events/index`.
3. Open the event `QA roles community event`.
4. Click **Edit Tags**, add `tlp:green` under **Global Tags** and click **Save Tags**.

**Expected:** the tag is refused with "Cannot alter the tags of this data, only the organisation that has created the data (orgc) can modify global tags."

**Seeded data:** `QA roles community event` (#102, org `ADMIN`, distribution **This community only**, tag `qa:tag-roles-global-other-org`). Through the API, `qa-user-b` got exactly this message (HTTP 403).

### Local tag on another organisation's event
<a id="tag-roles-local-other-org"></a>

A local tag on an event of another organisation

1. Log in to MISP as `user` of the organisation `QA-Org-B`.
2. Go to `/events/index`.
3. Open the event `QA roles community event`.
4. Click **Edit Tags**, add `tlp:green` under **Local Tags** and click **Save Tags**.

**Expected:** the local tag is attached (local tags are only for your own organisation), or it is refused with a message that explains why.

**Seeded data:** `QA roles community event` (#102, org `ADMIN`, distribution **This community only**, tag `qa:tag-roles-local-other-org`). Through the API, `qa-user-b` was refused with only "Could not attachTagToObject Tag" (HTTP 403), which does not explain why.

### Tag restricted to an organisation
<a id="tag-roles-restricted-org"></a>

A tag "Taggable by organisation" can only be used by that organisation

1. Log in to MISP as `user` of the organisation `QA-Org-B`.
2. Go to `/events/index`.
3. Create an event `QA restricted tag` with **Add Event**.
4. Click **Edit Tags** and search `qa:org-a-only`.
5. Log out, log in as `user` of `ADMIN`, open `QA roles org only event`, click **Edit Tags** and search `qa:org-a-only`.

**Expected:** `qa:org-a-only` is not offered (or refused) for `QA-Org-B`, and is offered for `ADMIN`.

**Seeded data:** Tag `qa:org-a-only` (Taggable by organisation `ADMIN`). Through the API, `qa-user-b` could not attach it (HTTP 403 "Could not attachTagToObject Tag") and `qa-user-a` attached it to `QA roles org only event` (#103).

### Tag create – User role
<a id="tag-roles-create-user"></a>

A user without the tag editor permission cannot create tags

1. Log in to MISP as `user` of the organisation `ADMIN`.
2. Go to `/tags/index`.
3. Look for **Add Tag**.
4. Go to `/tags/add`.

**Expected:** **Add Tag** is not offered and `/tags/add` is refused with "You do not have permission to use this functionality."

**Seeded data:** No data needed. Through the API, `qa-user-a` is refused (HTTP 403).
