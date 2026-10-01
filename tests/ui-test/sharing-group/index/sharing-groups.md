# MISP Web UI – Sharing Group Index – Sharing Groups Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Sharing group – create with two organisations](#sg-create) | |
| 2 | [Sharing group – emoji in the name](#sg-emoji) | |
| 3 | [Sharing group – member cannot edit it](#sg-edit-other-org) | |
| 4 | [Sharing group – delete while used](#sg-delete-used) | |

---


# E2E Tests

### Sharing group – create with two organisations
<a id="sg-create"></a>

Creating a sharing group and adding a second organisation

1. Log in to MISP as `site-admin`.
2. Go to `/sharing_groups/index`.
3. Click **Add Sharing Group**, name it `QA SG org A and B`, releasability `QA`.
4. Add the organisations `ADMIN` and `QA-Org-B` and save.

**Expected:** the sharing group is listed with its 2 organisations and can be chosen as **Sharing group** in **Add Event**.

**Seeded data:** `QA SG org A and B` (#2, members `ADMIN` and `QA-Org-B`), created through the API.

### Sharing group – emoji in the name
<a id="sg-emoji"></a>

A sharing group name with an emoji is saved without error (checks Bug 7 on sharing groups)

1. Log in to MISP as `site-admin`.
2. Go to `/sharing_groups/index`.
3. Click **Add Sharing Group**, name it `QA SG 🚀` and save.

**Expected:** no "An Internal Error Has Occurred." page; the sharing group is created with its emoji.

**Seeded data:** Through the API, creating `QA SG 🚀` gives HTTP 500 "An Internal Error Has Occurred." (Bug 7: `sharing_groups.name` is `utf8mb3`).

### Sharing group – member cannot edit it
<a id="sg-edit-other-org"></a>

A member organisation that did not create the sharing group cannot edit it

1. Log in to MISP as `user` of the organisation `QA-Org-B`.
2. Go to `/sharing_groups/index`.
3. Open `QA SG org A and B` and look for **Edit**.
4. Go to `/sharing_groups/edit/2`.

**Expected:** no **Edit** is offered and the edit page is refused with "You do not have permission to use this functionality."

**Seeded data:** `QA SG org A and B` (#2, members `ADMIN` and `QA-Org-B`). Through the API, `qa-user-b` is refused (HTTP 403) and only sees `QA SG org A and B` in the list (not `QA SG org A only`).

### Sharing group – delete while used
<a id="sg-delete-used"></a>

Deleting a sharing group that is used by an event

1. Log in to MISP as `site-admin`.
2. Go to `/sharing_groups/index`.
3. Click **Delete** on `QA SG org A only` and confirm.

**Expected:** the deletion is refused with a message that says the sharing group is still used by events (not only "Could not delete SharingGroup").

**Seeded data:** `QA SG org A only` (#1, member `ADMIN`) is used by `QA SG event org A only` (#110). Through the API the deletion is refused with HTTP 403 "Could not delete SharingGroup", without the reason.
