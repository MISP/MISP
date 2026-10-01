# MISP Web UI – Galaxy Cluster – Relations Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Cluster relation – between two clusters](#galaxy-cluster-relation-add) | |
| 2 | [Cluster relation – without type](#galaxy-cluster-relation-no-type) | |
| 3 | [Cluster relation – to itself](#galaxy-cluster-relation-self) | |
| 4 | [Cluster relation – target deleted](#galaxy-cluster-relation-target-deleted) | |

---


# E2E Tests

### Cluster relation – between two clusters
<a id="galaxy-cluster-relation-add"></a>

A relationship between two custom clusters is shown on both sides

1. Log in to MISP as `site-admin`.
2. Go to `/galaxies/index`.
3. Click **View** on the galaxy `QA galaxy` (create it first with **Add Custom Galaxy**, name `QA galaxy`, namespace `qa`, if it does not exist).
4. Create two clusters `QA relation source` and `QA relation target` with **Add Galaxy Cluster**.
5. Open `QA relation source`, go to **Relations** and click **Add Relationship**.
6. Choose `QA relation target` as target, type `attributed-to` as relationship and click **Add Relationship**.
7. Open `QA relation target` and go to **Relations**.

**Expected:** `QA relation source` shows an **Outbound** `attributed-to` relation to `QA relation target`, and `QA relation target` shows it as **Inbound**.

### Cluster relation – without type
<a id="galaxy-cluster-relation-no-type"></a>

A relationship without a type is refused

1. Log in to MISP as `site-admin`.
2. Go to `/galaxies/index`.
3. Click **View** on the galaxy `QA galaxy` (create it first with **Add Custom Galaxy**, name `QA galaxy`, namespace `qa`, if it does not exist).
4. Open `QA relation source` (create it with **Add Galaxy Cluster** if needed), go to **Relations** and click **Add Relationship**.
5. Choose any target and leave the relationship type empty.
6. Click **Add Relationship**.

**Expected:** the relationship is not created and the message "A relationship type is required." is shown.

### Cluster relation – to itself
<a id="galaxy-cluster-relation-self"></a>

A cluster related to itself

1. Log in to MISP as `site-admin`.
2. Go to `/galaxies/index`.
3. Click **View** on the galaxy `QA galaxy` (create it first with **Add Custom Galaxy**, name `QA galaxy`, namespace `qa`, if it does not exist).
4. Open `QA relation source` (create it with **Add Galaxy Cluster** if needed), go to **Relations** and click **Add Relationship**.
5. Choose `QA relation source` itself as target, type `related-to` and click **Add Relationship**.

**Expected:** the relationship is refused with a clear message, or created and shown without loop or error.

### Cluster relation – target deleted
<a id="galaxy-cluster-relation-target-deleted"></a>

Deleting the target cluster of a relationship

1. Log in to MISP as `site-admin`.
2. Go to `/galaxies/index`.
3. Click **View** on the galaxy `QA galaxy` (create it first with **Add Custom Galaxy**, name `QA galaxy`, namespace `qa`, if it does not exist).
4. Create the relation `QA relation source` → `QA relation target` (see the first test of this file).
5. Delete `QA relation target` with **Soft-delete** and confirm.
6. Open `QA relation source` and go to **Relations**.

**Expected:** the **Relations** tab of `QA relation source` opens without error and shows the relation as pointing to a deleted cluster, or no longer shows it.
