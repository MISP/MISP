# MISP Web UI – Galaxy Cluster – Clusters Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Cluster add – empty name](#galaxy-cluster-add-empty-name) | |
| 2 | [Cluster add – with elements](#galaxy-cluster-add-elements) | |
| 3 | [Cluster fork – default cluster](#galaxy-cluster-fork) | |
| 4 | [Cluster rename – used on an event](#galaxy-cluster-rename-used) | |
| 5 | [Cluster soft-delete and restore – used on an event](#galaxy-cluster-soft-delete) | |
| 6 | [Cluster hard-delete – re-import](#galaxy-cluster-hard-delete-reimport) | |
| 7 | [Cluster publish](#galaxy-cluster-publish) | |

---


# E2E Tests

### Cluster add – empty name
<a id="galaxy-cluster-add-empty-name"></a>

Creating a cluster without a name is refused

1. Log in to MISP as `site-admin`.
2. Go to `/galaxies/index`.
3. Click **View** on the galaxy `QA galaxy` (create it first with **Add Custom Galaxy**, name `QA galaxy`, namespace `qa`, if it does not exist).
4. Click **Add Galaxy Cluster**.
5. Leave **Name** empty.
6. Click **Add Cluster**.

**Expected:** the cluster is not created and the message "A name is required." is shown.

### Cluster add – with elements
<a id="galaxy-cluster-add-elements"></a>

Creating a cluster with key/value elements

1. Log in to MISP as `site-admin`.
2. Go to `/galaxies/index`.
3. Click **View** on the galaxy `QA galaxy` (create it first with **Add Custom Galaxy**, name `QA galaxy`, namespace `qa`, if it does not exist).
4. Click **Add Galaxy Cluster**.
5. Type `QA cluster elements` in **Name**.
6. In **Cluster Elements**, add the key `country` with the value `LU`, and the key `synonyms` with the value `QA alias`.
7. Click **Add Cluster**.

**Expected:** the cluster view shows the two elements in **Elements**, and searching `QA alias` in the cluster list finds the cluster.

### Cluster fork – default cluster
<a id="galaxy-cluster-fork"></a>

Forking a default cluster creates an editable copy and keeps the original unchanged

1. Log in to MISP as `site-admin`.
2. Go to `/galaxies/index`.
3. Click **View** on the galaxy `Threat Actor`.
4. Search for `APT28` and click **Fork** on it.
5. Change **Description** to `QA forked cluster`.
6. Click **Fork Cluster**.
7. Open the original `APT28` cluster.

**Expected:** the fork is saved as a custom cluster with the description `QA forked cluster`, and the original `APT28` still has its original description.

### Cluster rename – used on an event
<a id="galaxy-cluster-rename-used"></a>

Renaming a custom cluster that is attached to an event

1. Log in to MISP as `site-admin`.
2. Go to `/galaxies/index`.
3. Click **View** on the galaxy `QA galaxy` (create it first with **Add Custom Galaxy**, name `QA galaxy`, namespace `qa`, if it does not exist).
4. Click **Add Galaxy Cluster**, type `QA cluster old name` in **Name** and click **Add Cluster**.
5. Go to `/events/index`, open any event, click **Edit Galaxy Clusters**, add `QA cluster old name` and save.
6. Open the cluster, click **Edit**, change **Name** to `QA cluster new name` and click **Save Changes**.
7. Open the same event again.

**Expected:** the event shows the cluster as `QA cluster new name`, without a duplicate and without error.

### Cluster soft-delete and restore – used on an event
<a id="galaxy-cluster-soft-delete"></a>

Soft-deleting a cluster attached to an event, then restoring it

1. Log in to MISP as `site-admin`.
2. Go to `/galaxies/index`.
3. Click **View** on the galaxy `QA galaxy` (create it first with **Add Custom Galaxy**, name `QA galaxy`, namespace `qa`, if it does not exist).
4. Click **Add Galaxy Cluster**, type `QA cluster deleted` in **Name** and click **Add Cluster**.
5. Go to `/events/index`, open any event, click **Edit Galaxy Clusters**, add `QA cluster deleted` and save.
6. Open the cluster and click **Delete**, choose **Soft-delete** and confirm.
7. Open the same event.
8. Open the cluster again and click **Restore**, then confirm.

**Expected:** the event opens without error while the cluster is deleted, and after **Restore** the cluster is active again and shown on the event.

### Cluster hard-delete – re-import
<a id="galaxy-cluster-hard-delete-reimport"></a>

A hard-deleted cluster cannot come back by importing it again

1. Log in to MISP as `site-admin`.
2. Go to `/galaxies/index`.
3. Click **View** on the galaxy `QA galaxy` (create it first with **Add Custom Galaxy**, name `QA galaxy`, namespace `qa`, if it does not exist).
4. Click **Add Galaxy Cluster**, type `QA cluster hard` in **Name** and click **Add Cluster**.
5. Export the cluster in **MISP Format** and copy the JSON.
6. Delete the cluster with **Permanently delete (hard-delete, cannot be undone)** and confirm.
7. Go to `/galaxies/index`, click **Import Galaxy Clusters**, paste the copied JSON and click **Import**.

**Expected:** the import is refused with a message saying the cluster UUID is blocklisted; the cluster does not come back.

### Cluster publish
<a id="galaxy-cluster-publish"></a>

Publishing a custom cluster

1. Log in to MISP as `site-admin`.
2. Go to `/galaxies/index`.
3. Click **View** on the galaxy `QA galaxy` (create it first with **Add Custom Galaxy**, name `QA galaxy`, namespace `qa`, if it does not exist).
4. Click **Add Galaxy Cluster**, type `QA cluster publish` in **Name** and click **Add Cluster**.
5. Click **Publish** on the cluster and confirm.

**Expected:** the cluster is shown as **Published**.
