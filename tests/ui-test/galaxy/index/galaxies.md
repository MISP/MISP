# MISP Web UI – Galaxy Index – Galaxies Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Custom galaxy – empty name](#galaxy-add-empty-name) | |
| 2 | [Custom galaxy – create](#galaxy-add) | |
| 3 | [Custom galaxy – invalid kill chain order](#galaxy-add-invalid-kill-chain) | |
| 4 | [Galaxy disable – clusters not offered](#galaxy-disable) | |
| 5 | [Custom galaxy – delete while used on an event](#galaxy-delete-used) | |
| 6 | [Galaxy import – invalid JSON](#galaxy-import-invalid-json) | |
| 7 | [Galaxy import – JSON without cluster](#galaxy-import-no-cluster) | |

---


# E2E Tests

### Custom galaxy – empty name
<a id="galaxy-add-empty-name"></a>

Creating a custom galaxy without a name is refused

1. Log in to MISP as `site-admin`.
2. Go to `/galaxies/index`.
3. Click **Add Custom Galaxy**.
4. Leave **Name** empty and type `qa` in **Namespace**.
5. Click **Add Galaxy**.

**Expected:** the galaxy is not created and the message "Please provide a name for the galaxy." is shown.

### Custom galaxy – create
<a id="galaxy-add"></a>

Creating a custom galaxy with the minimal fields

1. Log in to MISP as `site-admin`.
2. Go to `/galaxies/index`.
3. Click **Add Custom Galaxy**.
4. Type `QA galaxy` in **Name** and `qa` in **Namespace**.
5. Click **Add Galaxy**.
6. Go to `/galaxies/index` and search for `QA galaxy`.

**Expected:** the galaxy is created, it is shown in the list as **Enabled**, and not as a **Default galaxy**.

### Custom galaxy – invalid kill chain order
<a id="galaxy-add-invalid-kill-chain"></a>

Creating a galaxy with a badly formatted kill chain order

1. Log in to MISP as `site-admin`.
2. Go to `/galaxies/index`.
3. Click **Add Custom Galaxy**.
4. Type `QA galaxy kill chain` in **Name** and `qa` in **Namespace**.
5. Type `not json {` in **Kill Chain order (for the Galaxy Matrix)**.
6. Click **Add Galaxy**.

**Expected:** the galaxy is refused with a clear message about the kill chain order, or created without it; no error page is shown.

### Galaxy disable – clusters not offered
<a id="galaxy-disable"></a>

The clusters of a disabled galaxy are not offered on events

1. Log in to MISP as `site-admin`.
2. Go to `/galaxies/index`.
3. Click **Disable** on the galaxy `Threat Actor` and confirm.
4. Go to `/events/index`, open any event, click **Edit Galaxy Clusters** and search for `APT28`.
5. Go back to `/galaxies/index` and click **Enable** on `Threat Actor`, then confirm.

**Expected:** while `Threat Actor` is disabled, its clusters (e.g. `APT28`) are not offered in **Edit Galaxy Clusters**.

### Custom galaxy – delete while used on an event
<a id="galaxy-delete-used"></a>

Deleting a custom galaxy whose cluster is attached to an event

1. Log in to MISP as `site-admin`.
2. Go to `/galaxies/index`.
3. Click **View** on the galaxy `QA galaxy` (create it first with **Add Custom Galaxy**, name `QA galaxy`, namespace `qa`, if it does not exist).
4. Click **Add Galaxy Cluster**, type `QA cluster used` in **Name** and click **Add Cluster**.
5. Go to `/events/index`, open any event, click **Edit Galaxy Clusters**, add `QA cluster used` and save.
6. Go to `/galaxies/index` and click **Delete** on `QA galaxy`, then confirm.
7. Open the same event again.

**Expected:** the galaxy is deleted and the event still opens without error.

### Galaxy import – invalid JSON
<a id="galaxy-import-invalid-json"></a>

Importing galaxy clusters from text that is not JSON

1. Log in to MISP as `site-admin`.
2. Go to `/galaxies/index`.
3. Click **Import Galaxy Clusters**.
4. Paste `{ not json` in **Galaxy Clusters JSON**.
5. Click **Import**.

**Expected:** nothing is imported and a clear error about the JSON is shown; no error page.

### Galaxy import – JSON without cluster
<a id="galaxy-import-no-cluster"></a>

Importing a JSON entry that has no GalaxyCluster object

1. Log in to MISP as `site-admin`.
2. Go to `/galaxies/index`.
3. Click **Import Galaxy Clusters**.
4. Paste `[{"Galaxy": {"name": "QA"}}]` in **Galaxy Clusters JSON**.
5. Click **Import**.

**Expected:** nothing is imported and a message says that the entry carries no "GalaxyCluster" object.
