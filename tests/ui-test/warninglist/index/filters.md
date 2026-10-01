# MISP Web UI – Warninglist Index – Filters Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Warninglist list – Default filter](#warninglist-index-default-filter) | |
| 2 | [Warninglist list – Enabled filter](#warninglist-index-enabled-filter) | |

---


# E2E Tests

### Warninglist list – Default filter
<a id="warninglist-index-default-filter"></a>

The "Default" filter separates default and custom warninglists (regression test for Bug 21)

1. Log in to MISP as `site-admin`.
2. Go to `/warninglists/index`.
3. Click **Add Warninglist**, create a warninglist `QA custom warninglist` with one entry `qa-warning.example`, and save.
4. Go to `/warninglists/index`, click **More filters**, select the non-default value in **Default** and apply.

**Expected:** only `QA custom warninglist` is listed.

### Warninglist list – Enabled filter
<a id="warninglist-index-enabled-filter"></a>

The "Enabled" filter only lists the enabled warninglists

1. Log in to MISP as `site-admin`.
2. Go to `/warninglists/index`.
3. Click **Enable** on `List of known IPv4 public DNS resolvers`.
4. Click **More filters**, select **Enabled** and apply.
5. Click **Disable** on `List of known IPv4 public DNS resolvers`.

**Expected:** only `List of known IPv4 public DNS resolvers` is listed while it is enabled.
