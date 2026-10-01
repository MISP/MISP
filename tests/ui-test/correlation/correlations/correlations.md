# MISP Web UI – Correlation – Correlations and Exclusions Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Correlation – same value in two events](#correlation-two-events) | |
| 2 | [Correlation exclusion – existing correlations](#correlation-exclusion-cleanup) | |
| 3 | [Correlation exclusion – same value twice](#correlation-exclusion-duplicate) | |
| 4 | [Correlation exclusion – empty value](#correlation-exclusion-empty) | |
| 5 | [Correlation – top correlations](#correlation-top) | |

---


# E2E Tests

### Correlation – same value in two events
<a id="correlation-two-events"></a>

Two events with the same value are related

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open `QA correlation A`.

**Expected:** **Related Events** lists `QA correlation B`, and the attribute `198.51.100.160` shows a correlation to it.

**Seeded data:** `QA correlation A` (#113) and `QA correlation B` (#114) both contain `198.51.100.160`. Through the API, A lists B in its related events.

### Correlation exclusion – existing correlations
<a id="correlation-exclusion-cleanup"></a>

An exclusion only removes the existing correlations after Clean up correlations

1. Log in to MISP as `site-admin`.
2. Go to `/correlation_exclusions/index`.
3. Click **Add Exclusion**, type `198.51.100.160`, comment `QA exclusion` and save.
4. Open `QA correlation A` and check **Related Events**.
5. Go back to `/correlation_exclusions/index` and click **Clean up correlations**.
6. Open `QA correlation A` again.

**Expected:** before the clean up `QA correlation B` is still related (as the page says: "Existing correlations are dropped by \"Clean up correlations\"."); after it, `QA correlation B` is no longer related through `198.51.100.160`.

**Seeded data:** The exclusion `198.51.100.160` was added through the API; without clean up, A still listed B as related.

### Correlation exclusion – same value twice
<a id="correlation-exclusion-duplicate"></a>

Adding the same exclusion twice

1. Log in to MISP as `site-admin`.
2. Go to `/correlation_exclusions/index`.
3. Click **Add Exclusion**, type `198.51.100.160` and save.

**Expected:** the second exclusion is refused with a message that the value is already excluded (not only "Could not add correlation_exclusion").

**Seeded data:** Through the API, the second exclusion of `198.51.100.160` is refused with HTTP 403 "Could not add correlation_exclusion", without the reason.

### Correlation exclusion – empty value
<a id="correlation-exclusion-empty"></a>

An exclusion without a value is refused

1. Log in to MISP as `site-admin`.
2. Go to `/correlation_exclusions/index`.
3. Click **Add Exclusion**, leave the value empty and save.

**Expected:** nothing is saved and the message "Please provide a value to exclude." is shown.

### Correlation – top correlations
<a id="correlation-top"></a>

The top correlations page lists the most correlated values

1. Log in to MISP as `site-admin`.
2. Go to `/correlations/top`.
3. Click **Regenerate cache** and wait.
4. Reload the page.

**Expected:** `198.51.100.160` (or the most correlated values of the instance) is listed with its **Correlation count**; no error page.

**Seeded data:** Through the API, `/correlations/top` returned an empty list before the cache was regenerated.
