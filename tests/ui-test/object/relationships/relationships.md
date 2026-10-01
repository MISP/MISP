# MISP Web UI – Object Relationships Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Object relationships – remove highlight for selected rows](#object-relationships-remove-highlight) | |
| 2 | [Object relationships – highlight selected rows](#object-relationships-highlight) | |

---


# E2E Tests

### Object relationships – remove highlight for selected rows
<a id="object-relationships-remove-highlight"></a>

Ticking a highlighted relationship offers Remove Highlight (regression test for Bug 26)

1. Log in to MISP as `site-admin`.
2. Go to `/object_relationships/index`.
3. Click **Highlight** in the actions of the relationship `shares`.
4. Tick the checkbox of `shares`.
5. Click **Remove Highlight** in the selection bar.

**Expected:** **Remove Highlight** is offered in step 5, and after clicking it `shares` is no longer highlighted.

### Object relationships – highlight selected rows
<a id="object-relationships-highlight"></a>

Highlighting several relationships at once from the selection bar

1. Log in to MISP as `site-admin`.
2. Go to `/object_relationships/index`.
3. Tick two relationships that are not highlighted (e.g. `derived-from` and `executes`).
4. Click **Highlight** in the selection bar and confirm.
5. Tick the same two relationships and click **Remove Highlight**.

**Expected:** after step 4 both are shown as highlighted; after step 5 they are not highlighted anymore.
