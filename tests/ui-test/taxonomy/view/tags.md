# MISP Web UI – Taxonomy View – Tags Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Taxonomy – enable all tags](#taxonomy-enable-all-tags) | |
| 2 | [Taxonomy – disable one tag](#taxonomy-disable-one-tag) | |

---


# E2E Tests

### Taxonomy – enable all tags
<a id="taxonomy-enable-all-tags"></a>

Enabling all tags of a taxonomy makes every value usable

1. Log in to MISP as `site-admin`.
2. Go to `/taxonomies/index`.
3. Search for `pap` and click **Enable** on the `pap` taxonomy, then confirm.
4. Click **View** on `pap`.
5. Click **Enable all tags** and confirm.
6. Go to `/events/index`, open any event, click **Edit Tags** and type `pap:`.
7. Go to `/taxonomies/index` and click **Disable** on `pap`, then confirm.

**Expected:** the **Active Tags** count of `pap` equals its number of values, and every `pap:` value is offered in **Edit Tags**.

### Taxonomy – disable one tag
<a id="taxonomy-disable-one-tag"></a>

A disabled tag is not offered anymore, the other tags of the taxonomy still are

1. Log in to MISP as `site-admin`.
2. Go to `/taxonomies/index`.
3. Click **View** on the `tlp` taxonomy.
4. Disable the tag `tlp:amber` and confirm.
5. Go to `/events/index`, open any event, click **Edit Tags** and type `tlp:`.
6. Go back to the `tlp` taxonomy view and enable `tlp:amber` again.

**Expected:** `tlp:amber` is not offered in **Edit Tags** while it is disabled, and the other `tlp:` tags still are.
