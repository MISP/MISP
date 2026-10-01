# MISP Web UI – Tag Collection – Collections Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Collection add – empty name](#tag-collection-empty-name) | |
| 2 | [Collection add – tags and cluster](#tag-collection-add) | |
| 3 | [Collection add – emoji in the name](#tag-collection-emoji) | |
| 4 | [Collection apply to an event](#tag-collection-apply) | |
| 5 | [Collection apply – exclusive tags](#tag-collection-exclusive) | |
| 6 | [Collection download configuration](#tag-collection-download) | |
| 7 | [Collection delete – tags kept](#tag-collection-delete) | |

---


# E2E Tests

### Collection add – empty name
<a id="tag-collection-empty-name"></a>

Creating a tag collection without a name is refused

1. Log in to MISP as `site-admin`.
2. Go to `/tag_collections/index`.
3. Click **Add Tag Collections**.
4. Leave **Collection Name** empty and click **Add Collection**.

**Expected:** the collection is not created and the message "Please provide a name for the collection." is shown.

### Collection add – tags and cluster
<a id="tag-collection-add"></a>

Creating a tag collection with tags and a galaxy cluster

1. Log in to MISP as `site-admin`.
2. Go to `/tag_collections/index`.
3. Click **Add Tag Collections**.
4. Type `QA collection` in **Collection Name**.
5. Add the tags `tlp:green` and `admiralty-scale:source-reliability="b"`.
6. Add the galaxy cluster `APT28`.
7. Click **Add Collection**.

**Expected:** the collection is listed with its 2 **Tags** and 1 **Galaxies** entry.

### Collection add – emoji in the name
<a id="tag-collection-emoji"></a>

A collection name with an emoji is saved without error (regression test for Bug 5)

1. Log in to MISP as `site-admin`.
2. Go to `/tag_collections/index`.
3. Click **Add Tag Collections**.
4. Type `QA collection 🚀` in **Collection Name**.
5. Click **Add Collection**.

**Expected:** the collection is created and shown as `QA collection 🚀`, or refused with a clear message; no "An Internal Error Has Occurred." page.

### Collection apply to an event
<a id="tag-collection-apply"></a>

Applying a tag collection adds all its tags to an event

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Go to `/events/index`, create an event `QA collection apply` with **Add Event** and stay on its detail page.
4. Click **Edit Tags**, open **Tag Collections**, choose `QA collection` (create it first, see "Collection add – tags and cluster") and click **Save Tags**.

**Expected:** the event shows `tlp:green`, `admiralty-scale:source-reliability="b"` and the cluster `APT28`.

### Collection apply – exclusive tags
<a id="tag-collection-exclusive"></a>

Applying a collection that contains two values of an exclusive taxonomy

1. Log in to MISP as `site-admin`.
2. Go to `/tag_collections/index`.
3. Click **Add Tag Collections**.
4. Type `QA collection tlp conflict` in **Collection Name**, add `tlp:green` and `tlp:red`, and click **Add Collection**.
5. Go to `/events/index`, create an event `QA collection conflict` with **Add Event** and stay on its detail page.
6. Click **Edit Tags**, open **Tag Collections**, choose `QA collection tlp conflict` and click **Save Tags**.

**Expected:** only one `tlp` value is attached and a message says the other one is not allowed due to taxonomy exclusivity; no error page.

### Collection download configuration
<a id="tag-collection-download"></a>

Downloading the configuration of a tag collection

1. Log in to MISP as `site-admin`.
2. Go to `/tag_collections/index`.
3. Click **Download configuration** on `QA collection`.
4. Open the downloaded file.

**Expected:** the file is valid JSON and contains `tlp:green`, `admiralty-scale:source-reliability="b"` and `APT28`.

### Collection delete – tags kept
<a id="tag-collection-delete"></a>

Deleting a collection does not delete its tags

1. Log in to MISP as `site-admin`.
2. Go to `/tag_collections/index`.
3. Click **Delete** on `QA collection` and confirm.
4. Go to `/tags/index` and search `tlp:green`.

**Expected:** the collection is gone and `tlp:green` still exists; events tagged with it keep the tag.
