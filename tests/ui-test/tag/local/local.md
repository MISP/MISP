# MISP Web UI – Tag Local – Local Tags Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Local tag on an event](#tag-local-add) | |
| 2 | [Local-only tag as a global tag](#tag-local-only-global) | |
| 3 | [Local-only tag as a local tag](#tag-local-only-local) | |
| 4 | [Local-only tag on several events at once](#tag-local-only-bulk) | |
| 5 | [Events list – filter by local tag](#tag-local-filter) | |

---


# E2E Tests

### Local tag on an event
<a id="tag-local-add"></a>

Adding a tag as a local tag

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Go to `/events/index`, create an event `QA local tag` with **Add Event** and stay on its detail page.
4. Click **Edit Tags**, search `tlp:green` in **Search tags to add…**, add it under **Local Tags** and click **Save Tags**.

**Expected:** the message "Tags updated." is shown and `tlp:green` is shown on the event as a local tag (not as a global tag).

### Local-only tag as a global tag
<a id="tag-local-only-global"></a>

A local-only tag cannot be attached as a global tag

1. Log in to MISP as `site-admin`.
2. Go to `/tags/index`.
3. Click **Add Tag**, type `qa:local-only` in **Tag Name** and tick **Local only** and click **Add Tag**.
4. Go to `/events/index`, create an event `QA local only global` with **Add Event** and stay on its detail page.
5. Click **Edit Tags**, search `qa:local-only` in **Search tags to add…**, add it under **Global Tags** and click **Save Tags**.

**Expected:** the tag is refused with "Invalid Tag. This tag can only be set as a local tag." and is not attached.

### Local-only tag as a local tag
<a id="tag-local-only-local"></a>

A local-only tag can be attached as a local tag

1. Log in to MISP as `site-admin`.
2. Go to `/tags/index`.
3. Click **Add Tag**, type `qa:local-only-ok` in **Tag Name** and tick **Local only** and click **Add Tag**.
4. Go to `/events/index`, create an event `QA local only local` with **Add Event** and stay on its detail page.
5. Click **Edit Tags**, search `qa:local-only-ok` in **Search tags to add…**, add it under **Local Tags** and click **Save Tags**.

**Expected:** the tag is attached as a local tag without error.

### Local-only tag on several events at once
<a id="tag-local-only-bulk"></a>

A local-only tag cannot be attached globally to several selected events

1. Log in to MISP as `site-admin`.
2. Go to `/tags/index`.
3. Click **Add Tag**, type `qa:local-only-bulk` in **Tag Name** and tick **Local only** and click **Add Tag**.
4. Go to `/events/index` and tick two events.
5. Use the selection toolbar to add the tag `qa:local-only-bulk` as a global tag.

**Expected:** nothing is tagged and the message "Tag \"qa:local-only-bulk\" can only be attached as a local tag — use the local tagging action instead." is shown.

### Events list – filter by local tag
<a id="tag-local-filter"></a>

Filtering the Events list on a tag that is only attached locally

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Go to `/events/index`, create an event `QA local filter` with **Add Event** and stay on its detail page.
4. Click **Edit Tags**, search `admiralty-scale:source-reliability="a"` in **Search tags to add…**, add it under **Local Tags** and click **Save Tags**.
5. Go to `/events/index`, click **More filters**, select `admiralty-scale:source-reliability="a"` in **Tags** and apply.

**Expected:** `QA local filter` is listed.
