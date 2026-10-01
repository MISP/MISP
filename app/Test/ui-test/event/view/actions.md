# MISP Web UI – Event View – Actions Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Event publish and unpublish](#event-publish-unpublish) | |
| 2 | [Event publish – empty event](#event-publish-empty) | |
| 3 | [Event delete](#event-delete) | |
| 4 | [Event delete – event extended by another](#event-delete-extended) | |
| 5 | [Event tags and galaxy clusters](#event-tags-galaxies) | |

---


# E2E Tests

### Event publish and unpublish
<a id="event-publish-unpublish"></a>

Publish an event, then unpublish it

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the event `QA publish` (create it first with **Add Event** if it does not exist).
4. Click **Publish Event** and confirm.
5. Go to `/events/index`.
6. Open the event `QA publish`.
7. Click **Unpublish Event** and confirm.

**Expected:** after publishing, the event is shown as Published in the event list; after unpublishing, it is shown as Unpublished.

### Event publish – empty event
<a id="event-publish-empty"></a>

Publish an event that has no attribute

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **Add Event** button
4. Type `QA publish empty` in **Event Info**.
5. Click **Create Event Entry**.
6. Click **Publish Event** and confirm.

**Expected:** MISP either publishes the event or shows a clear warning that the event is empty; no error page is shown.

### Event delete
<a id="event-delete"></a>

Delete an event

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the event `QA delete` (create it first with **Add Event** if it does not exist).
4. Click **Delete Event** and confirm.
5. Go to `/events/index`.

**Expected:** `QA delete` is no longer in the event list.

### Event delete – event extended by another
<a id="event-delete-extended"></a>

Delete an event that another event extends

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **Add Event** button
4. Type `QA parent` in **Event Info** and click **Create Event Entry**.
5. Note the event ID of `QA parent`.
6. Go to `/events/index` and click **Add Event**.
7. Type `QA child` in **Event Info**, type the noted ID in **Extends** and click **Create Event Entry**.
8. Open `QA parent`, click **Delete Event** and confirm.
9. Open `QA child`.

**Expected:** `QA child` opens normally, without error, even though the event it extended was deleted.

### Event tags and galaxy clusters
<a id="event-tags-galaxies"></a>

Add a tag and a galaxy cluster to an event, then remove them

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the event `QA tags` (create it first with **Add Event** if it does not exist).
4. Click **Edit Tags**, pick the tag `tlp:green` and save.
5. Click **Edit Galaxy Clusters**, pick any cluster and save.
6. Click **Remove tag** on `tlp:green`.
7. Click **Remove galaxy** on the cluster.

**Expected:** the tag and the cluster are shown on the events/view page after adding, and are gone after removing; no error is shown.
