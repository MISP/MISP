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
| 6 | [Event unpublish – page shown after unpublishing](#event-unpublish-redirect) | |
| 7 | [Event view – event that does not exist](#event-view-not-found) | |
| 8 | [Event view – invalid ID](#event-view-invalid-id) | |
| 9 | [Event view – open by UUID](#event-view-uuid) | |
| 10 | [Event extends – two events extending each other](#event-extends-cycle) | |

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

### Event unpublish – page shown after unpublishing
<a id="event-unpublish-redirect"></a>

After unpublishing, the user lands on the Overmind event detail page

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the event `QA unpublish redirect` (create it first with **Add Event** if it does not exist).
4. Click **Publish Event** and confirm.
5. Click **Unpublish Event** and confirm.

**Expected:** the event detail page opens at `/events/view2/<id>` in the Overmind layout, and the event is shown as Unpublished.

### Event view – event that does not exist
<a id="event-view-not-found"></a>

Opening the detail page of an event ID that does not exist

1. Log in to MISP as `site-admin`.
2. Go to `/events/view2/999999`.

**Expected:** a clear "Invalid event" (not found) message is shown; no "An Internal Error Has Occurred." page.

### Event view – invalid ID
<a id="event-view-invalid-id"></a>

Opening the detail page with text instead of an event ID

1. Log in to MISP as `site-admin`.
2. Go to `/events/view2/abc`.

**Expected:** a clear "Invalid event" (not found) message is shown; no "An Internal Error Has Occurred." page.

### Event view – open by UUID
<a id="event-view-uuid"></a>

Opening an event detail page with its UUID instead of its ID

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the event `QA view by UUID` (create it first with **Add Event** if it does not exist).
4. Copy the event UUID shown on the events/view page.
5. Go to `/events/view2/<copied UUID>`.

**Expected:** the same event detail page opens.

### Event extends – two events extending each other
<a id="event-extends-cycle"></a>

Two events that extend each other do not break the detail pages

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA cycle A` with **Add Event** and note its ID.
4. Create an event `QA cycle B` with **Extends** set to the ID of `QA cycle A`, and note its ID.
5. Open `QA cycle A` and click **Edit Event**.
6. Type the ID of `QA cycle B` in **Extends** and click **Save Changes**.
7. Open `QA cycle A`, then open `QA cycle B`.

**Expected:** either the second extension is refused with a clear message, or both detail pages open normally without loop, freeze or error.
