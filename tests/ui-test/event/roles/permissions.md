# MISP Web UI – Event Roles – Permissions Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Event visibility – organisation-only event](#event-roles-org-only-hidden) | |
| 2 | [Event visibility – community event](#event-roles-community-visible) | |
| 3 | [Event edit – other organisation](#event-roles-edit-other-org) | |
| 4 | [Event edit – same organisation, other user](#event-roles-edit-same-org) | |
| 5 | [Event publish – User role](#event-roles-publish-user) | |
| 6 | [Event publish – Org Admin role](#event-roles-publish-org-admin) | |

---


# E2E Tests

### Event visibility – organisation-only event
<a id="event-roles-org-only-hidden"></a>

An event shared with its organisation only is not visible to another organisation

1. Log in to MISP as `user` of the organisation `QA-Org-B`.
2. Go to `/events/index`.
3. Search the Events list for `QA roles org only event`.
4. Go to `/events/view2/103`.

**Expected:** the event is not in the list and its page shows "Invalid event" (not found).

**Seeded data:** `QA roles org only event` (#103, org `ADMIN`, distribution **Your organisation only**, tag `qa:event-roles-org-only-hidden`). Through the API, `qa-user-b` gets HTTP 404 "Invalid event".

### Event visibility – community event
<a id="event-roles-community-visible"></a>

An event shared with this community is visible to another organisation

1. Log in to MISP as `user` of the organisation `QA-Org-B`.
2. Go to `/events/index`.
3. Open the event `QA roles community event`.

**Expected:** the event opens and shows its attributes.

**Seeded data:** `QA roles community event` (#102, org `ADMIN`, distribution **This community only**, tag `qa:event-roles-community-visible`). Through the API, `qa-user-b` can view it (HTTP 200).

### Event edit – other organisation
<a id="event-roles-edit-other-org"></a>

A user cannot edit an event of another organisation

1. Log in to MISP as `user` of the organisation `QA-Org-B`.
2. Go to `/events/index`.
3. Open the event `QA roles community event`.
4. Look for **Edit Event**, **Add Attribute** and **Delete** on the attributes.
5. Go to `/events/edit/102`.

**Expected:** no edit or delete action is offered, and `/events/edit/102` is refused with "You are not authorised to do that."

**Seeded data:** `QA roles community event` (#102, org `ADMIN`, distribution **This community only**, tag `qa:event-roles-edit-other-org`). Through the API, `qa-user-b` is refused: edit event HTTP 403 "You are not authorised to do that.", add or delete attribute HTTP 403 "You do not have permission to do that."

### Event edit – same organisation, other user
<a id="event-roles-edit-same-org"></a>

A user can edit an event created by another user of the same organisation

1. Log in to MISP as `user` of the organisation `ADMIN`.
2. Go to `/events/index`.
3. Open the event `QA roles org only event`.
4. Click **Edit Event**, change **Event Info** to `QA roles org only event – edited` and click **Save Changes**.

**Expected:** the change is saved (the `User` role can modify the events of its organisation).

**Seeded data:** `QA roles org only event` (#103, org `ADMIN`, distribution **Your organisation only**, tag `qa:event-roles-edit-same-org`), created by `site-admin`. Through the API, `qa-user-a` edited it (HTTP 200).

### Event publish – User role
<a id="event-roles-publish-user"></a>

A user without the publish permission cannot publish

1. Log in to MISP as `user` of the organisation `ADMIN`.
2. Go to `/events/index`.
3. Open the event `QA roles org only event`.
4. Look for **Publish Event**.
5. If it is shown, click it and confirm.

**Expected:** **Publish Event** is not offered, or publishing is refused with "You do not have permission to use this functionality."

**Seeded data:** `QA roles org only event` (#103, org `ADMIN`, distribution **Your organisation only**, tag `qa:event-roles-publish-user`). Through the API, `qa-user-a` is refused (HTTP 403).

### Event publish – Org Admin role
<a id="event-roles-publish-org-admin"></a>

An organisation admin can publish an event of the organisation

1. Log in to MISP as `org-admin` of the organisation `ADMIN`.
2. Go to `/events/index`.
3. Open the event `QA roles org only event`.
4. Click **Publish Event** and confirm.

**Expected:** the event is published.

**Seeded data:** `QA roles org only event` (#103, org `ADMIN`, distribution **Your organisation only**, tag `qa:event-roles-publish-org-admin`). Through the API, `qa-orgadmin-a` published it (HTTP 200, "Job queued").
