# MISP Web UI – Event Edit Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Event edit – basic fields](#event-edit-basic) | |
| 2 | [Event edit – future date](#event-edit-future-date) | |
| 3 | [Event edit – Event Info over the database limit](#event-edit-info-too-long) | |
| 4 | [Event edit – extends itself](#event-edit-extends-itself) | |
| 5 | [Event edit – two tabs at the same time](#event-edit-concurrent) | |
| 6 | [Event edit – event deleted meanwhile](#event-edit-deleted) | |
| 7 | [Event edit – logged out before saving](#event-edit-logged-out) | |
| 8 | [Event edit – published event](#event-edit-published) | |
| 9 | [Event edit – empty Event Info](#event-edit-empty-info) | |

---


# E2E Tests

### Event edit – basic fields
<a id="event-edit-basic"></a>

Edit the Event Info and Threat Level of an existing event

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the event `QA edit` (create it first with **Add Event** if it does not exist).
4. Click **Edit Event**.
5. Replace **Event Info** with `QA edit – updated`.
6. In **Threat Level**, select **Medium**.
7. Click **Save Changes**.

**Expected:** the events/view page shows the Event Info `QA edit – updated` and the Threat Level Medium.

### Event edit – future date
<a id="event-edit-future-date"></a>

Edit an event and set a date later than today (checks Bug 28 also on edit)

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the event `QA edit date` (create it first with **Add Event** if it does not exist).
4. Click **Edit Event**.
5. Type `15/06/2030` in **Event Date (UTC)**.
6. Click **Save Changes**.

**Expected:** the event is saved with the date 2030-06-15 and no CSRF error is shown.

### Event edit – Event Info over the database limit
<a id="event-edit-info-too-long"></a>

Edit an event with an Event Info longer than 65,535 characters (checks Bug 8 also on edit)

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the event `QA edit long` (create it first with **Add Event** if it does not exist).
4. Click **Edit Event**.
5. Paste a text of 70,000 characters in **Event Info**.
6. Click **Save Changes**.

**Expected:** the event is not saved, no "An Internal Error Has Occurred." page is shown, and a message explains that **Event Info** is too long.

### Event edit – extends itself
<a id="event-edit-extends-itself"></a>

Edit an event so that it extends its own ID

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the event `QA extends itself` (create it first with **Add Event** if it does not exist).
4. Note the event ID shown on the events/view page.
5. Click **Edit Event**.
6. Type the noted event ID in **Extends**.
7. Click **Save Changes**.

**Expected:** the event is not saved and a message explains that an event cannot extend itself; no error page is shown.

### Event edit – two tabs at the same time
<a id="event-edit-concurrent"></a>

Two users editing the same event at the same time

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the event `QA concurrent edit` (create it first with **Add Event** if it does not exist).
4. Click **Edit Event**.
5. Open the same event in a second browser tab and click **Edit Event**.
6. In the second tab, change **Event Info** to `QA edit tab 2` and click **Save Changes**.
7. In the first tab, change **Event Info** to `QA edit tab 1` and click **Save Changes**.

**Expected:** the first tab warns that the event was changed in the meantime, instead of silently overwriting `QA edit tab 2`.

**Seeded data:** `QA concurrent edit`, tag `qa:event-edit-concurrent`. The edit code does not check if the event changed in the meantime, so the last save probably wins without warning.

### Event edit – event deleted meanwhile
<a id="event-edit-deleted"></a>

Saving the edit form of an event that was deleted in another tab

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the event `QA edit deleted` (create it first with **Add Event** if it does not exist).
4. Click **Edit Event**.
5. Open the same event in a second browser tab, click **Delete Event** and confirm.
6. In the first tab, change **Event Info** and click **Save Changes**.

**Expected:** a clear message says the event does not exist anymore; no "An Internal Error Has Occurred." page and no event is re-created.

**Seeded data:** `QA edit deleted`, tag `qa:event-edit-deleted`.

### Event edit – logged out before saving
<a id="event-edit-logged-out"></a>

Saving the edit form after the session was closed in another tab

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the event `QA edit logged out` (create it first with **Add Event** if it does not exist).
4. Click **Edit Event**.
5. Open MISP in a second browser tab and log out.
6. In the first tab, change **Event Info** and click **Save Changes**.

**Expected:** the login page is shown with a clear message; no CSRF or internal error page, and the event is not changed.

**Seeded data:** `QA edit logged out`, tag `qa:event-edit-logged-out`.

### Event edit – published event
<a id="event-edit-published"></a>

Editing a published event unpublishes it, so the change is not shared before a new publish

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the event `QA edit published` (create it first with **Add Event** if it does not exist).
4. Check that the event is shown as Published.
5. Click **Edit Event**.
6. Replace **Event Info** with `QA edit published – changed`.
7. Click **Save Changes**.

**Expected:** the event is saved and is now shown as Unpublished, with a way to publish it again.

**Seeded data:** `QA edit published` (published), tag `qa:event-edit-published`. In the code, saving the edit form sets `published = 0`.

### Event edit – empty Event Info
<a id="event-edit-empty-info"></a>

Saving an event with an empty Event Info is refused

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the event `QA edit empty info` (create it first with **Add Event** if it does not exist).
4. Click **Edit Event**.
5. Delete all the text in **Event Info**.
6. Click **Save Changes**.

**Expected:** the event is not saved, the form stays open and the message "Please provide a name for the event." is shown under **Event Info**.

**Seeded data:** `QA edit empty info`, tag `qa:event-edit-empty-info`.
