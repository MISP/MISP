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

Edit an event and set a date later than today (checks Bug 1 also on edit)

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the event `QA edit date` (create it first with **Add Event** if it does not exist).
4. Click **Edit Event**.
5. Type `15/06/2030` in **Event Date (UTC)**.
6. Click **Save Changes**.

**Expected:** the event is saved with the date 2030-06-15 and no CSRF error is shown.

### Event edit – Event Info over the database limit
<a id="event-edit-info-too-long"></a>

Edit an event with an Event Info longer than 65,535 characters (checks Bug 3 also on edit)

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
