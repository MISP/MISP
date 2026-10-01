# MISP Web UI – Event Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Event add](#event-add) | |
| 2 | [Event add – minimal fields](#event-add-minimal) | |
| 3 | [Event add – empty Event Info](#event-add-empty-info) | |
| 4 | [Event add – Event Info with only spaces](#event-add-spaces-info) | |
| 5 | [Event add – future date](#event-add-future-date) | |
| 6 | [Event add – invalid date](#event-add-invalid-date) | |
| 7 | [Event add – text in date field](#event-add-text-date) | |
| 8 | [Event add – ISO date format](#event-add-iso-date) | |
| 9 | [Event add – all fields set](#event-add-all-fields) | |
| 10 | [Event add – distribution options](#event-add-distribution-options) | |
| 11 | [Event add – distribution Your organisation only](#event-add-org-only) | |
| 12 | [Event add – distribution This community only](#event-add-community-only) | |
| 13 | [Event add – distribution Connected communities](#event-add-connected-communities) | |
| 14 | [Event add – distribution All communities](#event-add-all-communities) | |
| 15 | [Event add – extends an existing event](#event-add-extends) | |
| 16 | [Event add – extends with invalid value](#event-add-extends-invalid) | |
| 17 | [Event add – very long Event Info](#event-add-long-info) | |
| 18 | [Event add – special characters](#event-add-unicode) | |
| 19 | [Event add – HTML in Event Info](#event-add-html) | |
| 20 | [Event add – double click on submit](#event-add-double-click) | |
| 21 | [Event add – close without saving](#event-add-cancel) | |
| 22 | [Event add – shown in event list](#event-add-in-list) | |
| 23 | [Event add – extends an unknown event ID](#event-add-extends-unknown-id) | |

---


# E2E Tests

### Event add
<a id="event-add"></a>

Simple Event creation flow with custom date

1. Log in to MISP as `side-admin`.
2. Go to /events/index.
3. Click **Create an event** button
4. Pick a title
5. Change the date to before than today
6. Submit

**Expected:** the event is created and its events/view page opens.

### Event add – minimal fields
<a id="event-add-minimal"></a>

Event creation with only the Event Info field filled, all other fields left on default

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **Add Event** button
4. Type `QA minimal event` in **Event Info**.
5. Click **Create Event Entry**.

**Expected:** the event is created with today's date and the default values, and its events/view page opens.

### Event add – empty Event Info
<a id="event-add-empty-info"></a>

Event creation is refused when Event Info is empty

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **Add Event** button
4. Leave **Event Info** empty.
5. Click **Create Event Entry**.

**Expected:** the event is not created and the message "Please provide a name for the event." is shown under **Event Info**.

### Event add – Event Info with only spaces
<a id="event-add-spaces-info"></a>

Event creation is refused when Event Info contains only spaces

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **Add Event** button
4. Type 5 spaces in **Event Info**.
5. Click **Create Event Entry**.

**Expected:** the event is not created and an error is shown under **Event Info**.

### Event add – future date
<a id="event-add-future-date"></a>

Event creation with a date later than today (regression test for Bug 1)

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **Add Event** button
4. Type `QA future date` in **Event Info**.
5. Type `15/06/2030` in **Event Date (UTC)**.
6. Click **Create Event Entry**.

**Expected:** the event is created with the date 2030-06-15, no CSRF error is shown, and its events/view page opens.

### Event add – invalid date
<a id="event-add-invalid-date"></a>

Event creation is refused when the date does not exist

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **Add Event** button
4. Type `QA invalid date` in **Event Info**.
5. Type `31/02/2026` in **Event Date (UTC)**.
6. Click **Create Event Entry**.

**Expected:** the event is not created and the message "Enter the event date as DD/MM/YYYY." is shown.

### Event add – text in date field
<a id="event-add-text-date"></a>

Event creation is refused when the date field contains text

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **Add Event** button
4. Type `QA text date` in **Event Info**.
5. Type `abc` in **Event Date (UTC)**.
6. Click **Create Event Entry**.

**Expected:** the event is not created and the message "Enter the event date as DD/MM/YYYY." is shown.

### Event add – ISO date format
<a id="event-add-iso-date"></a>

Event creation with a date pasted in YYYY-MM-DD format

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **Add Event** button
4. Type `QA ISO date` in **Event Info**.
5. Paste `2026-09-15` in **Event Date (UTC)**.
6. Click outside the date field.
7. Click **Create Event Entry**.

**Expected:** the date is shown as `15/09/2026`, the event is created with the date 2026-09-15, and its events/view page opens.

### Event add – all fields set
<a id="event-add-all-fields"></a>

Event creation with every option changed from its default value

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **Add Event** button
4. Type `QA all fields` in **Event Info**.
5. In **Distribution**, select **All communities**.
6. In **Analysis Level**, select **Completed**.
7. In **Threat Level**, select **High**.
8. Type `01/09/2026` in **Event Date (UTC)**.
9. Click **Create Event Entry**.

**Expected:** the event is created and its events/view page shows Distribution All communities, Analysis Completed, Threat Level High and date 2026-09-01.

### Event add – distribution options
<a id="event-add-distribution-options"></a>

The Add Event form offers exactly the 4 distribution levels

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **Add Event** button
4. Look at the **Distribution** choices.

**Expected:** **Distribution** shows exactly 4 choices: **Your organisation only**, **This community only**, **Connected communities**, **All communities**, and no **Sharing group** choice.

### Event add – distribution Your organisation only
<a id="event-add-org-only"></a>

Event creation with the distribution set to Your organisation only

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **Add Event** button
4. Type `QA distribution org only` in **Event Info**.
5. In **Distribution**, select **Your organisation only**.
6. Click **Create Event Entry**.

**Expected:** the event is created, its events/view page opens and shows the distribution Your organisation only.

### Event add – distribution This community only
<a id="event-add-community-only"></a>

Event creation with the distribution set to This community only

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **Add Event** button
4. Type `QA distribution community only` in **Event Info**.
5. In **Distribution**, select **This community only**.
6. Click **Create Event Entry**.

**Expected:** the event is created, its events/view page opens and shows the distribution This community only.

### Event add – distribution Connected communities
<a id="event-add-connected-communities"></a>

Event creation with the distribution set to Connected communities

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **Add Event** button
4. Type `QA distribution connected communities` in **Event Info**.
5. In **Distribution**, select **Connected communities**.
6. Click **Create Event Entry**.

**Expected:** the event is created, its events/view page opens and shows the distribution Connected communities.

### Event add – distribution All communities
<a id="event-add-all-communities"></a>

Event creation with the distribution set to All communities

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **Add Event** button
4. Type `QA distribution all communities` in **Event Info**.
5. In **Distribution**, select **All communities**.
6. Click **Create Event Entry**.

**Expected:** the event is created, its events/view page opens and shows the distribution All communities.

### Event add – extends an existing event
<a id="event-add-extends"></a>

Event creation that extends another event by its ID

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **Add Event** button
4. Type `QA extends event` in **Event Info**.
5. Type the ID of an existing event (e.g. `1`) in **Extends**.
6. Wait for the preview of the extended event to appear.
7. Click **Create Event Entry**.

**Expected:** the event is created, its events/view page opens and shows that it extends the chosen event.

### Event add – extends with invalid value
<a id="event-add-extends-invalid"></a>

Event creation is refused when Extends is not a valid ID or UUID

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **Add Event** button
4. Type `QA extends invalid` in **Event Info**.
5. Type `not-a-uuid` in **Extends**.
6. Click **Create Event Entry**.

**Expected:** the event is not created and the message "Please provide a valid UUID" is shown.

### Event add – very long Event Info
<a id="event-add-long-info"></a>

Event creation with a 1000-character Event Info

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **Add Event** button
4. Paste a text of 1000 characters in **Event Info**.
5. Click **Create Event Entry**.

**Expected:** the event is created, its events/view page opens and the full text is shown without breaking the page layout.

### Event add – special characters
<a id="event-add-unicode"></a>

Event creation with accents, non-Latin characters and emoji in Event Info

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **Add Event** button
4. Type `Événement test – 漢字 – Привет – 🚀` in **Event Info**.
5. Click **Create Event Entry**.

**Expected:** the event is created and its events/view page shows the Event Info exactly as typed.

### Event add – HTML in Event Info
<a id="event-add-html"></a>

Event creation with HTML/script code in Event Info is shown as plain text

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **Add Event** button
4. Type `<script>alert(1)</script><b>QA</b>` in **Event Info**.
5. Click **Create Event Entry**.
6. Go to `/events/index`.

**Expected:** the event is created, no alert pops up, and the Event Info is shown as plain text on the events/view page and in the event list.

### Event add – double click on submit
<a id="event-add-double-click"></a>

Clicking the submit button twice quickly creates only one event

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **Add Event** button
4. Type `QA double click` in **Event Info**.
5. Double-click **Create Event Entry**.
6. Go to `/events/index`.

**Expected:** only one event named `QA double click` exists in the event list.

### Event add – close without saving
<a id="event-add-cancel"></a>

Closing the Add Event form does not create an event

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **Add Event** button
4. Type `QA cancelled event` in **Event Info**.
5. Close the form without clicking **Create Event Entry**.
6. Go to `/events/index`.

**Expected:** no event named `QA cancelled event` exists in the event list.

### Event add – shown in event list
<a id="event-add-in-list"></a>

A newly created event appears at the top of the event list as unpublished

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **Add Event** button
4. Type `QA list check` in **Event Info**.
5. Click **Create Event Entry**.
6. Go to `/events/index`.

**Expected:** `QA list check` is shown first in the event list, with your organisation and as not published.

### Event add – extends an unknown event ID
<a id="event-add-extends-unknown-id"></a>

Event creation with an Extends ID that matches no event shows the reason and keeps the form (regression test for Bug 2)

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **Add Event** button
4. Type `QA extends unknown ID` in **Event Info**.
5. Type `999999` in **Extends**.
6. Click **Create Event Entry**.

**Expected:** the event is not created, the form stays open with `QA extends unknown ID` still filled in, and the message "Invalid event ID provided." is shown under **Extends**.
