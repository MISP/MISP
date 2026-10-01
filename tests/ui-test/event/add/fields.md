# MISP Web UI – Event Add – Fields Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

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
| 3 | [Event add – future date](#event-add-future-date) | |
| 4 | [Event add – all fields set](#event-add-all-fields) | |
| 5 | [Event add – distribution levels](#event-add-distribution) | |
| 6 | [Event add – extends an existing event](#event-add-extends) | |
| 7 | [Event add – HTML in Event Info](#event-add-html) | |
| 8 | [Event add – extends an unknown UUID](#event-add-extends-unknown-uuid) | |
| 9 | [Event add – Event Info with line breaks](#event-add-multiline-info) | |
| 10 | [Event add – extreme dates](#event-add-extreme-dates) | |

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

### Event add – distribution levels
<a id="event-add-distribution"></a>

The Add Event form offers the 4 distribution levels and saves the chosen one

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **Add Event** button
4. Check the **Distribution** choices: **Your organisation only**, **This community only**, **Connected communities**, **All communities**, plus **Sharing group** only if a sharing group exists.
5. Type `QA distribution` in **Event Info**.
6. In **Distribution**, select **This community only**.
7. Click **Create Event Entry**.

**Expected:** **Sharing group** is offered only when at least one sharing group exists (none at first, then `QA SG org A only` / `QA SG org A and B`, see `sharing-group/`), the event is created, and its events/view page shows the distribution This community only.

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

### Event add – extends an unknown UUID
<a id="event-add-extends-unknown-uuid"></a>

Event creation that extends a valid UUID which is not on this instance

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **Add Event** button
4. Type `QA extends unknown UUID` in **Event Info**.
5. Type `7c9e6679-7425-40de-944b-e07fc1f90ae7` in **Extends**.
6. Click **Create Event Entry**.

**Expected:** the event is created (or refused with a clear message), and its events/view page opens without error.

**Seeded data:** `QA extends unknown UUID`, tag `qa:event-add-extends-unknown-uuid`, created through the API with **Extends** = `7c9e6679-7425-40de-944b-e07fc1f90ae7`. Result: accepted. Note: a badly formed UUID such as `11111111-2222-3333-4444-555555555555` is refused with "Please provide a valid UUID".

### Event add – Event Info with line breaks
<a id="event-add-multiline-info"></a>

Event creation with an Event Info on several lines

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **Add Event** button
4. Type `QA line 1`, press Shift+Enter, then type `QA line 2` in **Event Info**.
5. Click **Create Event Entry**.
6. Go to `/events/index`.

**Expected:** the event is created and the Event Info is shown readably on the events/view page and in the Events list, without breaking the layout.

**Seeded data:** `QA line 1` / `QA line 2`, tag `qa:event-add-multiline-info`, created through the API: accepted, the line break is stored.

### Event add – extreme dates
<a id="event-add-extreme-dates"></a>

Event creation with very old and very far dates

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **Add Event** button
4. Type `QA date 1900` in **Event Info**.
5. Type `01/01/1900` in **Event Date (UTC)**.
6. Click **Create Event Entry**.
7. Go to `/events/index` and click **Add Event** button
8. Type `QA date 9999` in **Event Info**.
9. Type `31/12/9999` in **Event Date (UTC)**.
10. Click **Create Event Entry**.

**Expected:** each event is created with the typed date, or refused with a clear message; no error page is shown.

**Seeded data:** `QA date 1900` (date 1900-01-01) and `QA date 9999` (date 9999-12-31), tag `qa:event-add-extreme-dates`, created through the API: both accepted with these dates.
