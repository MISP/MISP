# MISP Web UI – Event Add – Validation Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Event add – empty Event Info](#event-add-empty-info) | |
| 2 | [Event add – Event Info with only spaces](#event-add-spaces-info) | |
| 3 | [Event add – invalid date](#event-add-invalid-date) | |
| 4 | [Event add – extends an unknown event ID](#event-add-extends-unknown-id) | |
| 5 | [Event add – Event Info over the database limit](#event-add-info-too-long) | |

---


# E2E Tests

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

### Event add – Event Info over the database limit
<a id="event-add-info-too-long"></a>

Event creation with an Event Info longer than 65,535 characters is refused with a clear message (regression test for Bug 3)

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **Add Event** button
4. Paste a text of 70,000 characters in **Event Info**.
5. Click **Create Event Entry**.

**Expected:** the event is not created, no "An Internal Error Has Occurred." page is shown, and a message explains that **Event Info** is too long.
