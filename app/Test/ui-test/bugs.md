# MISP Web UI – Bugs  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 

## Bugs

| # | Bug | Status | Version | Owner | 
|---|-----|--------| ------- | ----- |
| 1 | [CSRF error when creating an event with a future date](#bug-1) | Fixed | v2.5.48 | Thomas |
| 2 | [Invalid Extends value: event not saved and no reason shown](#bug-2) | Open | v2.5.48 | |

---


# Bugs
### Bug 1 – CSRF error when creating an event with a future date
<a id="bug-1"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce
1. On the Events list page, click **Create an event**.
2. Enter a title.
3. Set a date later than today (e.g. 2030).
4. Submit the form.

- **Expected result**: The event is created.
- **Actual result**: CSRF error - event not created
- **Notes**: It only happens when the date is changed. With the default date (today), the event is created normally.
- **Likely cause**: The date is stored in a hidden form field that CakePHP locks. When the date picker changes its value, MISP rejects the form as tampered and shows a misleading CSRF error.

### Bug 2 – Invalid Extends value: event not saved and no reason shown
<a id="bug-2"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce
1. On the Events list page, click **Add Event**.
2. Type a title in **Event Info**.
3. Type `999999` (an event ID that does not exist) in **Extends**.
4. Click **Create Event Entry**.

- **Expected result**: The form stays open and says why the event cannot be saved ("Invalid event ID provided.").
- **Actual result**: The page goes back to the Events list with only "The event could not be saved. Please, try again." and everything typed in the form is lost.
- **Notes**: Found by reading the code, not yet reproduced in the UI. The same happens for any server-side validation error (e.g. Extends = `abc`).
- **Likely cause**: In `EventsController::add()`, when the save fails with the Overmind theme, MISP shows a generic flash message and redirects to `/events/index`. The validation errors returned by `Event::_add()` (`$validationErrors`) are never shown and the form data is dropped.
