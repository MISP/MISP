# MISP Web UI – Test Plan & Results

<a id="navigation"></a>

Roles:

- user
- site-admin
- org-admin

## Bugs

| #   | Bug | Status | Version | Owner |
| --- | --- | --- | --- | --- |
| 1   | [CSRF error when creating an event with a future date](#bug-1) | Fixed | v2.5.48 | Thomas |
| 2   | [Selected event loses its checkbox when switching between table and card view](#bug-2) | Open | v2.5.48 | |
| 3   | [Internal error when Event Info is longer than the database limit](#bug-3) | Open | v2.5.48 | |
| 4   | [Galaxy filter on the Events list is ignored](#bug-4) | Open | v2.5.48 | |
| 5   | [Event selection is lost when sorting the Events list](#bug-5) | Open | v2.5.48 | |

## E2E UI Tests

https://github.com/MISP/MISP/tree/ui_test/tests/ui-test

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

### Bug 2 – Selected event loses its checkbox when switching between table and card view

<a id="bug-2"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce

1. Go to the Events list page (`/events/index`) in table view.
2. Tick the checkbox of one event.
3. Switch to card view.

- **Expected result**: The event is still ticked in card view.
- **Actual result**: The selection still counts the event as selected, but its checkbox is not ticked anymore in card view.
- **Notes**: It also happens the other way round (select in card view, then switch to table view).
- **Likely cause**: The table view and the card view are two separate lists, each with its own checkboxes. `setView()` in `app/webroot/js/mispOvermind.js` only hides one list and shows the other; it does not copy the ticked checkboxes to the list that becomes visible.

### Bug 3 – Internal error when Event Info is longer than the database limit

<a id="bug-3"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce

1. On the Events list page, click **Add Event**.
2. Paste a very long text (more than 65,535 characters) in **Event Info**.
3. Click **Create Event Entry**.

- **Expected result**: The form refuses the text and shows a clear message about the maximum length.
- **Actual result**: Error page "An Internal Error Has Occurred." - event not created.
- **Notes**: There is no length limit or check on **Event Info** in the form. error.log shows: `SQLSTATE[22001]: String data, right truncated: 1406 Data too long for column 'info' at row 1`.
- **Likely cause**: `events.info` is a MySQL `TEXT` column (max 65,535 bytes). The `info` validation rule in `app/Model/Event.php` only checks that the value is not empty, and the **Event Info** field has no `maxlength`, so the too-long value reaches the database and the PDOException is shown as an internal error.

### Bug 4 – Galaxy filter on the Events list is ignored

<a id="bug-4"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce

1. Go to the Events list page (`/events/index`).
2. Open the filters.
3. In **Galaxy**, select a galaxy that is attached to none of the events.
4. Apply the filter.

- **Expected result**: No event is shown.
- **Actual result**: All events are still shown, as if no filter was applied.
- **Notes**: It only happens with the **Galaxy** filter. The **Tags** filter works.
- **Likely cause**: The filter adds `searchgalaxy:<name>` to the URL (`app/webroot/js/mispOvermind.js`), but `__setIndexFilterConditions()` in `app/Controller/EventsController.php` has no `galaxy` case, so the value falls into `default: continue 2;` and is silently ignored.


### Bug 5 – Event selection is lost when sorting the Events list

<a id="bug-5"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce

1. Go to the Events list page (`/events/index`).
2. Tick the checkbox of one event.
3. Click a column header to sort the list (sort icon `<>`).

- **Expected result**: The event stays selected after the list is sorted.
- **Actual result**: The event is unselected, both in the selection and in its checkbox.
- **Notes**: Not sure it is a bug: it may be an intended choice.
- **Likely cause**: Column headers are pagination sort links (`$paginator->sort()` in `genericElementsBS5/IndexTable/headers.ctp`) that reload the list. The selection only exists in the page (it is not stored anywhere), so it is reset when the list reloads.

# Recommendations

### Recommendation 1 – Filter the Events list by several tags or galaxies

<a id="recommendation-1"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

- **Current behaviour**: The filters on the Events list (`/events/index`) accept only one tag and one galaxy at a time.
- **Proposal**: Allow selecting several tags and several galaxies in the same filter, with a choice between **AND** (the event must have all of them) and **OR** (the event must have at least one of them).
- **Benefit**: Analysts can find events matching a combination of tags/galaxies in one search instead of filtering several times.

### Recommendation 2 – Add a "Go to top" button

<a id="recommendation-2"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

- **Current behaviour**: On long pages (e.g. the Events list or an event with many attributes), there is no quick way to go back to the top of the page.
- **Proposal**: Add a floating **Go to top** button that appears after scrolling down and brings the user back to the top of the page.
- **Benefit**: Faster navigation on long pages, without scrolling back up manually.
