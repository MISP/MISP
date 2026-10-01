# MISP Web UI – Event Index – Selection Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Event index – selection kept when switching view](#event-index-selection-switch-view) | |
| 2 | [Event index – selection kept when sorting](#event-index-selection-sort) | |
| 3 | [Event index – delete selected events](#event-index-mass-delete) | |

---


# E2E Tests

### Event index – selection kept when switching view
<a id="event-index-selection-switch-view"></a>

A selected event stays ticked when switching between table and card view (regression test for Bug 7)

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Switch to table view.
4. Tick the checkbox of the first event.
5. Switch to card view.
6. Switch back to table view.

**Expected:** the first event is ticked in card view and still ticked after going back to table view.

### Event index – selection kept when sorting
<a id="event-index-selection-sort"></a>

A selected event stays selected after sorting the Events list by a column (regression test for Bug 27)

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Tick the checkbox of the first event.
4. Click the **ID** column header to sort the list.

**Expected:** the event is still ticked and still counted in the selection.

### Event index – delete selected events
<a id="event-index-mass-delete"></a>

Delete several events at once from the Events list

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create two events named `QA mass delete 1` and `QA mass delete 2` with **Add Event**.
4. Go to `/events/index`.
5. Tick the checkboxes of `QA mass delete 1` and `QA mass delete 2`.
6. Click **Delete** in the selection toolbar and confirm.

**Expected:** both events are deleted and are no longer in the Events list.

**Seeded data:** `QA mass delete 1` and `QA mass delete 2`, tag `qa:event-index-mass-delete`.
