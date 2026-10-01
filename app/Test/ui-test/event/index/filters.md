# MISP Web UI – Event Index – Filters Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Event index – filter by galaxy](#event-index-filter-galaxy) | |
| 2 | [Event index – filter by tag](#event-index-filter-tag) | |
| 3 | [Event index – date range reversed](#event-index-date-reversed) | |
| 4 | [Event index – search with special characters](#event-index-search-special) | |
| 5 | [Event index – page out of range](#event-index-page-out-of-range) | |

---


# E2E Tests

### Event index – filter by galaxy
<a id="event-index-filter-galaxy"></a>

Filtering the Events list by a galaxy that no event uses shows no event (regression test for Bug 4)

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the filters.
4. In **Galaxy**, select a galaxy that is attached to none of the events.
5. Apply the filter.

**Expected:** the Events list is empty.

### Event index – filter by tag
<a id="event-index-filter-tag"></a>

Filtering the Events list by a tag that no event uses shows no event (control case for Bug 4)

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **More filters**.
4. In **Tags**, select a tag that is attached to none of the events.
5. Apply the filter.

**Expected:** the Events list is empty.

### Event index – date range reversed
<a id="event-index-date-reversed"></a>

Events list with a start date after the end date

1. Log in to MISP as `site-admin`.
2. Go to `/events/index/searchDatefrom:2026-10-01/searchDateuntil:2026-01-01`.

**Expected:** the Events list is empty or a clear message is shown; no error page is shown.

### Event index – search with special characters
<a id="event-index-search-special"></a>

Searching the Events list with special characters

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Type `'%"<b>🚀` in the search bar of the Events list.
4. Press Enter.

**Expected:** the list shows only matching events (or none), the search text is shown as typed, and no error page is shown.

### Event index – page out of range
<a id="event-index-page-out-of-range"></a>

Opening a page number that does not exist

1. Log in to MISP as `site-admin`.
2. Go to `/events/index/page:9999`.

**Expected:** an empty list or the last page is shown; no error page is shown.
