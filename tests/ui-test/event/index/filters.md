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
| 6 | [Event index – search with a single match](#event-index-search-single) | |
| 7 | [Event index – combined filters](#event-index-combined-filters) | |
| 8 | [Event index – filter kept on the next page](#event-index-filter-pagination) | |

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

**Seeded data:** Tag `qa:unused-tag` exists and is attached to no event: use it in **Tags**.

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

### Event index – search with a single match
<a id="event-index-search-single"></a>

A search that matches exactly one event opens that event (regression test for Bug 13)

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event named `QA unique search 7f3k` with **Add Event**.
4. Go to `/events/index`.
5. Type `QA unique search 7f3k` in the search bar of the Events list.
6. Press Enter.

**Expected:** the detail page of `QA unique search 7f3k` opens at `/events/view2/<id>` in the Overmind layout.

**Seeded data:** `QA unique search 7f3k` (#13), tag `qa:event-index-search-single`. It is the only event with this name.

### Event index – combined filters
<a id="event-index-combined-filters"></a>

Two filters applied together only keep events matching both

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **More filters**.
4. In **Tags**, select `tlp:green`.
5. In **Published**, select **Published**.
6. Apply the filters.

**Expected:** only published events with the tag `tlp:green` are listed; removing one filter shows more events again.

**Seeded data:** 3 events, tag `qa:event-index-combined-filters`: `QA filter published green` (#14, published, `tlp:green`), `QA filter unpublished green` (#15, not published, `tlp:green`), `QA filter published no tlp` (#16, published, no `tlp:green`). Only #14 must be listed.

### Event index – filter kept on the next page
<a id="event-index-filter-pagination"></a>

A filter stays applied when going to the next page of results

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Click **More filters**.
4. In **Tags**, select `qa:event-index-filter-pagination` (70 events).
5. Apply the filter.
6. Go to the next page of the list.

**Expected:** page 1 shows 60 events and page 2 shows the 10 others, all with the tag `qa:event-index-filter-pagination`; no event without this tag is shown.

**Seeded data:** 70 events `QA page filter 01` to `QA page filter 70` (#28 to #97), all with the tag `qa:event-index-filter-pagination`. The list shows 60 events per page.
