# MISP Web UI – Event View – Performance Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Event view – event with 2,000 attributes](#event-view-big-event) | |

---


# E2E Tests

### Event view – event with 2,000 attributes
<a id="event-view-big-event"></a>

The detail page of a large event loads in a reasonable time and stays usable

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the event `QA big event`. If it does not exist, create it with **Add Event** and add 2,000 attributes of type `ip-dst` (one of them with the value `198.51.100.250`).
4. Measure the time until the attribute list is displayed.
5. Go to the next page of attributes.
6. Search for `198.51.100.250` in the attribute search.

**Expected:** the page is usable in less than 5 seconds, the attributes are paginated, the next page loads, and the search finds the attribute; no error or frozen page.

**Seeded data:** `QA big event`, tag `qa:event-view-big-event`, 2,000 `ip-dst` attributes (one is `198.51.100.250`). Through the API, `/events/view/<id>` answers in about 0.25 s; the UI page time is still to measure.
