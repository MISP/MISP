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
| 6   | [CSRF error when submitting a new object after Review](#bug-6) | Open | v2.5.48 | |
| 7   | [Internal error when an emoji is saved in many text fields](#bug-7) | Open | v2.5.48 | |
| 8   | [Tag name longer than 255 characters is silently cut](#bug-8) | Open | v2.5.48 | |
| 9   | [Tags list: the "Not favourite" filter still shows favourite tags](#bug-9) | Open | v2.5.48 | |
| 10  | [Warninglists list: the "Default" filter is ignored](#bug-10) | Open | v2.5.48 | |
| 11  | [Inactive event template can still be used by its URL](#bug-11) | Open | v2.5.48 | |
| 12  | [Event template form: an invalid value gives an error that does not say which field](#bug-12) | Open | v2.5.48 | |
| 13  | [Some actions open the old event page /events/view instead of the Overmind one](#bug-13) | Open | v2.5.48 | |

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
- **Notes**: It also happens the other way round (select in card view, then switch to table view). **Also affects:** every list built with the same table/card component (`app/View/Themed/Overmind/Elements/genericElementsBS5/IndexTable/scaffold.ctp`) that has row checkboxes — 63 list pages, e.g. Attributes list, Event Reports, Galaxies, Galaxy clusters, Tags, Tag Collections, Taxonomies, Object Templates, Warninglists, Noticelists, Feeds, Servers, Organisations, Users, Roles, Sharing Groups, Workflows, Jobs, Auth keys, Event/Org blocklists. Not yet checked one by one.
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
- **Notes**: Not sure it is a bug: it may be an intended choice. **Also affects:** every list with sortable column headers and row checkboxes built with the same component (`genericElementsBS5/IndexTable/scaffold.ctp`) — 63 list pages, e.g. Attributes list, Event Reports, Galaxies, Galaxy clusters, Tags, Tag Collections, Taxonomies, Object Templates, Warninglists, Noticelists, Feeds, Servers, Organisations, Users, Roles, Sharing Groups, Workflows, Jobs, Auth keys, Event/Org blocklists. Not yet checked one by one.
- **Likely cause**: Column headers are pagination sort links (`$paginator->sort()` in `genericElementsBS5/IndexTable/headers.ctp`) that reload the list. The selection only exists in the page (it is not stored anywhere), so it is reset when the list reloads.

### Bug 6 – CSRF error when submitting a new object after Review

<a id="bug-6"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce

1. Open an event and click **Add Object**.
2. Select any template (e.g. `nova-rule` or `scrippsco2-c13-daily`) and click **Next**.
3. On the **Object** step, scroll to the bottom of the form.
4. Click **Review**, then **Submit**.

- **Expected result**: The object is saved, or a clear message says which fields are missing.
- **Actual result**: Error page "You have tripped the cross-site request forgery protection of MISP" - object not saved.
- **Notes**: Happened with two different templates (`nova-rule`, `scrippsco2-c13-daily`), so it does not depend on the template. error.log shows: `Blackhole exception when accessing /objects/add/45/333 (isRest: 0, action: add, unlockedActions: ["revise_object","get_row"]): The request has been black-holed`. **Also affects:** the other forms with the same locked hidden fields filled by JavaScript: **Add/Edit Attribute** (`first_seen`, `last_seen` in `Overmind/Attributes/add.ctp`), **Edit Object** (same form as Add Object), and **Add/Edit Event** (`date` in `Overmind/Events/add.ctp`, Bug 1). None of them unlocks these fields.
- **Likely cause**: The POST to `/objects/add` is rejected by CakePHP's Security component (black-hole = form considered tampered), which MISP shows as a CSRF error. The form contains locked hidden fields (`first_seen` and `last_seen` in `app/View/Themed/Overmind/Objects/add.ctp`) that the page's JavaScript fills, the same pattern as Bug 1.

### Bug 7 – Internal error when an emoji is saved in many text fields

<a id="bug-7"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce

1. Open an event and click **Add Attribute**.
2. In **Category** select `Network activity`, in **Type** select `ip-dst`, and type `198.51.100.60` in **Value**.
3. Type `QA comment 🚀` in **Contextual Comment**.
4. Click **Add Attribute** to save.

- **Expected result**: The attribute is saved with its comment, emoji included.
- **Actual result**: "An Internal Error Has Occurred." (HTTP 500) - attribute not saved.
- **Notes**: Confirmed through the API for an attribute comment and a tag collection name (`QA collection 🚀`), still to confirm in the UI. error.log shows: `SQLSTATE[HY000]: General error: 1267 Illegal mix of collations (utf8mb3_unicode_ci,IMPLICIT) and (utf8mb4_unicode_ci,COERCIBLE) for operation '='`. Event Info, tag names and event reports are fine (`utf8mb4`). **Also affects** (columns still in `utf8mb3`): attribute and object comments, object name and description, galaxy name and description, galaxy cluster value and elements, tag collection name and description, organisation name and description, sharing group name and description, feed name, server name, role name, warninglist name, description and entries, noticelist name, decaying model name, correlation rules, blocklist comments, bookmarks, user settings, news, templates.
- **Likely cause**: These columns use the `utf8mb3` character set, which cannot store 4-byte characters such as emoji, while MISP talks to the database in `utf8mb4`; the tables already migrated (`events`, `tags`, …) work.

### Bug 8 – Tag name longer than 255 characters is silently cut

<a id="bug-8"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce

1. Go to `/tags/index` and click **Add Tag**.
2. Paste a name of 300 characters in **Tag Name**.
3. Click **Add Tag**.

- **Expected result**: The tag is refused with a message that the name is too long.
- **Actual result**: The tag is created, but its name is cut to 255 characters without any warning.
- **Notes**: Found through the API (`POST /tags/add` with a 300-character name returned a tag whose stored name has 255 characters), still to confirm in the UI.
- **Likely cause**: `tags.name` is `varchar(255)` and the `name` rules in `app/Model/Tag.php` only check that it is not empty and unique, so the database cuts the value.

### Bug 9 – Tags list: the "Not favourite" filter still shows favourite tags

<a id="bug-9"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce

1. Mark one tag as **Favourite** on the Tags list (`/tags/index`).
2. Click **More filters**, in **Favourite** select **Not favourite** and apply (URL `/tags/index/favouritesOnly:0`).

- **Expected result**: Only the tags that are not favourite are listed.
- **Actual result**: All tags are listed, the favourite ones included. **Favourite only** (`favouritesOnly:1`) works.
- **Notes**: Through the API: 181 tags in total, 1 favourite; `favouritesOnly:1` returns 1 tag, `favouritesOnly:0` returns all 181. **Also affects:** the same **Favourite** filter on the Tag Collections list (`/tag_collections/index`): `TagCollectionsController` never reads `favouritesOnly`, so both choices are probably ignored there (found in the code, not yet checked: no collection exists on the test instance).
- **Likely cause**: In `TagsController::index()` the filter is applied only `if (!empty($passedArgsArray['favouritesOnly']))`; the value `'0'` is "empty" in PHP, so no condition is added, and there is no branch that excludes the favourite tags.

### Bug 10 – Warninglists list: the "Default" filter is ignored

<a id="bug-10"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce

1. Go to the Warninglists list (`/warninglists/index`).
2. Click **More filters**, in **Default** select the value for non-default lists and apply (URL `/warninglists/index/default:0`).

- **Expected result**: Only the warninglists that are not default (custom ones) are listed.
- **Actual result**: All warninglists are listed.
- **Notes**: Through the API: the instance has 225 warninglists, all default; `default:0` and `default:1` both return 225. The **Enabled** filter of the same page works (`enabled:1` returns 0, as none is enabled).
- **Likely cause**: The **Default** filter is offered in `app/View/Themed/Overmind/Warninglists/index.ctp`, but `default` is not in the list of filters read by `WarninglistsController::index()` (`value`, `category`, `type`, `enabled`, `id`, `matchValue`), so it is dropped.

### Bug 11 – Inactive event template can still be used by its URL

<a id="bug-11"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce

1. Log in as a user with the `User` role.
2. Check in `/event_templates/index` that `Suspicious domain triage` (#8) is inactive (it is not offered in **Use a template**).
3. Go to `/event_templates/instantiate/8`.
4. Fill the mandatory fields and click **Create event**.

- **Expected result**: The template is refused because it is inactive; no event is created.
- **Actual result**: The event is created from the inactive template.
- **Notes**: Confirmed through the API: `qa-user-a` (role `User`) posted the mandatory values to `/event_templates/instantiate/8` and got `event_id: 105` (`Suspicious domain — qa-inactive.example`). The list page says "Inactive templates are hidden from the "From template" picker", so hiding is the only protection.
- **Likely cause**: `EventTemplatesController::instantiate()` loads the template with `__fetchForRead()` (which checks visibility only) and never checks `EventTemplate.active` before rendering the form or creating the event.

### Bug 12 – Event template form: an invalid value gives an error that does not say which field

<a id="bug-12"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce

1. Make the event template `Suspicious domain triage` active and open it with **Use a template** from **Add Event**.
2. Type `not a domain!` in `domain`, fill the other mandatory fields.
3. Click **Create event**.

- **Expected result**: The form says that `domain` is not a valid domain name.
- **Actual result**: The event is not created and the only messages are "Some attributes or objects were dropped during event creation." and "expected 2 top-level attribute(s), saved 1 — see audit log for dropped rows".
- **Notes**: Confirmed through the API (`POST /event_templates/instantiate/8`, HTTP 403). The rollback works: no partial event is left. A template user (often a reporter, not an admin) cannot read the audit log to find the reason.
- **Likely cause**: `app/Lib/Tools/EventTemplateInstantiator.php` only counts the saved attributes against the expected ones and returns a generic message; the validation error of the dropped attribute is not passed back to the form.

### Bug 13 – Some actions open the old event page /events/view instead of the Overmind one

<a id="bug-13"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce

1. Make an event template active, open it with **Use a template** from **Add Event**.
2. Fill the mandatory fields and click **Create event**.

- **Expected result**: The new event opens on the Overmind event page `/events/view2/<id>`.
- **Actual result**: The browser goes to `/events/view/<id>`, which renders the old (non-Overmind) event page.
- **Notes**: Checked on the instance: `/events/view/103` returns the old event page (old markup, 150 kB) while `/events/view2/103` is the Overmind page. **Also affects** (found in the code, they redirect to `view` without checking the theme): **Unpublish Event** (`EventsController::unpublish()`), a quick search on the Events list that matches only one event (`EventsController::index()`), and **Remove pivot** (`EventsController::removePivot()`). **Publish Event** does check the theme and opens `view2`.
- **Likely cause**: `app/webroot/js/event-templates/user_form.js` sends the user to `cfg.baseurl + '/events/view/' + event_id`, and the controller actions listed above call `redirect(['action' => 'view', …])` instead of using `view2` when the theme is Overmind; `/events/view` itself does not forward to `view2`.

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
