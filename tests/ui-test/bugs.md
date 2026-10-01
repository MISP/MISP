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
| 11  | [Event template form: an invalid value gives an error that does not say which field](#bug-11) | Open | v2.5.48 | |
| 12  | [Some actions open the old event page /events/view instead of the Overmind one](#bug-12) | Open | v2.5.48 | |
| 13  | [CSV export does not neutralise spreadsheet formulas](#bug-13) | Open | v2.5.48 | |
| 14  | [Creating an event report opens the old event page](#bug-14) | Open | v2.5.48 | |
| 15  | [Adding an attribute to an existing object does not add anything](#bug-15) | Open | v2.5.48 | |
| 16  | [The correlation icon of an attribute does not toggle the correlation](#bug-16) | Open | v2.5.48 | |
| 17  | [Attribute menu of an object is hidden behind the pagination bar](#bug-17) | Open | v2.5.48 | |
| 18  | [Events with proposals list: the actions menu is empty](#bug-18) | Open | v2.5.48 | |

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
- **Notes**: **Confirmed in the UI** (real browser, Overmind, 2026-10-01). It also happens the other way round (select in card view, then switch to table view). **Also affects:** every list built with the same table/card component (`app/View/Themed/Overmind/Elements/genericElementsBS5/IndexTable/scaffold.ctp`) that has row checkboxes — 63 list pages. **Confirmed in a real browser (Playwright, 2026-10-01) on 14 lists:** `/events/index`, `/attributes/index`, `/galaxies/index`, `/tags/index`, `/taxonomies/index`, `/objectTemplates/index`, `/warninglists/index`, `/noticelists/index`, `/organisations/index`, `/admin/users/index`, `/roles/index`, `/event_templates/index`, `/auth_keys/index`, `/event_blocklists/index` — in each, the ticked row is unticked in card view (it is still ticked when going back to table view). Lists that were empty on the test instance (Feeds, Sharing Groups, Correlation exclusions, Workflows, Servers, Jobs) could not be checked.
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
- **Notes**: **Confirmed in the UI** (real browser, Overmind, 2026-10-01). The Add Event modal has no `maxlength` and shows "An Internal Error Has Occurred." There is no length limit or check on **Event Info** in the form. error.log shows: `SQLSTATE[22001]: String data, right truncated: 1406 Data too long for column 'info' at row 1`.
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
- **Notes**: **Confirmed in the UI** (real browser, Overmind, 2026-10-01). With **More filters** → **Galaxy** = a galaxy used by no event → **Apply filters**, the URL gets `searchgalaxy:…` and the list still shows all events. It only happens with the **Galaxy** filter. The **Tags** filter works.
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
- **Notes**: **Confirmed in the UI** (real browser, Overmind, 2026-10-01). Not sure it is a bug: it may be an intended choice. **Also affects:** every list with sortable column headers and row checkboxes built with the same component (`genericElementsBS5/IndexTable/scaffold.ctp`) — 63 list pages. **Confirmed in a real browser (Playwright, 2026-10-01) on the same 14 lists:** `/events/index`, `/attributes/index`, `/galaxies/index`, `/tags/index`, `/taxonomies/index`, `/objectTemplates/index`, `/warninglists/index`, `/noticelists/index`, `/organisations/index`, `/admin/users/index`, `/roles/index`, `/event_templates/index`, `/auth_keys/index`, `/event_blocklists/index` — in each, the ticked row is unticked after clicking a sortable column header.
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
- **Notes**: **Confirmed in the UI** (real browser, Overmind, 2026-10-01). Happened with two different templates (`nova-rule`, `scrippsco2-c13-daily`), so it does not depend on the template. error.log shows (example): `Blackhole exception when accessing /objects/add/<event id>/<template id> (isRest: 0, action: add, unlockedActions: ["revise_object","get_row"]): The request has been black-holed`. It happens with and without filling **First Seen**. **Not affected** (checked in the UI): **Add Attribute** with **First Seen** filled, and **Edit object** ("Object saved.").
- **Likely cause**: The POST to `/objects/add` is rejected by CakePHP's Security component (black-hole = form considered tampered), which MISP shows as a CSRF error. The exact field that breaks the form token is not identified yet (the attribute rows of the form are built by JavaScript).

### Bug 7 – Internal error when an emoji is saved in many text fields

<a id="bug-7"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce

1. Create an event with **Add Event** and click **Add Attribute**.
2. In **Category** select `Network activity`, in **Type** select `ip-dst`, and type `198.51.100.60` in **Value**.
3. Type `QA comment 🚀` in **Contextual Comment**.
4. Click **Add Attribute** to save.

- **Expected result**: The attribute is saved with its comment, emoji included.
- **Actual result**: "An Internal Error Has Occurred." (HTTP 500) - attribute not saved.
- **Notes**: **Confirmed in the UI** (real browser, Overmind, 2026-10-01). Through **Add Attribute** with the comment `QA comment 🚀`: "An Internal Error Has Occurred." Confirmed through the API on 2026-10-01 — **HTTP 500 with an emoji in:** attribute comment, object comment, galaxy name, galaxy cluster value, organisation name, sharing group name, tag collection name, feed name, warninglist name, event blocklist comment, role name. **Saved fine:** Event Info, attribute value (type `text`), event report name and content, tag name, correlation exclusion comment. error.log shows: `SQLSTATE[HY000]: General error: 1267 Illegal mix of collations (utf8mb3_unicode_ci,IMPLICIT) and (utf8mb4_unicode_ci,COERCIBLE) for operation '='`. No partial row was left after the errors. **Also affects** (other columns still in `utf8mb3`, not tested one by one): object name and description, galaxy description and elements, organisation and sharing group descriptions, noticelist name, decaying model name, correlation rules, bookmarks, user settings, news, templates, proposals (`shadow_attributes.comment`).
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
- **Notes**: **Confirmed in the UI** (real browser, Overmind, 2026-10-01). Through **Add Tag** with a 300-character name: the tag is created with a 255-character name (the field has no `maxlength`). Also seen through the API (`POST /tags/add`).
- **Likely cause**: `tags.name` is `varchar(255)` and the `name` rules in `app/Model/Tag.php` only check that it is not empty and unique, so the database cuts the value.

### Bug 9 – Tags list: the "Not favourite" filter still shows favourite tags

<a id="bug-9"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce

1. Mark one tag as **Favourite** on the Tags list (`/tags/index`).
2. Click **More filters**, in **Favourite** select **Not favourite** and apply (URL `/tags/index/favouritesOnly:0`).

- **Expected result**: Only the tags that are not favourite are listed.
- **Actual result**: All tags are listed, the favourite ones included. **Favourite only** (`favouritesOnly:1`) works.
- **Notes**: **Confirmed in the UI** (real browser, Overmind, 2026-10-01). With one favourite tag, **Not favourite** still lists it. Checked through the API with one favourite tag: `favouritesOnly:1` returns only that tag, `favouritesOnly:0` returns every tag, the favourite one included. **Also affects:** the same **Favourite** filter on the Tag Collections list (`/tag_collections/index`): `TagCollectionsController` never reads `favouritesOnly`, so both choices are probably ignored there (found in the code, not yet checked).
- **Likely cause**: In `TagsController::index()` the filter is applied only `if (!empty($passedArgsArray['favouritesOnly']))`; the value `'0'` is "empty" in PHP, so no condition is added, and there is no branch that excludes the favourite tags.

### Bug 10 – Warninglists list: the "Default" filter is ignored

<a id="bug-10"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce

1. Go to the Warninglists list (`/warninglists/index`).
2. Click **More filters**, in **Default** select the value for non-default lists and apply (URL `/warninglists/index/default:0`).

- **Expected result**: Only the warninglists that are not default (custom ones) are listed.
- **Actual result**: All warninglists are listed.
- **Notes**: **Confirmed in the UI** (real browser, Overmind, 2026-10-01). **More filters** → **Default** = non-default → **Apply filters**: all warninglists are still listed. On a fresh install every warninglist is a default one, so `default:0` should return nothing; through the API `default:0` and `default:1` both return all of them. The **Enabled** filter of the same page works.
- **Likely cause**: The **Default** filter is offered in `app/View/Themed/Overmind/Warninglists/index.ctp`, but `default` is not in the list of filters read by `WarninglistsController::index()` (`value`, `category`, `type`, `enabled`, `id`, `matchValue`), so it is dropped.

### Bug 11 – Event template form: an invalid value gives an error that does not say which field

<a id="bug-11"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce

1. Make the event template `Suspicious domain triage` active and open it with **Use a template** from **Add Event**.
2. Type `not a domain!` in `domain`, fill the other mandatory fields.
3. Click **Create event**.

- **Expected result**: The form says that `domain` is not a valid domain name.
- **Actual result**: The event is not created and the only messages are "Some attributes or objects were dropped during event creation." and "expected 2 top-level attribute(s), saved 1 — see audit log for dropped rows".
- **Notes**: **Confirmed in the UI** (real browser, Overmind, 2026-10-01). The template form shows only "Could not create event: Some attributes or objects were dropped during event creation. expected 2 top-level attribute(s), saved 1 — see audit log for dropped rows". Confirmed through the API (`POST /event_templates/instantiate/<id>`, HTTP 403). The rollback works: no partial event is left. A template user (often a reporter, not an admin) cannot read the audit log to find the reason.
- **Likely cause**: `app/Lib/Tools/EventTemplateInstantiator.php` only counts the saved attributes against the expected ones and returns a generic message; the validation error of the dropped attribute is not passed back to the form.

### Bug 12 – Some actions open the old event page /events/view instead of the Overmind one

<a id="bug-12"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce

1. Make an event template active, open it with **Use a template** from **Add Event**.
2. Fill the mandatory fields and click **Create event**.

- **Expected result**: The new event opens on the Overmind event page `/events/view2/<id>`.
- **Actual result**: The browser goes to `/events/view/<id>`, which renders the old (non-Overmind) event page.
- **Notes**: **Confirmed in the UI** (real browser, Overmind, 2026-10-01). For any event, `/events/view/<id>` returns the old event page while `/events/view2/<id>` is the Overmind page (checked in the Overmind theme). **Also affects** (checked in the UI): **Unpublish Event** opens `/events/view/<id>`, while **Publish Event** opens `/events/view2/<id>`. The search of the Events list is not affected (it filters the list and stays on it).
- **Likely cause**: `app/webroot/js/event-templates/user_form.js` sends the user to `cfg.baseurl + '/events/view/' + event_id`, and `EventsController::unpublish()` calls `redirect(['action' => 'view', …])` instead of using `view2` when the theme is Overmind; `/events/view` itself does not forward to `view2`.

### Bug 13 – CSV export does not neutralise spreadsheet formulas

<a id="bug-13"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce

1. Create an event with **Add Event**, and add an attribute (e.g. `ip-dst` `198.51.100.122`) with the comment `=HYPERLINK("http://qa-csv.example","click")` and another attribute with the comment `+cmd|calc`.
2. Use **Download as** → **CSV (NOT FOR EXCEL)**.
3. Open the file.

- **Expected result**: Cells starting with `=`, `+`, `-` or `@` are neutralised (e.g. prefixed with `'`), so a spreadsheet does not run them.
- **Actual result**: The comments are written unchanged, so a spreadsheet opening the file runs them as formulas.
- **Notes**: **Confirmed in the UI** (real browser, Overmind, 2026-10-01). **Download as** → **CSV (NOT FOR EXCEL…)** downloads `misp.event.<id>.csv` with both formulas unchanged. Confirmed through the API (`/events/restSearch` with `returnFormat: csv`). The menu labels the format "CSV (NOT FOR EXCEL)", but values come from other organisations (sync, proposals, feeds), so a shared CSV can carry formulas. **Also affects:** every CSV output built with the same exporter: attribute `restSearch` in CSV, the CSV cached export on `/events/export`, and the deprecated `/events/csv`.
- **Likely cause**: `app/Lib/Export/CsvExport.php` quotes the values but does not escape a leading formula character.

### Bug 14 – Creating an event report opens the old event page

<a id="bug-14"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce

1. Create an event with **Add Event**.
2. On the event page (`/events/view2/<event id>`), open the **Reports** tab.
3. Create an event report and submit it.

- **Expected result**: The event page stays the Overmind one (`/events/view2/<event id>`, **Reports** tab) and shows the new report.
- **Actual result**: The browser goes to `/events/view/<event id>`, the old (non-Overmind) event page.
- **Notes**: **Confirmed in the UI** (tester, 2026-10-01). Same kind of problem as Bug 12 (template creation and **Unpublish Event** also open `/events/view`).
- **Likely cause**: `EventReportsController::add()` sets its redirect target to `['controller' => 'events', 'action' => 'view', $eventId]` without checking the theme, instead of `view2` in the Overmind theme.

### Bug 15 – Adding an attribute to an existing object does not add anything

<a id="bug-15"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce

1. Create an event with **Add Event**.
2. Click **Add Object**, choose the template `domain-ip`, fill only `domain` = `qa-object.example`, then **Review** and **Submit**.
3. Go to the **Objects** tab and click **Edit object** on this object.
4. Type `198.51.100.180` in the empty field `ip`.
5. Click **Review**, then **Submit**.

- **Expected result**: The object now has the new attribute `ip` = `198.51.100.180`.
- **Actual result**: Nothing is added, neither to the object nor to the event.
- **Notes**: **Confirmed in the UI** (real browser, Overmind, 2026-10-01). "Object saved." is shown but the new attribute is not in the object. Changing the value of an attribute that already exists in the object is saved correctly; only new attributes are lost. The same happens when several new attributes are filled at once.
- **Likely cause**: Unknown

### Bug 16 – The correlation icon of an attribute does not toggle the correlation

<a id="bug-16"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce

1. Create an event with **Add Event** and add an attribute `ip-dst` `198.51.100.181` (or an object with an attribute).
2. In the Attributes tab, click the correlation icon (`chain-link`) of the attribute.
3. In the confirmation window, choose **Disable correlation** (or **Enable correlation**).

- **Expected result**: The correlation of the attribute is disabled (or enabled) and the icon changes.
- **Actual result**: The state does not change and the message `error: undefined` is shown.
- **Notes**: **Confirmed in the UI** (real browser, Overmind, 2026-10-01). Clicking the icon and confirming shows "Error: undefined" and the correlation does not change. The IDS toggle works. The correlation can still be changed by editing the attribute or the object. Reproduced in a browser: the request `POST /attributes/toggleCorrelation/<id>` answers HTTP 400 "The request has been black-holed". **Also affects:** every place that shows this icon (attributes of the event, attributes inside objects, the Attributes list), as they all use the same element.
- **Likely cause**: The icon (`app/View/Themed/Overmind/Elements/genericElementsBS5/IndexTable/Fields/correlate.ctp`) sends a POST with an empty body and only an `X-CSRF-Token` header; `toggleCorrelation` is not in the unlocked actions of `AttributesController`, so CakePHP's Security component black-holes it. The answer has neither `saved` nor `errors`, so the script shows `error: undefined`.

### Bug 17 – Attribute menu of an object is hidden behind the pagination bar

<a id="bug-17"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce

1. Create an event with **Add Event** and add one object (e.g. `domain-ip` with a domain).
2. Go to the **Objects** tab and switch to card view.
3. Click the **⋮** button of an attribute of the object.

- **Expected result**: The whole menu (Copy UUID, Propose change, Enrich, Edit, Delete, Add note, Add opinion, Add relationship, View analyst data) is shown above the rest of the page.
- **Actual result**: The pagination bar ("Page 1 of 1, showing …") is drawn over the menu and hides the entries between **Edit** and **Add note**.
- **Notes**: **Confirmed in the UI** (screenshot of a tester, 2026-10-01). Seen with an object that is the last one of the page, so the menu goes down over the pagination bar.
- **Likely cause**: Unknown

### Bug 18 – Events with proposals list: the actions menu is empty

<a id="bug-18"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce

1. Create an event with **Add Event** and add an attribute (e.g. `ip-dst` `198.51.100.200`).
2. Click **Propose change** on the attribute, change the value and click **Submit proposal**.
3. Go to the list of events with proposals (`/events/proposalEventIndex`).
4. Click the **…** (actions) button of the event.

- **Expected result**: The menu offers actions for the event (at least **View**).
- **Actual result**: The menu opens but is empty.
- **Notes**: **Confirmed in the UI** (real browser, Overmind, 2026-10-01): the menu opens with no entry. No other Overmind list has an empty actions menu.
- **Likely cause**: In `app/View/Themed/Overmind/Events/proposal_event_index.ctp` the **Actions** column uses the `row_actions` element with `'actions' => []`, so the menu is drawn with nothing in it (the Events list defines View, Edit and Delete).

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

### Recommendation 3 – Say why an action was refused

<a id="recommendation-3"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

- **Current behaviour**: Many refusals only say "Could not …" without the reason, e.g. "Could not add auth_key" (invalid IP range), "Could not change_pw User" (password too short), "Could not delete SharingGroup" (still used by events), "Could not add correlation_exclusion" (value already excluded), "Could not attachTagToObject Tag" (tag not allowed for this organisation), "Some attributes or objects were dropped during event creation" (Bug 11), "Could not add User" (email already used or invalid), "Could not delete Organisation" (still has users and events).
- **Proposal**: Always return and show the validation error that caused the refusal (field + rule), in the UI and in the API.
- **Benefit**: Users fix their input themselves instead of guessing or asking an admin to read the logs.

# Missing Features (compared to the default UI)

1. Create a relationship between two objects within an event.
2. Group one or more orphan attributes to create an object.
3. Visual indication of existing analyst data.
   - **Notes**: Only tested with analyst data relationships.

