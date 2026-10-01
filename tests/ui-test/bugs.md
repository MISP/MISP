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
| 19  | [Row checkboxes do nothing on some lists](#bug-19) | Open | v2.5.48 | |
| 20  | [A note can be saved without its required text](#bug-20) | Open | v2.5.48 | |
| 21  | [Nested analyst data: deep notes are not shown and the counters are wrong](#bug-21) | Open | v2.5.48 | |
| 22  | [The "Full sightings list" button of the event page reloads the same page](#bug-22) | Open | v2.5.48 | |
| 23  | [Adding a sighting from the UI fails (sighting buttons and Advanced sightings)](#bug-23) | Open | v2.5.48 | |
| 24  | [Object relationships list: "Remove Highlight" is never offered for selected rows](#bug-24) | Open | v2.5.48 | |
| 25  | [No length limit on form fields and searches: internal error or 414](#bug-25) | Open | v2.5.48 | |
| 26  | [A refused form opens an unstyled page (no CSS, no menu)](#bug-26) | Open | v2.5.48 | |
| 27  | [Add User: an empty form gives no message (it only appears after a reload)](#bug-27) | Open | v2.5.48 | |

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
- **Notes**: **Confirmed in the UI** (real browser, Overmind, 2026-10-01). The Add Event modal has no `maxlength` and shows "An Internal Error Has Occurred." error.log shows: `SQLSTATE[22001]: String data, right truncated: 1406 Data too long for column 'info' at row 1`. The same problem exists in many other forms and in the searches, see Bug 25.
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

### Bug 19 – Row checkboxes do nothing on some lists

<a id="bug-19"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce

1. Create an event with **Add Event**, add an attribute, click **Propose change** on it, change the value and click **Submit proposal**.
2. Go to the list of events with proposals (`/events/proposalEventIndex`).
3. Tick the checkbox of the event.

- **Expected result**: A selection bar appears ("Selected items: 1") with actions for the selected rows, as on the Events list.
- **Actual result**: Nothing happens: no selection bar, no action. The checkbox is ticked but cannot be used.
- **Notes**: **Confirmed in the UI** (real browser, Overmind, 2026-10-01): after ticking a row, no new control appears on the page. On `/events/index` the same action shows "Selected items: 1" with **Export** and **Delete**. **Also affects** (checked in the browser, same result): the **Attributes** tab of an event page (ticking one attribute, or all of them with the header checkbox, shows no selection bar, while the **Objects** tab shows "Selected objects: 1" with **Delete**), the Attributes list (`/attributes/index`), the Users list (`/admin/users/index`) and the Proposals list (`/shadow_attributes/index`). The other lists checked (Galaxies, Tags, Taxonomies, Object templates, Warninglists, Noticelists, Organisations, Roles, Event templates, Auth keys, Event blocklists, Sharing groups, Correlation exclusions, Feeds) show the selection bar.
- **Likely cause**: The selection bar (`genericElementsBS5/IndexTable/multi_select_toolbar.ctp`) is only drawn when the list declares at least one mass action (`mass_delete`, `mass_publish`, …) in its `filter_bar`; `Events/proposal_event_index.ctp` declares none (`'children' => []`) but still shows the checkbox column.

### Bug 20 – A note can be saved without its required text

<a id="bug-20"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce

1. Create an event with **Add Event**.
2. On the event page, open **Analyst data** and click **Add note**.
3. Leave **Note** (marked **REQUIRED**) empty and click **Create Note**.
4. Open the note again with **Edit**, type a text and save; then edit it again, delete the whole text and save.

- **Expected result**: An empty note is refused with a message under **Note**, both when adding and when editing.
- **Actual result**: "Note added." — an empty note is created; and an existing note is saved with an empty text, without any error.
- **Notes**: **Confirmed in the UI** (real browser, Overmind, 2026-10-01), for **Add note** and for **Edit**. The **Note** textarea is labelled **REQUIRED** but has no `required` attribute. **Also affects:** opinions probably accept empty values too (`Opinion` has no validation rule either; found in the code, not checked in the UI). Relationships are validated.
- **Likely cause**: `app/Model/Note.php` declares `$childValidate = []`, so nothing on the server checks that `note` is filled, and the form (`app/View/Themed/Overmind/AnalystData/add.ctp`) does not mark the field as required for the browser.

### Bug 21 – Nested analyst data: deep notes are not shown and the counters are wrong

<a id="bug-21"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce

1. Create an event with **Add Event**.
2. On the event page, click **Add note**, type `QA level 1` and click **Create Note**.
3. On the note `QA level 1`, click **Add note** (in its menu), type `QA level 2` and click **Create Note**.
4. Do the same on `QA level 2` with `QA level 3`, then on `QA level 3` with `QA level 4`.
5. Click **Add opinion** twice to add two opinions to the event, and add a note to one of them.
6. Reload the event page and look at the **Analyst data** block.

- **Expected result**: Every note is shown under its parent, and the counters show how many notes and opinions the thread contains.
- **Actual result**:
  - "Note added." is shown for `QA level 4`, but `QA level 4` is not shown anywhere on the event page (levels 1 to 3 are shown).
  - The counters show **Notes (1)** and **Opinions (2)**: the notes nested under notes or under opinions are not counted.
- **Notes**: **Confirmed in the UI** (real browser and tester, Overmind, 2026-10-01). In the database `QA level 4` is attached to `QA level 3`, as expected: the note exists but cannot be seen or answered from the event page. A tester also saw a 4th note placed under the 2nd one. For the counters, it may be intended that they count the first level only, but then nothing on the page tells how much analyst data the event really has.
- **Likely cause**:
  - Deep notes: `AnalystData::fetchChildNotesAndOpinions()` (`app/Model/AnalystData.php`) loads nested notes with `$depth = 2` and only sets `_max_depth_reached` when there are more; the old UI uses this flag to offer loading the rest (`View/Elements/genericElements/Analyst_data/thread.ctp`), but the Overmind thread ignores it.
  - Counters: the Overmind thread (`app/View/Themed/Overmind/Elements/AnalystData/thread.ctp`) prints `count($notes)` and `count($opinions)`, which only count the items directly attached to the event.

### Bug 22 – The "Full sightings list" button of the event page reloads the same page

<a id="bug-22"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce

1. Create an event with **Add Event** (with or without sightings).
2. On the event page, find the **Sightings** card ("No sightings" when there is none).
3. Click its button (external link icon, title **Full sightings list**).

- **Expected result**: The full list of the sightings of the event opens.
- **Actual result**: The same event page is reloaded.
- **Notes**: **Confirmed in the UI** (real browser, Overmind, 2026-10-01): the button has `href=""` and clicking it reloads `/events/view2/<id>`. It happens with and without sightings. No other card of the event page has an empty link.
- **Likely cause**: In `app/View/Themed/Overmind/Elements/Events/View/event_sightings.ctp` the button is written `<a href="" … title="Full sightings list">`: the link target was never filled in.

### Bug 23 – Adding a sighting from the UI fails (sighting buttons and Advanced sightings)

<a id="bug-23"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce

1. Create an event with **Add Event** and add an attribute `ip-dst` `198.51.100.230`.
2. In the Attributes tab, click the green thumbs-up button **Add sighting** of the attribute.
3. Click the red thumbs-down button **Mark as false positive** of the attribute.
4. Click the button **Advanced sightings** of the attribute and, in the panel, click **Add** (with or without filling the fields).

- **Expected result**: A sighting (then a false positive, then the advanced sighting) is added and the counters go up; with empty fields the panel either uses the default values or says which field is missing.
- **Actual result**:
  - The two thumb buttons show "Failed to add sighting" and nothing is added.
  - The **Advanced sightings** panel shows an error 400 with only `{}` as message.
- **Notes**: **Confirmed in the UI** (real browser and tester, Overmind, 2026-10-01). It is not a configuration problem: no sighting setting is changed on the instance (defaults), and adding sightings through the API works. Every request `POST /sightings/add/<attribute id>` answers HTTP 400 "The request has been black-holed"; error.log says `Blackhole exception when accessing /sightings/add/<id> (isRest: 1, action: add, unlockedActions: []): '_Token' was not found in request data.` (for the buttons and for the panel). Same mechanism as Bug 16 (correlation icon).
- **Likely cause**: The buttons and the panel (`app/View/Themed/Overmind/Sightings/ajax/advanced.ctp`) send the POST from JavaScript without the CakePHP form token (`_Token`), and `add` is not in the unlocked actions of `SightingsController`, so the Security component black-holes the request. The panel then prints `JSON.stringify(data.errors || {})`, and as the answer has no `errors` field the user only sees `{}`.

### Bug 24 – Object relationships list: "Remove Highlight" is never offered for selected rows

<a id="bug-24"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce

1. Go to the Object relationships list (`/object_relationships/index`).
2. Highlight one relationship (e.g. `shares`) with its **Highlight** action.
3. Tick the checkbox of this highlighted relationship.

- **Expected result**: The selection bar offers **Remove Highlight** (and **Highlight** only for rows that are not highlighted).
- **Actual result**: The selection bar only offers **Highlight**, whatever rows are ticked; the highlight cannot be removed for several rows at once.
- **Notes**: **Confirmed in the UI** (real browser, Overmind, 2026-10-01): with the highlighted relationship `shares` ticked, with a normal one ticked, and with both, only **Highlight** is shown. The checkboxes of this list have no `data-highlight` attribute. **Also affects:** probably the Taxonomies list (`/taxonomies/index`), which has the same configuration (found in the code, not checked in the UI: no taxonomy is highlighted on the test instance).
- **Likely cause**: In `app/View/Themed/Overmind/ObjectRelationships/index.ctp`, `'highlight_path' => 'highlighted'` is set on the **Actions** column, not on the `checkbox` column. The checkbox element (`genericElementsBS5/IndexTable/Fields/checkbox.ctp`) only writes `data-highlight` when its own field has `highlight_path`, so `updateMultiSelectToolbar()` in `mispOvermind.js` never sees a highlighted row and keeps **Remove Highlight** hidden.

### Bug 25 – No length limit on form fields and searches: internal error or 414

<a id="bug-25"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce

1. Go to `/correlation_exclusions/add`, paste a text of 70,000 characters in the value field and save.
2. Go to the Events list (`/events/index`), paste a text of 20,000 characters in **Search by info, ID or UUID** and press Enter.

- **Expected result**: The form refuses the too long text with a message (or the field does not accept more characters), and the search box limits the length or shows a message.
- **Actual result**:
  - Step 1: error page "An Internal Error Has Occurred." - nothing saved.
  - Step 2: the search fails with **414 Request-URI Too Large** from nginx (the page shows nothing, or the nginx 414 page).
- **Notes**: **Confirmed in the UI** (real browser and tester, Overmind, 2026-10-01) for the correlation exclusion value and the Events list search. Checked in the browser: on 17 add forms, almost no text field has a `maxlength` (only the tag collection name, 255, and the warninglist name, 60), and the search boxes have none. **Also affects** (70,000 characters sent through the same routes as the forms, each gives HTTP 500; no partial row is left): attribute comment, object comment, event report name, tag collection description, galaxy name and description, organisation name and description, sharing group name, warninglist description, feed name, role name, event blocklist comment, object relationship name and description. Not affected: attribute value (refused with a message); tag name (cut, see Bug 8); Event Info is Bug 3.
- **Likely cause**: The database runs in strict mode (`STRICT_TRANS_TABLES`), so a value longer than its column is rejected with a PDOException, which MISP shows as an internal error. The models only check that the fields are not empty, and the Overmind forms and search boxes have no `maxlength`; the search text is put in the URL, so a very long search goes over the nginx URL limit.

### Bug 26 – A refused form opens an unstyled page (no CSS, no menu)

<a id="bug-26"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce

1. Go to the Allowedlist page (`/admin/allowedlists/index`) and click **Add**.
2. Type an invalid expression, e.g. `e.e.e.e` (no delimiters), in **Expression**.
3. Click **Add Entry**.

- **Expected result**: The form stays in the Overmind page (or its window) and says why the expression is refused.
- **Actual result**: The browser goes to `/admin/allowedlists/add`, a raw page without any style and without the MISP menu, showing the empty form again; no clear message tells what is wrong.
- **Notes**: **Confirmed in the UI** (real browser and tester screenshot, Overmind, 2026-10-01): the page has 0 stylesheets and no menu. A valid expression (e.g. `/qa-valid/`) is saved and the next page is styled, so it only happens when the form is refused. **Also affects** (checked in the browser with a refused value, same raw page): **Add correlation exclusion** with an empty value (`/correlation_exclusions/add`), **Event blocklist** with an invalid UUID (`/event_blocklists/add`), **Add Tag** with a name already used (`/tags/add`), **Add Organisation** sent empty (`/admin/organisations/add`, also seen by a tester). The same code is in more than 20 controllers (e.g. Auth keys, Bookmarks, Collections, Correlation rules, Decaying models, Event reports, Galaxy clusters, Org blocklists), not checked one by one.
- **Likely cause**: In the Overmind theme these add/edit actions always set `$this->layout = false` (e.g. `AllowedlistsController::admin_add()` and `admin_edit()`), because the form is meant to be shown in a modal. When the form is refused, the answer to the normal form POST is the form rendered without layout, so the browser shows it as a full page without CSS, menu or flash message.

### Bug 27 – Add User: an empty form gives no message (it only appears after a reload)

<a id="bug-27"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

#### Steps to reproduce

1. Go to the Users list (`/admin/users/index`) and click **Add User**.
2. Leave every field empty and click **Create User**.
3. Reload the page.

- **Expected result**: After step 2, the window shows which required fields are missing (email, organisation, role…), and the browser marks the required fields.
- **Actual result**: After step 2 nothing visible happens: no message, no field marked. After the reload, the page shows "The user could not be saved. Invalid organisation."
- **Notes**: **Confirmed in the UI** (real browser and tester, Overmind, 2026-10-01). The form has 6 required fields (4 of them invalid for the browser), but the browser check is turned off and the request is still sent. The message seen after the reload only names the organisation, although the email and the other required fields are empty too.
- **Likely cause**: The form is built with `'novalidate' => true` (`app/View/Themed/Overmind/Users/admin_add.ctp`), so the browser does not stop the submit, and its script sends it with `fetch()` and re-renders the window with the returned form, which has no inline errors. `UsersController` reports the problem with `Flash->error()`, a session message that is only displayed on the next full page load.

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

### Recommendation 4 – Filter the Object relationships list by highlighted / not highlighted

<a id="recommendation-4"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

- **Current behaviour**: The Object relationships list (`/object_relationships/index`) has no filter on the **Highlighted** state; with 300+ relationships, the highlighted ones can only be found by sorting the column.
- **Proposal**: Add a **Highlighted** filter (highlighted / not highlighted) in **More filters**, like the **Enabled** or **Published** filters of other lists.
- **Benefit**: Admins can see and manage the highlighted relationships (the ones offered first in the object reference picker) in one click.

### Recommendation 5 – Show a newly created object relationship first

<a id="recommendation-5"></a>

**Environment:** MISP v2.5.48 (misp-docker) · Overmind UI theme

- **Current behaviour**: The Object relationships list is sorted by name (A to Z), so a relationship that was just created appears at its alphabetical place, e.g. on page 6 at the end of the list.
- **Proposal**: After creating a relationship, open it (or the list filtered on it), or offer a sort by creation date / ID with the newest first.
- **Benefit**: The user can check right away what was created, without browsing several pages.

# Missing Features (compared to the default UI)

1. Create a relationship between two objects within an event.
2. Group one or more orphan attributes to create an object.
3. Visual indication of existing analyst data.
   - **Notes**: Only tested with analyst data relationships.

