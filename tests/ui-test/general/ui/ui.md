# MISP Web UI – General – Interface Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Main pages – no JavaScript error](#general-ui-js-errors) | |
| 2 | [Main pages – phone width](#general-ui-mobile) | |
| 3 | [Main pages – dark mode](#general-ui-dark-mode) | |
| 4 | [Refused form – page keeps its style](#general-ui-refused-form) | |
| 5 | [Documentation pages open](#general-ui-doc-pages) | |

---


# E2E Tests

### Main pages – no JavaScript error
<a id="general-ui-js-errors"></a>

The main pages open without JavaScript errors in the browser console

1. Log in to MISP as `org-admin` of the organisation `ADMIN`.
2. Go to `/events/index`.
3. Open the browser console (F12).
4. Open one after the other: `/events/index`, an event page with many attributes, an event page with proposals, `/attributes/index`, `/galaxies/index`, `/tags/index`, `/taxonomies/index`, `/objectTemplates/index`, `/warninglists/index`, `/event_templates/index`, `/shadow_attributes/index/all:0`, `/users/view/me`, `/events/add`.

**Expected:** no red error appears in the console on any of these pages.

**Seeded data:** No data needed. Checked with a headless Chromium (Playwright) on 2026-10-01: no JavaScript error and no console error on these 13 pages.

### Main pages – phone width
<a id="general-ui-mobile"></a>

The main pages fit the screen of a phone

1. Log in to MISP as `org-admin` of the organisation `ADMIN`.
2. Go to `/events/index`.
3. Set the browser to a phone size (375 × 812 px, e.g. with the device toolbar of the developer tools).
4. Open one after the other: `/events/index`, an event page with many attributes, an event page with proposals, `/attributes/index`, `/galaxies/index`, `/tags/index`, `/taxonomies/index`, `/objectTemplates/index`, `/warninglists/index`, `/event_templates/index`, `/shadow_attributes/index/all:0`, `/users/view/me`, `/events/add`.

**Expected:** no page needs a horizontal scroll; menus and buttons stay reachable.

**Seeded data:** No data needed. Checked at 375 px width (Playwright): no horizontal overflow on these 13 pages. Whether menus and buttons are easy to use with a finger is still to check by hand.

### Main pages – dark mode
<a id="general-ui-dark-mode"></a>

Dark mode is applied on every main page

1. Log in to MISP as `org-admin` of the organisation `ADMIN`.
2. Turn on the dark mode.
3. Open one after the other: `/events/index`, an event page with many attributes, an event page with proposals, `/attributes/index`, `/galaxies/index`, `/tags/index`, `/taxonomies/index`, `/objectTemplates/index`, `/warninglists/index`, `/event_templates/index`, `/shadow_attributes/index/all:0`, `/users/view/me`, `/events/add`.

**Expected:** every page is dark (dark background, readable text), with no white block left.

**Seeded data:** No data needed. Checked with Playwright (dark mode stored in the browser): every page has the dark theme and a dark background (`rgb(33, 37, 41)`); white blocks inside the pages are still to check by eye.

### Refused form – page keeps its style
<a id="general-ui-refused-form"></a>

When a form is refused, the user stays on a styled page with the reason (regression test for Bug 26)

1. Log in to MISP as `site-admin`.
2. Go to `/admin/allowedlists/index`.
3. Click **Add**, type `e.e.e.e` in **Expression** and click **Add Entry**.
4. Go to `/correlation_exclusions/index`, click **Add Exclusion**, leave the value empty and save.
5. Go to `/tags/index`, click **Add Tag**, type `tlp:green` (already used) in **Tag Name** and click **Add Tag**.
6. Go to `/organisations/index`, click **Add Organisation**, leave every field empty and click **Add organisation**.

**Expected:** after each refused form, the page keeps the Overmind style and menu (or the window stays open) and a message explains why it was refused.

### Documentation pages open
<a id="general-ui-doc-pages"></a>

The documentation pages of the Resources menu open without error (regression test for Bug 28)

1. Log in to MISP as `user` of the organisation `ADMIN`.
2. Go to `/events/index`.
3. In the **Resources** menu, open the categories and types documentation (`/pages/display/doc/categories_and_types`).
4. Click the link to its Markdown version (`/pages/display/doc/md/categories_and_types`).

**Expected:** both pages show the documentation; no "An Internal Error Has Occurred." page.

**Seeded data:** No data needed. Checked in a browser on 2026-10-01: both URLs, and every other `/pages/display/…` URL tried, answer HTTP 500.
