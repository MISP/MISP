# MISP Web UI – Sighting – Add Sightings Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Sighting – add](#sighting-add) | |
| 2 | [Sighting – false positive](#sighting-false-positive) | |
| 3 | [Sighting – by value in every event](#sighting-by-value) | |
| 4 | [Sighting – from another organisation](#sighting-other-org) | |
| 5 | [Sighting – date in the future](#sighting-future) | |
| 6 | [Sighting – delete](#sighting-delete) | |
| 7 | [Sightings card – full list button](#sighting-card-full-list) | |

---


# E2E Tests

### Sighting – add
<a id="sighting-add"></a>

Adding a sighting to an attribute (regression test for Bug 23)

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the event `QA correlation A` and go to the Attributes tab.
4. Click **Add sighting** on `198.51.100.160`.

**Expected:** the sighting count of the attribute goes up by one and the sighting is listed with your organisation and the current date.

**Seeded data:** `QA correlation A` with `198.51.100.160` (also in `QA correlation B`) and `198.51.100.161`. Through the API, a sighting on `198.51.100.160` was saved (HTTP 200).

### Sighting – false positive
<a id="sighting-false-positive"></a>

Adding a false-positive sighting (regression test for Bug 23)

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the event `QA correlation A` and go to the Attributes tab.
4. Click **Add false-positive sighting** on `198.51.100.160`.

**Expected:** the attribute shows one more **False positive**, separately from the normal sightings.

**Seeded data:** Through the API, a sighting of type 1 (false positive) was saved.

### Sighting – by value in every event
<a id="sighting-by-value"></a>

A sighting on a value is added to every attribute with that value

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Add a sighting for the value `198.51.100.160` (e.g. from the Attributes list `/attributes/index`, filtered on that value).
4. Open `QA correlation A` and `QA correlation B`.

**Expected:** both events show the new sighting on their `198.51.100.160` attribute.

**Seeded data:** Through the API, `/sightings/add` with only `value: 198.51.100.160` created one sighting on each of the two attributes.

### Sighting – from another organisation
<a id="sighting-other-org"></a>

A user of another organisation can add a sighting on a visible attribute

1. Log in to MISP as `user` of the organisation `QA-Org-B`.
2. Go to `/events/index`.
3. Open `QA correlation A` (distribution **This community only**) and click **Add sighting** on `198.51.100.160`.

**Expected:** the sighting is added and is shown as coming from `QA-Org-B`.

**Seeded data:** Through the API, `qa-user-b` added a sighting on this attribute (HTTP 200, org 2).

### Sighting – date in the future
<a id="sighting-future"></a>

A sighting dated in the future is refused

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the event `QA correlation A` and go to the Attributes tab.
4. Add a sighting on `198.51.100.161` with a date one year from today (e.g. through **Advanced sightings**).

**Expected:** the sighting is refused with a clear message, or saved with the current date; no sighting dated in the future is listed.

**Seeded data:** Through the API, a sighting on `198.51.100.161` with a timestamp one year ahead was saved with that future date (HTTP 200).

### Sighting – delete
<a id="sighting-delete"></a>

Deleting a sighting

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the event `QA correlation A` and go to the Attributes tab.
4. Open the sightings of `198.51.100.160`, click **Delete sighting** on one of them and confirm.

**Expected:** the sighting is removed and the count goes down by one.

### Sightings card – full list button
<a id="sighting-card-full-list"></a>

The button of the Sightings card opens the full list of sightings (regression test for Bug 22)

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA sightings card` with **Add Event**, add an attribute `ip-dst` `198.51.100.210` and click **Add sighting** on it.
4. On the event page, click the button **Full sightings list** (external link icon) of the **Sightings** card.

**Expected:** a page listing the sightings of `QA sightings card` opens (with the sighting on `198.51.100.210`); the event page is not just reloaded.
