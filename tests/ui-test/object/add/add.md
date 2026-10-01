# MISP Web UI – Object Add – Form Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Object add – domain-ip](#object-add-domain-ip) | |
| 2 | [Object add – no attribute](#object-add-empty) | |
| 3 | [Object add – required one of missing](#object-add-required-one-of) | |
| 4 | [Object add – required attribute missing](#object-add-required) | |
| 5 | [Object add – invalid attribute value](#object-add-invalid-value) | |
| 6 | [Object add – first seen after last seen](#object-add-seen-order) | |
| 7 | [Object add – same object twice](#object-add-duplicate) | |
| 8 | [Object add – on a published event](#object-add-published-event) | |
| 9 | [Object add – review then submit](#object-add-review-submit) | |

---


# E2E Tests

### Object add – domain-ip
<a id="object-add-domain-ip"></a>

Adding a domain-ip object with a domain and an IP

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA object domain-ip` with **Add Event** and stay on its detail page.
4. Click **Add Object**, select the template `domain-ip` and click **Next**.
5. Type `qa-test.example` in **domain** and `198.51.100.20` in **ip**.
6. Click **Review**, then **Submit**.

**Expected:** the object is saved, the event opens on the **Objects** tab and the object shows both attributes `qa-test.example` and `198.51.100.20`.

### Object add – no attribute
<a id="object-add-empty"></a>

Submitting an object without any attribute is refused

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA object empty` with **Add Event** and stay on its detail page.
4. Click **Add Object**, select the template `domain-ip` and click **Next**.
5. Leave every field empty.
6. Click **Review**, then **Submit**.

**Expected:** the object is not saved and the message "Could not save the object as no attributes were set." is shown.

### Object add – required one of missing
<a id="object-add-required-one-of"></a>

An object without any of its "required one of" attributes is refused

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA object required one of` with **Add Event** and stay on its detail page.
4. Click **Add Object**, select the template `domain-ip` and click **Next**.
5. Fill only **port** with `443` (leave **domain**, **hostname** and **ip** empty).
6. Click **Review**, then **Submit**.

**Expected:** the object is not saved and the message says it requires at least one of `ip`, `domain`, `hostname`; the typed value `443` is still in the form.

### Object add – required attribute missing
<a id="object-add-required"></a>

An object without its required attribute is refused

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA object required` with **Add Event** and stay on its detail page.
4. Click **Add Object**, select the template `ai-dataset-component` and click **Next**.
5. Fill any field except **dataset-name**.
6. Click **Review**, then **Submit**.

**Expected:** the object is not saved and the message "Could not save the object as a required attribute is not set (dataset-name)" is shown.

### Object add – invalid attribute value
<a id="object-add-invalid-value"></a>

An object with a value that is not valid for its attribute type is refused

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA object invalid ip` with **Add Event** and stay on its detail page.
4. Click **Add Object**, select the template `domain-ip` and click **Next**.
5. Type `qa-test.example` in **domain** and `999.1.1.1` in **ip**.
6. Click **Review**, then **Submit**.

**Expected:** the object is not saved, the message names the **ip** attribute as invalid, and the form keeps the typed values.

### Object add – first seen after last seen
<a id="object-add-seen-order"></a>

An object whose First Seen is later than its Last Seen

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA object seen order` with **Add Event** and stay on its detail page.
4. Click **Add Object**, select the template `domain-ip` and click **Next**.
5. Type `qa-test.example` in **domain**.
6. Set **First Seen (UTC)** to `2026-10-01 12:00` and **Last Seen (UTC)** to `2026-01-01 12:00`.
7. Click **Review**, then **Submit**.

**Expected:** the object is refused with a clear message that First Seen must be before Last Seen; no error page is shown.

### Object add – same object twice
<a id="object-add-duplicate"></a>

Adding twice the same object to one event

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA object duplicate` with **Add Event** and stay on its detail page.
4. Click **Add Object**, select the template `domain-ip` and click **Next**.
5. Type `qa-dup.example` in **domain**.
6. Click **Review**, then **Submit**.
7. Click **Add Object**, select the template `domain-ip` and click **Next**.
8. Type `qa-dup.example` in **domain**.
9. Click **Review**, then **Submit**.

**Expected:** MISP either warns that the object already exists or saves a second object; the event page shows no error.

### Object add – on a published event
<a id="object-add-published-event"></a>

Adding an object to a published event unpublishes it

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA object published` with **Add Event** and stay on its detail page.
4. Click **Publish Event** and confirm.
5. Click **Add Object**, select the template `domain-ip` and click **Next**.
6. Type `qa-published.example` in **domain**.
7. Click **Review**, then **Submit**.

**Expected:** the object is saved and the event is now shown as Unpublished, so the change is not shared before a new publish.

### Object add – review then submit
<a id="object-add-review-submit"></a>

Submitting a new object after the Review step saves it without CSRF error (regression test for Bug 6)

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open any event.
4. Click **Add Object**, select the template `nova-rule` and click **Next**.
5. On the **Object** step, scroll to the bottom of the form.
6. Click **Review**, then **Submit**.

**Expected:** no "You have tripped the cross-site request forgery protection of MISP" page; the object is saved, or a clear message says which fields are missing.
