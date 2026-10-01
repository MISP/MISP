# MISP Web UI – Object View – Objects Tab Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Object edit – change a value](#object-edit-value) | |
| 2 | [Object edit – remove the required attributes](#object-edit-remove-required) | |
| 3 | [Object soft-delete](#object-soft-delete) | |
| 4 | [Object permanent delete](#object-hard-delete) | |
| 5 | [Object delete – several selected](#object-delete-selected) | |
| 6 | [Object filter](#object-filter) | |
| 7 | [Object correlation between events](#object-correlation) | |
| 8 | [Object edit – add a new attribute](#object-edit-add-attribute) | |
| 9 | [Object card – attribute menu](#object-card-attribute-menu) | |

---


# E2E Tests

### Object edit – change a value
<a id="object-edit-value"></a>

Changing an attribute value of an object

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the event `QA object domain-ip` (create it first with a `domain-ip` object `qa-test.example` / `198.51.100.20` if it does not exist) and go to the **Objects** tab.
4. Click **Edit object** on the `domain-ip` object.
5. Change **ip** to `198.51.100.21`.
6. Click **Review**, then **Submit**.

**Expected:** the object shows `198.51.100.21` and no longer `198.51.100.20`.

### Object edit – remove the required attributes
<a id="object-edit-remove-required"></a>

Removing all "required one of" attributes when editing an object is refused

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the event `QA object domain-ip` (create it first with a `domain-ip` object `qa-test.example` / `198.51.100.20` if it does not exist) and go to the **Objects** tab.
4. Click **Edit object** on the `domain-ip` object.
5. Empty **domain** and **ip**, and type `443` in **port**.
6. Click **Review**, then **Submit**.

**Expected:** the change is refused with a message that the object requires at least one of `ip`, `domain`, `hostname`, and the object keeps its old values.

### Object soft-delete
<a id="object-soft-delete"></a>

A soft-deleted object is marked as deleted and hidden from normal use

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA object soft delete` with **Add Event** and stay on its detail page.
4. Click **Add Object**, select the template `domain-ip` and click **Next**.
5. Type `qa-soft.example` in **domain**.
6. Click **Review**, then **Submit**.
7. Click **Delete** on the object, choose **Soft-delete** and confirm.

**Expected:** the message "Object soft-deleted." is shown and the object is marked **Deleted** (or hidden unless deleted items are shown).

### Object permanent delete
<a id="object-hard-delete"></a>

A permanently deleted object and its attributes are gone

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA object hard delete` with **Add Event** and stay on its detail page.
4. Click **Add Object**, select the template `domain-ip` and click **Next**.
5. Type `qa-hard.example` in **domain**.
6. Click **Review**, then **Submit**.
7. Click **Delete permanently** on the object and confirm.
8. Search `qa-hard.example` in the attribute search of the event.

**Expected:** the message "Object deleted permanently." is shown and `qa-hard.example` is not found anymore.

### Object delete – several selected
<a id="object-delete-selected"></a>

Deleting several selected objects at once

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA objects mass delete` with **Add Event** and stay on its detail page.
4. Click **Add Object**, select the template `domain-ip` and click **Next**.
5. Type `qa-mass1.example` in **domain**.
6. Click **Review**, then **Submit**.
7. Click **Add Object**, select the template `domain-ip` and click **Next**.
8. Type `qa-mass2.example` in **domain**.
9. Click **Review**, then **Submit**.
10. Tick **Select this object** on both objects.
11. Click **Delete selected objects**, choose **Permanently delete (cannot be undone)** and confirm.

**Expected:** the message "Objects deleted permanently." is shown and no object is left in the **Objects** tab.

### Object filter
<a id="object-filter"></a>

Filtering the objects of an event by value

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA object filter` with **Add Event** and stay on its detail page.
4. Click **Add Object**, select the template `domain-ip` and click **Next**.
5. Type `qa-alpha.example` in **domain**.
6. Click **Review**, then **Submit**.
7. Click **Add Object**, select the template `domain-ip` and click **Next**.
8. Type `qa-beta.example` in **domain**.
9. Click **Review**, then **Submit**.
10. Type `alpha` in **Filter objects…**.

**Expected:** only the object with `qa-alpha.example` is shown; clearing the filter shows both objects again.

### Object correlation between events
<a id="object-correlation"></a>

The same IP in objects of two events correlates the events

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA correlation 1` with **Add Event** and stay on its detail page.
4. Click **Add Object**, select the template `domain-ip` and click **Next**.
5. Type `198.51.100.99` in **ip**.
6. Click **Review**, then **Submit**.
7. Go to `/events/index`.
8. Create an event `QA correlation 2` with **Add Event** and stay on its detail page.
9. Click **Add Object**, select the template `domain-ip` and click **Next**.
10. Type `198.51.100.99` in **ip**.
11. Click **Review**, then **Submit**.

**Expected:** `QA correlation 2` lists `QA correlation 1` in **Related Events**, and the ip attribute shows a correlation.

### Object edit – add a new attribute
<a id="object-edit-add-attribute"></a>

Filling an empty field when editing an object adds the attribute (regression test for Bug 6)

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA object add attribute` with **Add Event** and stay on its detail page.
4. Click **Add Object**, select the template `domain-ip`, type `qa-object.example` in **domain**, then click **Review** and **Submit**.
5. In the **Objects** tab, click **Edit object** on this object.
6. Type `198.51.100.180` in **ip**.
7. Click **Review**, then **Submit**.

**Expected:** the object shows both `qa-object.example` and `198.51.100.180`.

### Object card – attribute menu
<a id="object-card-attribute-menu"></a>

The menu of an attribute in an object card is fully visible (regression test for Bug 22)

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA object menu` with **Add Event**, and add a `domain-ip` object with the domain `qa-menu.example`.
4. Go to the **Objects** tab and switch to card view.
5. Click the **⋮** button of the attribute `qa-menu.example`.

**Expected:** every entry of the menu is visible and clickable; the pagination bar does not cover it.
