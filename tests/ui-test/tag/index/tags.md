# MISP Web UI – Tag Index – Tags Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Tag add – custom tag](#tag-add) | |
| 2 | [Tag add – empty name](#tag-add-empty) | |
| 3 | [Tag add – same name with other case](#tag-add-case-duplicate) | |
| 4 | [Tag add – name longer than 255 characters](#tag-add-too-long) | |
| 5 | [Tag add – invalid colour](#tag-add-invalid-colour) | |
| 6 | [Tag search with a colon](#tag-search-colon) | |
| 7 | [Tag rename – used on an event](#tag-rename-used) | |
| 8 | [Tag delete – used on an event](#tag-delete-used) | |
| 9 | [Tag hidden](#tag-hidden) | |
| 10 | [Tag not exportable](#tag-not-exportable) | |
| 11 | [Tag list – Not favourite filter](#tag-index-not-favourite) | |

---


# E2E Tests

### Tag add – custom tag
<a id="tag-add"></a>

Creating a custom tag and using it on an event

1. Log in to MISP as `site-admin`.
2. Go to `/tags/index`.
3. Click **Add Tag**, type `qa:custom` in **Tag Name** and click **Add Tag**.
4. Go to `/events/index`, create an event `QA custom tag` with **Add Event** and stay on its detail page.
5. Click **Edit Tags** and open **Custom Tags**.

**Expected:** `qa:custom` is in the Tags list and is offered in **Custom Tags**.

### Tag add – empty name
<a id="tag-add-empty"></a>

Creating a tag without a name is refused

1. Log in to MISP as `site-admin`.
2. Go to `/tags/index`.
3. Click **Add Tag**.
4. Leave **Tag Name** empty and click **Add Tag**.

**Expected:** the tag is not created and the message "Please provide a name for the tag." is shown.

### Tag add – same name with other case
<a id="tag-add-case-duplicate"></a>

A tag name that only differs by case is a duplicate

1. Log in to MISP as `site-admin`.
2. Go to `/tags/index`.
3. Click **Add Tag**, type `qa:case` in **Tag Name** and click **Add Tag**.
4. Click **Add Tag**, type `QA:CASE` in **Tag Name** and click **Add Tag**.

**Expected:** the second tag is refused with "A similar name already exists."; only one tag `qa:case` exists.

### Tag add – name longer than 255 characters
<a id="tag-add-too-long"></a>

A tag name longer than the database limit is refused, not cut (regression test for Bug 19)

1. Log in to MISP as `site-admin`.
2. Go to `/tags/index`.
3. Click **Add Tag**.
4. Paste a name of 300 characters starting with `qa:` in **Tag Name**.
5. Click **Add Tag**.

**Expected:** the tag is not created and a message says the name is too long; no tag with a cut name is created.

### Tag add – invalid colour
<a id="tag-add-invalid-colour"></a>

A tag with an invalid colour is refused

1. Log in to MISP as `site-admin`.
2. Go to `/tags/index`.
3. Click **Add Tag**.
4. Type `qa:colour` in **Tag Name** and `#12` in **Colour**.
5. Click **Add Tag**.

**Expected:** the tag is not created and a message says the colour is invalid.

### Tag search with a colon
<a id="tag-search-colon"></a>

Searching tags by a name that contains `:`

1. Log in to MISP as `site-admin`.
2. Go to `/tags/index`.
3. Type `tlp:` in **Search by tag name**.
4. Press Enter.

**Expected:** the `tlp:` tags (e.g. `tlp:green`, `tlp:red`) are listed.

### Tag rename – used on an event
<a id="tag-rename-used"></a>

Renaming a tag that is attached to an event

1. Log in to MISP as `site-admin`.
2. Go to `/tags/index`.
3. Click **Add Tag**, type `qa:old-name` in **Tag Name** and click **Add Tag**.
4. Go to `/events/index`, create an event `QA tag rename` with **Add Event** and stay on its detail page.
5. Click **Edit Tags**, search `qa:old-name` in **Search tags to add…**, add it under **Global Tags** and click **Save Tags**.
6. Go to `/tags/index`, click **Edit** on `qa:old-name`, change **Tag Name** to `qa:new-name` and click **Save Changes**.
7. Open `QA tag rename` again.

**Expected:** the event shows the tag `qa:new-name`, without duplicate and without error.

### Tag delete – used on an event
<a id="tag-delete-used"></a>

Deleting a tag that is attached to an event

1. Log in to MISP as `site-admin`.
2. Go to `/tags/index`.
3. Click **Add Tag**, type `qa:to-delete` in **Tag Name** and click **Add Tag**.
4. Go to `/events/index`, create an event `QA tag delete` with **Add Event** and stay on its detail page.
5. Click **Edit Tags**, search `qa:to-delete` in **Search tags to add…**, add it under **Global Tags** and click **Save Tags**.
6. Go to `/tags/index`, click **Delete** on `qa:to-delete` and confirm.
7. Open `QA tag delete` again.

**Expected:** the event opens without error and no longer shows `qa:to-delete`.

### Tag hidden
<a id="tag-hidden"></a>

A hidden tag is not offered in the tag pickers

1. Log in to MISP as `site-admin`.
2. Go to `/tags/index`.
3. Click **Add Tag**, type `qa:hidden` in **Tag Name** and tick **Hidden** and click **Add Tag**.
4. Go to `/events/index`, create an event `QA hidden tag` with **Add Event** and stay on its detail page.
5. Click **Edit Tags** and search `qa:hidden`.

**Expected:** `qa:hidden` is not offered in **Edit Tags**.

### Tag not exportable
<a id="tag-not-exportable"></a>

A tag that is not exportable is left out of the event export

1. Log in to MISP as `site-admin`.
2. Go to `/tags/index`.
3. Click **Add Tag**, type `qa:no-export` in **Tag Name** and untick **Exportable** and click **Add Tag**.
4. Go to `/events/index`, create an event `QA not exportable` with **Add Event** and stay on its detail page.
5. Click **Edit Tags**, search `qa:no-export` in **Search tags to add…**, add it under **Global Tags** and click **Save Tags**.
6. Note the event ID and go to `/events/view/<id>.json`.

**Expected:** the event page shows `qa:no-export`, but the JSON export does not contain it.

### Tag list – Not favourite filter
<a id="tag-index-not-favourite"></a>

The "Not favourite" filter hides the favourite tags (regression test for Bug 20)

1. Log in to MISP as `site-admin`.
2. Go to `/tags/index`.
3. Mark the tag `tlp:green` as **Favourite**.
4. Click **More filters**, in **Favourite** select **Not favourite** and apply.
5. In **Favourite**, select **Favourite only** and apply.

**Expected:** with **Not favourite**, `tlp:green` is not listed; with **Favourite only**, only `tlp:green` is listed.
