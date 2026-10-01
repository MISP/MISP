# MISP Web UI – Attribute View – Attributes Tab Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Attribute edit – invalid value](#attribute-edit-invalid) | |
| 2 | [Attribute edit – IDS flag](#attribute-edit-ids) | |
| 3 | [Attribute soft-delete and restore](#attribute-soft-delete-restore) | |
| 4 | [Attribute delete – correlation removed](#attribute-delete-correlation) | |
| 5 | [Attribute filter in an event](#attribute-filter-event) | |
| 6 | [Attribute correlation icon](#attribute-correlation-toggle) | |

---


# E2E Tests

### Attribute edit – invalid value
<a id="attribute-edit-invalid"></a>

Editing an attribute with an invalid value is refused and keeps the old value

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the event `QA attribute ip` (create it first with an `ip-dst` attribute `198.51.100.30` if it does not exist) and go to the Attributes tab.
4. Click **Edit** on `198.51.100.30`.
5. Change **Value** to `999.1.1.1`.
6. Click **Save Changes**.

**Expected:** the change is refused with "IP address has an invalid format." and the attribute still shows `198.51.100.30`.

### Attribute edit – IDS flag
<a id="attribute-edit-ids"></a>

Turning the IDS flag off on an attribute

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the event `QA attribute ip` (create it first with an `ip-dst` attribute `198.51.100.30` if it does not exist) and go to the Attributes tab.
4. Click **Edit** on `198.51.100.30`.
5. Untick **For IDS**.
6. Click **Save Changes**.

**Expected:** the attribute is shown with **IDS** off.

### Attribute soft-delete and restore
<a id="attribute-soft-delete-restore"></a>

A soft-deleted attribute can be restored

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA attribute restore` with **Add Event** and stay on its detail page.
4. Click **Add Attribute**.
5. In **Category** select `Network activity`, in **Type** select `ip-dst`, and type `198.51.100.50` in **Value**.
6. Click **Add Attribute** to save.
7. Click **Delete** on `198.51.100.50` and confirm the soft delete.
8. Show the deleted attributes and click **Restore** on `198.51.100.50`, then confirm.

**Expected:** after the delete the attribute is marked **Deleted**; after **Restore** it is active again.

### Attribute delete – correlation removed
<a id="attribute-delete-correlation"></a>

Deleting an attribute removes the correlation it created

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA delete correlation 1` with **Add Event** and stay on its detail page.
4. Click **Add Attribute**.
5. In **Category** select `Network activity`, in **Type** select `ip-dst`, and type `198.51.100.51` in **Value**.
6. Click **Add Attribute** to save.
7. Go to `/events/index`.
8. Create an event `QA delete correlation 2` with **Add Event** and stay on its detail page.
9. Click **Add Attribute**.
10. In **Category** select `Network activity`, in **Type** select `ip-dst`, and type `198.51.100.51` in **Value**.
11. Click **Add Attribute** to save.
12. Delete `198.51.100.51` permanently in `QA delete correlation 2`.

**Expected:** `QA delete correlation 1` does not list `QA delete correlation 2` in **Related Events** anymore.

### Attribute filter in an event
<a id="attribute-filter-event"></a>

Filtering the attributes of an event by value

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA attribute filter` with **Add Event** and stay on its detail page.
4. Click **Add Attribute**.
5. In **Category** select `Network activity`, in **Type** select `domain`, and type `qa-alpha.example` in **Value**.
6. Click **Add Attribute** to save.
7. Click **Add Attribute**.
8. In **Category** select `Network activity`, in **Type** select `domain`, and type `qa-beta.example` in **Value**.
9. Click **Add Attribute** to save.
10. Type `alpha` in the attribute filter of the Attributes tab.

**Expected:** only `qa-alpha.example` is shown; clearing the filter shows both again.

### Attribute correlation icon
<a id="attribute-correlation-toggle"></a>

The correlation icon disables and enables the correlation of an attribute (regression test for Bug 16)

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA correlation toggle` with **Add Event** and add an attribute `ip-dst` `198.51.100.181`.
4. In the Attributes tab, click the correlation icon (`chain-link`) of `198.51.100.181` and choose **Disable correlation**.
5. Click the icon again and choose **Enable correlation**.

**Expected:** after step 4 the message "Correlation disabled" is shown and the icon turns grey; after step 5 "Correlation enabled" is shown; no `error: undefined` message.

**Seeded data:** No data needed. Reproduced in a browser as `org-admin`: the request `POST /attributes/toggleCorrelation/<id>` answered HTTP 400 "The request has been black-holed" (see Bug 16).
