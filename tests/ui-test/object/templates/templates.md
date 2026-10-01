# MISP Web UI – Object Templates Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Object template deactivate](#object-template-deactivate) | |
| 2 | [Object template deactivated – object already used](#object-template-deactivated-used) | |
| 3 | [Object templates update](#object-template-update) | |
| 4 | [Object template search in Add Object](#object-template-search) | |

---


# E2E Tests

### Object template deactivate
<a id="object-template-deactivate"></a>

A deactivated template is not offered when adding an object

1. Log in to MISP as `site-admin`.
2. Go to `/objectTemplates/index`.
3. Search for `geolocation` and click **Deactivate** on it.
4. Go to `/events/index`, open any event and click **Add Object**.
5. Search for `geolocation` in the template list.
6. Go back to `/objectTemplates/index` and click **Activate** on `geolocation`.

**Expected:** while deactivated, `geolocation` is not offered in the **Add Object** template list.

### Object template deactivated – object already used
<a id="object-template-deactivated-used"></a>

Deactivating a template does not break the objects already created with it

1. Log in to MISP as `site-admin`.
2. Go to `/objectTemplates/index`.
3. Go to `/events/index`.
4. Create an event `QA template deactivated` with **Add Event** and stay on its detail page.
5. Click **Add Object**, select the template `geolocation` and click **Next**.
6. Type `Luxembourg` in **city**.
7. Click **Review**, then **Submit**.
8. Go to `/objectTemplates/index` and click **Deactivate** on `geolocation`.
9. Open `QA template deactivated` again and go to the **Objects** tab.
10. Go back to `/objectTemplates/index` and click **Activate** on `geolocation`.

**Expected:** the event still shows the `geolocation` object with `Luxembourg`, without error.

### Object templates update
<a id="object-template-update"></a>

Updating the object templates keeps their active state

1. Log in to MISP as `site-admin`.
2. Go to `/objectTemplates/index`.
3. Note that `geolocation` is **Active**.
4. Click **Update Object** and wait for the end.
5. Reload the page.

**Expected:** a success message is shown, the number of templates does not drop, and `geolocation` is still **Active**.

### Object template search in Add Object
<a id="object-template-search"></a>

Finding a template by part of its name when adding an object

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA template search` with **Add Event** and stay on its detail page.
4. Click **Add Object**.
5. Type `domain` in the template search of **-- Select a template --**.

**Expected:** `domain-ip` is offered in the results and can be selected.
