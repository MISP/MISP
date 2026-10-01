# MISP Web UI – Event Template Builder Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Template builder – new template](#event-template-builder-add) | |
| 2 | [Template builder – no name](#event-template-builder-no-name) | |
| 3 | [Template builder – reorder elements](#event-template-builder-reorder) | |

---


# E2E Tests

### Template builder – new template
<a id="event-template-builder-add"></a>

Building a small template with one mandatory attribute field

1. Log in to MISP as `site-admin`.
2. Go to `/event_templates/index`.
3. Click **Add Event Template**.
4. Type `QA template` as name.
5. Click **Add Element**, choose **Attribute field**, set **Label** `QA IP`, **MISP type** `ip-dst`, and tick **Mandatory (user must fill this field)**.
6. Save the template.
7. Click **Preview the user form**.

**Expected:** the template is saved and the preview shows the field `QA IP` marked **Mandatory**.

### Template builder – no name
<a id="event-template-builder-no-name"></a>

Saving a template without a name is refused

1. Log in to MISP as `site-admin`.
2. Go to `/event_templates/index`.
3. Click **Add Event Template**.
4. Leave the name empty and save.

**Expected:** nothing is saved and "Could not save:" is shown with the reason.

### Template builder – reorder elements
<a id="event-template-builder-reorder"></a>

The order of the elements is kept after saving

1. Log in to MISP as `site-admin`.
2. Go to `/event_templates/index`.
3. Edit `QA template` (see "Template builder – new template").
4. Add a **Text block** element.
5. Drag the text block above `QA IP` (**Drag to reorder**) and save.
6. Open the template again.

**Expected:** the text block is still above `QA IP`.
