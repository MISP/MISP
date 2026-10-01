# MISP Web UI – Analyst Data – Notes Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Note – add without text](#analyst-note-add-empty) | |
| 2 | [Note – edit to an empty text](#analyst-note-edit-empty) | |
| 3 | [Note – add with text](#analyst-note-add) | |

---


# E2E Tests

### Note – add without text
<a id="analyst-note-add-empty"></a>

A note without text is refused (regression test for Bug 20)

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA analyst note` with **Add Event** and stay on its detail page.
4. Open **Analyst data** and click **Add note**.
5. Leave **Note** empty and click **Create Note**.

**Expected:** no note is created and a message under **Note** says that it is required.

### Note – edit to an empty text
<a id="analyst-note-edit-empty"></a>

Removing the whole text of an existing note is refused (regression test for Bug 20)

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open `QA analyst note`, open **Analyst data** and add a note `QA note text` with **Add note** → **Create Note**.
4. Click **Edit** on this note, delete the whole text and save.

**Expected:** the change is refused with a message under **Note**, and the note still shows `QA note text`.

### Note – add with text
<a id="analyst-note-add"></a>

Adding a normal note to an event

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open `QA analyst note`, open **Analyst data** and click **Add note**.
4. Type `QA analyst note text` in **Note** and click **Create Note**.

**Expected:** the message "Note added." is shown and the note `QA analyst note text` is listed under **Analyst data** → **Notes** of the event.
