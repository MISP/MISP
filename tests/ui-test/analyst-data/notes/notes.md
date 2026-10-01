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
| 4 | [Note – four nested levels](#analyst-note-nested) | |
| 5 | [Analyst data – counters with nested items](#analyst-note-counter) | |

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

### Note – four nested levels
<a id="analyst-note-nested"></a>

Notes answered four levels deep are all shown (regression test for Bug 21)

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA nested notes` with **Add Event** and stay on its detail page.
4. Click **Add note**, type `QA level 1` and click **Create Note**.
5. In the menu of `QA level 1`, click **Add note**, type `QA level 2` and click **Create Note**.
6. Do the same on `QA level 2` with `QA level 3`, then on `QA level 3` with `QA level 4`.
7. Reload the page.

**Expected:** `QA level 1`, `QA level 2`, `QA level 3` and `QA level 4` are all shown, each one under the previous one (or a link shows the deeper notes).

**Seeded data:** `QA nested notes`, built through the UI on 2026-10-01: levels 1 to 4 saved with the right parents, but `QA level 4` is not shown on the event page.

### Analyst data – counters with nested items
<a id="analyst-note-counter"></a>

The Notes and Opinions counters reflect the nested notes (regression test for Bug 21)

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open `QA nested notes` (see "Note – four nested levels").
4. Click **Add opinion** twice to add two opinions to the event, then add a note `QA note on opinion` to one of them.
5. Look at the counters of the **Analyst data** block.

**Expected:** the counters show all the notes and opinions of the thread (notes under notes and under opinions included), or say that they count the first level only.

**Seeded data:** Checked on 2026-10-01: **NOTES (1)** with 4 nested notes; a tester saw **Opinions (2)** with notes nested inside the opinions.
