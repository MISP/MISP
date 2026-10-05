# MISP Web UI – User Workflows – Collaboration Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Propose a change and accept it](#wf-proposal-accept) | |
| 2 | [Propose a change and discard it](#wf-proposal-discard) | |
| 3 | [Propose a new attribute](#wf-proposal-new-attribute) | |

---


# E2E Tests

### Propose a change and accept it
<a id="wf-proposal-accept"></a>

A partner proposes a correction and the event owner accepts it

- **Role:** `user` of the organisation `QA-Org-B`, then `org-admin` of the organisation `ADMIN`
- **Test data (before):** event `QA wf proposal {timestamp}` of `ADMIN` (distribution **This community only**) with the attribute `203.0.113.90` (`ip-dst`), created through the API
- **Cleanup (after):** delete the event

1. As `user` of `QA-Org-B`, open the event page of `QA wf proposal {timestamp}` and the **tab** "Attributes".
2. Open the **⋮** menu of `203.0.113.90` and click the **menu item** "Propose change".
3. In the **Propose a change** window, change the **textbox** "Value" to `203.0.113.91` and click the **button** "Submit proposal".
4. Check that the event still shows `203.0.113.90`.
5. Log out and log in as `org-admin` of `ADMIN`.
6. Open `/shadow_attributes/index/all:0` and check that the proposal `203.0.113.91` from `QA-Org-B` is listed.
7. Open the event page of `QA wf proposal {timestamp}`, click the **button** "Accept" on the proposal and confirm.

**Expected:**
- The attribute now shows `203.0.113.91`.
- `203.0.113.90` is no longer shown.
- No proposal is left for the event in `/shadow_attributes/index/all:0`.

### Propose a change and discard it
<a id="wf-proposal-discard"></a>

A partner proposes a wrong value and the event owner refuses it

- **Role:** `user` of the organisation `QA-Org-B`, then `org-admin` of the organisation `ADMIN`
- **Test data (before):** event `QA wf proposal discard {timestamp}` of `ADMIN` (distribution **This community only**) with the attribute `203.0.113.92` (`ip-dst`), created through the API
- **Cleanup (after):** delete the event

1. As `user` of `QA-Org-B`, open the event page of `QA wf proposal discard {timestamp}` and the **tab** "Attributes".
2. Open the **⋮** menu of `203.0.113.92`, click the **menu item** "Propose change", change the value to `203.0.113.93` and click the **button** "Submit proposal".
3. Log out and log in as `org-admin` of `ADMIN`.
4. Open the event page of `QA wf proposal discard {timestamp}`, click the **button** "Discard" on the proposal and confirm.

**Expected:**
- The text "Proposal discarded." is visible.
- The attribute still shows `203.0.113.92`.
- No proposal is left for the event.

### Propose a new attribute
<a id="wf-proposal-new-attribute"></a>

A partner proposes an attribute that the event does not have yet

- **Role:** `user` of the organisation `QA-Org-B`, then `org-admin` of the organisation `ADMIN`
- **Test data (before):** event `QA wf proposal new {timestamp}` of `ADMIN` (distribution **This community only**), created through the API
- **Cleanup (after):** delete the event

1. As `user` of `QA-Org-B`, open the event page of `QA wf proposal new {timestamp}`.
2. Check that the **button** "Add attribute" proposes the attribute instead of adding it (the window title or button says proposal).
3. Choose `Network activity` / `domain`, type `qa-wf-proposed.example` in the **textbox** "Value" and submit the proposal.
4. Check that the **tab** "Attributes" does **not** show `qa-wf-proposed.example` as a normal attribute.
5. Log out and log in as `org-admin` of `ADMIN`, open the event and click the **button** "Accept" on the proposal.

**Expected:**
- After step 4 the value is only a proposal.
- After step 5 `qa-wf-proposed.example` is a normal attribute of the event.
