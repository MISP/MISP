# MISP Web UI – Proposal Review – Accept and Discard Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Proposal accept – value change](#proposal-accept-value) | |
| 2 | [Proposal accept – deletion](#proposal-accept-delete) | |
| 3 | [Proposal discard](#proposal-discard) | |
| 4 | [Proposal accept – twice](#proposal-accept-twice) | |
| 5 | [Proposal accept – attribute deleted meanwhile](#proposal-accept-attribute-deleted) | |
| 6 | [Proposal accept – several at once](#proposal-accept-all) | |

---


# E2E Tests

### Proposal accept – value change
<a id="proposal-accept-value"></a>

Accepting a proposed value updates the attribute

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA accept value` with **Add Event**, then add an attribute `ip-dst` `198.51.100.80` (category `Network activity`) and stay on the Attributes tab.
4. Click **Propose change** on `198.51.100.80`.
5. Change **Value** to `198.51.100.81`.
6. Click **Submit proposal**.
7. Click **Accept** on the proposal and confirm.

**Expected:** the attribute now shows `198.51.100.81`, the proposal is gone from `/shadow_attributes/index/all:0`, and the event is shown as Unpublished if it was published.

### Proposal accept – deletion
<a id="proposal-accept-delete"></a>

Accepting a deletion proposal deletes the attribute

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA accept delete` with **Add Event**, then add an attribute `ip-dst` `198.51.100.82` (category `Network activity`) and stay on the Attributes tab.
4. Click **Propose change** on `198.51.100.82`.
5. Click **Propose deletion of this attribute**, then **Submit deletion proposal**.
6. Click **Accept** on the proposal and confirm.

**Expected:** `198.51.100.82` is deleted from the event and the proposal is gone.

### Proposal discard
<a id="proposal-discard"></a>

Discarding a proposal keeps the attribute unchanged

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA discard` with **Add Event**, then add an attribute `ip-dst` `198.51.100.83` (category `Network activity`) and stay on the Attributes tab.
4. Click **Propose change** on `198.51.100.83`.
5. Change **Value** to `198.51.100.84`.
6. Click **Submit proposal**.
7. Click **Discard** on the proposal and confirm.

**Expected:** the message "Proposal discarded." is shown, the attribute still shows `198.51.100.83`, and the proposal is gone.

### Proposal accept – twice
<a id="proposal-accept-twice"></a>

Accepting a proposal that was already accepted in another tab

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA accept twice` with **Add Event**, then add an attribute `ip-dst` `198.51.100.85` (category `Network activity`) and stay on the Attributes tab.
4. Click **Propose change** on `198.51.100.85`.
5. Change **Value** to `198.51.100.86`.
6. Click **Submit proposal**.
7. Open the event in a second tab.
8. In the first tab, click **Accept** on the proposal and confirm.
9. In the second tab, click **Accept** on the same proposal and confirm.

**Expected:** the second tab shows a clear error that the proposal does not exist anymore, not a success message; the attribute shows `198.51.100.86` only once.

### Proposal accept – attribute deleted meanwhile
<a id="proposal-accept-attribute-deleted"></a>

Accepting a value proposal whose attribute was permanently deleted

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA accept deleted attribute` with **Add Event**, then add an attribute `ip-dst` `198.51.100.87` (category `Network activity`) and stay on the Attributes tab.
4. Click **Propose change** on `198.51.100.87`.
5. Change **Value** to `198.51.100.88`.
6. Click **Submit proposal**.
7. Delete the attribute `198.51.100.87` permanently.
8. Click **Accept** on the proposal and confirm.

**Expected:** a clear message says the attribute does not exist anymore; no error page, and no new attribute `198.51.100.88` without event appears.

### Proposal accept – several at once
<a id="proposal-accept-all"></a>

Accepting several proposals of an event at once

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA accept all` with **Add Event**, then add an attribute `ip-dst` `198.51.100.90` (category `Network activity`) and stay on the Attributes tab.
4. Add a second attribute `ip-dst` `198.51.100.91`.
5. Click **Propose change** on `198.51.100.90`.
6. Change **Value** to `198.51.100.92`.
7. Click **Submit proposal**.
8. Click **Propose change** on `198.51.100.91`.
9. Change **Value** to `198.51.100.93`.
10. Click **Submit proposal**.
11. Click **Accept all** and confirm.

**Expected:** both attributes are updated (`198.51.100.92` and `198.51.100.93`) and no proposal is left for the event.
