# MISP Web UI – Proposal Add – Propose a Change Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Proposal – change a value](#proposal-change-value) | |
| 2 | [Proposal – delete an attribute](#proposal-delete) | |
| 3 | [Proposal – invalid value](#proposal-invalid-value) | |
| 4 | [Proposal – no change](#proposal-no-change) | |
| 5 | [Proposal – emoji in the comment](#proposal-emoji-comment) | |

---


# E2E Tests

### Proposal – change a value
<a id="proposal-change-value"></a>

Proposing a new value for an attribute does not change the attribute before it is accepted

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA proposal value` with **Add Event**, then add an attribute `ip-dst` `198.51.100.70` (category `Network activity`) and stay on the Attributes tab.
4. Click **Propose change** on `198.51.100.70`.
5. Change **Value** to `198.51.100.71`.
6. Click **Submit proposal**.
7. Go to `/shadow_attributes/index/all:0`.

**Expected:** the message "The proposed Attribute has been saved" is shown, the event still shows `198.51.100.70`, and the Proposals list shows the proposal with **Proposed value** `198.51.100.71`.

### Proposal – delete an attribute
<a id="proposal-delete"></a>

Proposing the deletion of an attribute

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA proposal delete` with **Add Event**, then add an attribute `ip-dst` `198.51.100.72` (category `Network activity`) and stay on the Attributes tab.
4. Click **Propose change** on `198.51.100.72`.
5. Click **Propose deletion of this attribute**, then **Submit deletion proposal**.
6. Go to `/shadow_attributes/index/all:0`.

**Expected:** the attribute is still in the event, and the Proposals list shows a deletion request for `198.51.100.72`.

### Proposal – invalid value
<a id="proposal-invalid-value"></a>

Proposing a value that is not valid for the attribute type is refused with the reason

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA proposal invalid` with **Add Event**, then add an attribute `ip-dst` `198.51.100.73` (category `Network activity`) and stay on the Attributes tab.
4. Click **Propose change** on `198.51.100.73`.
5. Change **Value** to `999.1.1.1`.
6. Click **Submit proposal**.

**Expected:** the proposal is not saved, the message explains that the IP address has an invalid format (not only "The proposed Attribute could not be saved. Please, try again."), and the typed value is kept.

### Proposal – no change
<a id="proposal-no-change"></a>

Submitting a proposal without changing anything

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA proposal no change` with **Add Event**, then add an attribute `ip-dst` `198.51.100.74` (category `Network activity`) and stay on the Attributes tab.
4. Click **Propose change** on `198.51.100.74`.
5. Do not change any field.
6. Click **Submit proposal**.
7. Go to `/shadow_attributes/index/all:0`.

**Expected:** MISP refuses the empty proposal with a clear message, or saves it; it does not create several identical proposals and no error page is shown.

### Proposal – emoji in the comment
<a id="proposal-emoji-comment"></a>

A proposal with an emoji in its comment is saved without error (checks Bug 5 on proposals)

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA proposal emoji` with **Add Event**, then add an attribute `ip-dst` `198.51.100.75` (category `Network activity`) and stay on the Attributes tab.
4. Click **Propose change** on `198.51.100.75`.
5. Type `QA proposal 🚀` in **Contextual Comment**.
6. Click **Submit proposal**.

**Expected:** no "An Internal Error Has Occurred." page; the proposal is saved with its comment.
