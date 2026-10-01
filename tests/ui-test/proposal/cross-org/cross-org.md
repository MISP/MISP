# MISP Web UI – Proposal Cross-Organisation Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Proposal – from another organisation](#proposal-cross-org-create) | |
| 2 | [Proposal – listed for the event organisation](#proposal-cross-org-index) | |
| 3 | [Proposal – proposer cannot accept](#proposal-cross-org-self-accept) | |
| 4 | [Proposal – accepted by a user without publish right](#proposal-cross-org-accept-user) | |
| 5 | [Proposal – discard by the event organisation](#proposal-cross-org-discard) | |
| 6 | [Proposal – event not visible](#proposal-cross-org-not-visible) | |

---


# E2E Tests

### Proposal – from another organisation
<a id="proposal-cross-org-create"></a>

A user of another organisation proposes a change instead of editing

1. Log in to MISP as `user` of the organisation `QA-Org-B`.
2. Go to `/events/index`.
3. Open the event `QA roles community event`.
4. Click **Propose change** on `198.51.100.113`.
5. Change **Value** to `198.51.100.118` and click **Submit proposal**.

**Expected:** the proposal is saved and the event still shows `198.51.100.113`.

**Seeded data:** `QA roles community event` (#102, org `ADMIN`, distribution **This community only**, tag `qa:proposal-cross-org-create`). Through the API, `qa-user-b` created a value proposal and a new-attribute proposal (HTTP 200).

### Proposal – listed for the event organisation
<a id="proposal-cross-org-index"></a>

Proposals made by another organisation are listed for the event organisation only

1. Log in to MISP as `org-admin` of the organisation `ADMIN`.
2. Go to `/shadow_attributes/index/all:0`.
3. Look at the proposals listed.
4. Log out, log in as `user` of `QA-Org-B` and go to `/shadow_attributes/index/all:0`.

**Expected:** `org-admin` of `ADMIN` sees the proposals of `QA-Org-B` on `QA roles community event`; `user` of `QA-Org-B` sees none with `all:0`.

**Seeded data:** `QA roles community event` (#102, org `ADMIN`, distribution **This community only**, tag `qa:proposal-cross-org-index`). 3 pending proposals from `QA-Org-B`: value `198.51.100.117`, new domain `qa-proposed-by-b.example`, deletion of `198.51.100.113`. Through the API, `qa-orgadmin-a` saw 2 proposals and `qa-user-b` 0 (`all:0`).

### Proposal – proposer cannot accept
<a id="proposal-cross-org-self-accept"></a>

The user who made a proposal cannot accept it on another organisation's event

1. Log in to MISP as `user` of the organisation `QA-Org-B`.
2. Go to `/events/index`.
3. Open the event `QA roles community event`.
4. Look for **Accept** on the proposal `198.51.100.117`.
5. If it is shown, click it and confirm.

**Expected:** **Accept** is not offered, or it is refused with a clear message; the attribute does not change.

**Seeded data:** `QA roles community event` (#102, org `ADMIN`, distribution **This community only**, tag `qa:proposal-cross-org-self-accept`). Through the API, `qa-user-b` is refused: HTTP 405 "Proposal not found or you are not authorised to accept it."

### Proposal – accepted by a user without publish right
<a id="proposal-cross-org-accept-user"></a>

Who can accept a proposal: a `User` of the event organisation (no publish permission)

1. Log in to MISP as `user` of the organisation `ADMIN`.
2. Go to `/events/index`.
3. Open the event `QA roles community event`.
4. Click **Accept** on the proposal `198.51.100.117` and confirm.

**Expected:** the behaviour matches the rule chosen by MISP: the code comment says only publishing users of the event organisation can handle proposals, so either **Accept** is refused for `user`, or this rule is documented as wrong.

**Seeded data:** `QA roles community event` (#102, org `ADMIN`, distribution **This community only**, tag `qa:proposal-cross-org-accept-user`). Through the API, `qa-user-a` (role `User`, no publish permission) accepted a proposal of `QA-Org-B` (HTTP 200 "Proposed change accepted."), while the comment above `discard()` in `ShadowAttributesController.php` speaks of "publishing users".

### Proposal – discard by the event organisation
<a id="proposal-cross-org-discard"></a>

The event organisation discards a proposal of another organisation

1. Log in to MISP as `org-admin` of the organisation `ADMIN`.
2. Go to `/events/index`.
3. Open the event `QA roles community event`.
4. Click **Discard** on the proposal `qa-proposed-by-b.example` and confirm.

**Expected:** the message "Proposal discarded." is shown and `qa-proposed-by-b.example` is not added to the event.

**Seeded data:** `QA roles community event` (#102, org `ADMIN`, distribution **This community only**, tag `qa:proposal-cross-org-discard`). Through the API, `qa-orgadmin-a` discarded a proposal of `QA-Org-B` (HTTP 200 "Proposal discarded.").

### Proposal – event not visible
<a id="proposal-cross-org-not-visible"></a>

A user cannot propose on an event that is not shared with their organisation

1. Log in to MISP as `user` of the organisation `QA-Org-B`.
2. Go to `/events/index`.
3. Go to `/events/view2/103`.

**Expected:** the event is not found, so no proposal can be made.

**Seeded data:** `QA roles org only event` (#103, org `ADMIN`, distribution **Your organisation only**, tag `qa:proposal-cross-org-not-visible`). Through the API, a proposal from `qa-user-b` on its attribute is refused (HTTP 404 "Invalid Attribute.").
