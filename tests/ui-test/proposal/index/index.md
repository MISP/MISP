# MISP Web UI – Proposal Index – Proposals List Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Proposals list – my organisation's events](#proposal-index-own-org) | |
| 2 | [Proposals list – search](#proposal-index-search) | |
| 3 | [Proposals list – View Event](#proposal-index-view-event) | |

---


# E2E Tests

### Proposals list – my organisation's events
<a id="proposal-index-own-org"></a>

`all:0` lists only the proposals made on events of my organisation

1. Log in to MISP as `site-admin`.
2. Go to `/shadow_attributes/index/all:0`.
3. Make sure there is a proposal on an event of your organisation (see "Proposal – change a value").
4. Note the proposals shown.
5. Go to `/shadow_attributes/index/all:1`.

**Expected:** `all:0` shows only proposals on events created by your organisation; `all:1` shows at least the same proposals.

### Proposals list – search
<a id="proposal-index-search"></a>

Searching the proposals by proposed value

1. Log in to MISP as `site-admin`.
2. Go to `/shadow_attributes/index/all:0`.
3. Type `198.51.100.71` in **Enter value to search**.
4. Press Enter.

**Expected:** only the proposal with **Proposed value** `198.51.100.71` is listed.

### Proposals list – View Event
<a id="proposal-index-view-event"></a>

The View Event action opens the event on the proposed attribute

1. Log in to MISP as `site-admin`.
2. Go to `/shadow_attributes/index/all:0`.
3. Click **View Event** on a proposal.

**Expected:** the event detail page opens at `/events/view2/<id>` and shows the attribute the proposal is about.
