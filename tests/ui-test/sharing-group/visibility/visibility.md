# MISP Web UI – Sharing Group – Visibility Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Event in a sharing group – not a member](#sg-event-not-member) | |
| 2 | [Event in a sharing group – member](#sg-event-member) | |
| 3 | [Sharing group – not a member cannot use it](#sg-use-not-member) | |
| 4 | [Sharing group – organisation removed](#sg-org-removed) | |

---


# E2E Tests

### Event in a sharing group – not a member
<a id="sg-event-not-member"></a>

An organisation that is not in the sharing group cannot see the event

1. Log in to MISP as `user` of the organisation `QA-Org-B`.
2. Go to `/events/index`.
3. Search the Events list for `QA SG event org A only`.
4. Go to `/events/view2/110`.

**Expected:** the event is not listed and its page shows "Invalid event".

**Seeded data:** `QA SG event org A only` (#110, distribution **Sharing group** `QA SG org A only` (#1, member `ADMIN`), tag `qa:sg-event-not-member`). Through the API, `qa-user-b` gets HTTP 404.

### Event in a sharing group – member
<a id="sg-event-member"></a>

A member organisation sees the event, but not an attribute restricted to another sharing group

1. Log in to MISP as `user` of the organisation `QA-Org-B`.
2. Go to `/events/index`.
3. Open `QA SG event org A and B`.

**Expected:** the event opens and shows `198.51.100.141`, but not `198.51.100.140` (that attribute is restricted to `QA SG org A only`).

**Seeded data:** `QA SG event org A and B` (#111, distribution `QA SG org A and B` (#2, members `ADMIN` and `QA-Org-B`), tag `qa:sg-event-member`) with `198.51.100.140` (attribute distribution `QA SG org A only`) and `198.51.100.141` (inherit). Through the API, `qa-user-b` sees only `198.51.100.141`.

### Sharing group – not a member cannot use it
<a id="sg-use-not-member"></a>

A user cannot create an event in a sharing group their organisation is not in

1. Log in to MISP as `user` of the organisation `QA-Org-B`.
2. Go to `/events/index`.
3. Click **Add Event**, choose **Sharing group** in **Distribution** and open the **Sharing Group** list.

**Expected:** `QA SG org A only` is not offered; only `QA SG org A and B` is.

**Seeded data:** Through the API, `qa-user-b` creating an event with `QA SG org A only` is refused: HTTP 405 "Invalid Sharing Group or not authorised."

### Sharing group – organisation removed
<a id="sg-org-removed"></a>

Removing an organisation from a sharing group removes its access at once

1. Log in to MISP as `site-admin`.
2. Go to `/sharing_groups/index`.
3. Open `QA SG org A and B`, remove `QA-Org-B` and save.
4. Log out, log in as `user` of `QA-Org-B` and go to `/events/view2/111`.
5. Log back in as `site-admin` and add `QA-Org-B` to `QA SG org A and B` again.

**Expected:** while `QA-Org-B` is removed, `/events/view2/111` shows "Invalid event".

**Seeded data:** Through the API: after removing `QA-Org-B` from `QA SG org A and B` (#2, members `ADMIN` and `QA-Org-B`), `qa-user-b` got HTTP 404 on #111; after adding it back, access came back.
