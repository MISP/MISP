# MISP Web UI – Use Case – Partner Sharing Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Use case 3 – Share with a partner CERT](#use-case-partner-sharing) | |

---


# E2E Tests

### Use case 3 – Share with a partner CERT
<a id="use-case-partner-sharing"></a>

The CERT shares the campaign with a partner CERT only. The partner sees it, reports that it saw the IP, and proposes a new indicator that the CERT accepts. Story: *Operation Fake-Parcel*, a fictional phishing campaign that sends fake parcel-delivery emails. All data is fictional and harmless (documentation IP ranges, `.example` domains).

- **Role:** `org-admin` of the organisation `ADMIN`, then `user` of the organisation `QA-Org-B`, then `org-admin` of `ADMIN` again
- **Test data (before):** event `Fake-Parcel shared {timestamp}` (distribution **Your organisation only**) with the attribute `203.0.113.45` (`ip-dst`), created through the API
- **Cleanup (after):** delete the event and the sharing group `QA Fake-Parcel partners {timestamp}`
- **Known bugs on the way:** Bug 3 (sightings), Bug 5 (no emoji in the sharing group name)

**Phase 1 – Create the sharing group (as `org-admin` of `ADMIN`)**

1. Open `/sharing_groups/index` and click the **button** "Add Sharing Group".
2. Type `QA Fake-Parcel partners {timestamp}` in the **textbox** "Name" and `QA` in the **textbox** "Releasable to".
3. Add the organisations `ADMIN` and `QA-Org-B` and save.

**Phase 2 – Share the event**

4. Open the event page of `Fake-Parcel shared {timestamp}`, click the **button** "Edit Event".
5. Choose **Sharing group** in **Distribution**, choose `QA Fake-Parcel partners {timestamp}` in the **combobox** "Sharing Group" and click the **button** "Save Changes".
6. Click the **button** "Publish Event" and confirm.

**Phase 3 – The partner works on it (as `user` of `QA-Org-B`)**

7. Log out and log in as `user` of `QA-Org-B`.
8. Open `/events/index` and check that `Fake-Parcel shared {timestamp}` is listed.
9. Open it, and in the **tab** "Attributes" click the **button** "Add sighting" of `203.0.113.45`.
10. Open the **⋮** menu of `203.0.113.45`, click the **menu item** "Propose change", change the value to `203.0.113.47` and click the **button** "Submit proposal".
11. Check that the event still shows `203.0.113.45` (a proposal does not change the event).

**Phase 4 – The CERT reviews (as `org-admin` of `ADMIN`)**

12. Log out and log in as `org-admin` of `ADMIN`.
13. Open `/shadow_attributes/index/all:0` and check that the proposal `203.0.113.47` from `QA-Org-B` is listed.
14. Open the event, click the **button** "Accept" on the proposal and confirm.

**Expected:**
- `QA-Org-B` sees `Fake-Parcel shared {timestamp}`; an organisation outside the sharing group would not.
- `203.0.113.45` had **1** sighting from `QA-Org-B` before the proposal was accepted.
- After step 14 the attribute shows `203.0.113.47` and no proposal is left for the event.
