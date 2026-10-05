# MISP Web UI – Use Case – Campaign Correlation Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Use case 2 – Discover a campaign](#use-case-campaign-correlation) | |

---


# E2E Tests

### Use case 2 – Discover a campaign
<a id="use-case-campaign-correlation"></a>

A week later a second fake parcel email arrives and reuses the same domain. MISP must link the two events on its own; the analyst links them explicitly and records that the domain was seen in the company logs. Story: *Operation Fake-Parcel*, a fictional phishing campaign that sends fake parcel-delivery emails. All data is fictional and harmless (documentation IP ranges, `.example` domains).

- **Role:** `org-admin` of the organisation `ADMIN`
- **Test data (before):** event `Fake-Parcel wave 1 {timestamp}` (published, distribution **This community only**) with the attributes `parcel-tracking.example` (`domain`) and `203.0.113.45` (`ip-dst`), created through the API
- **Cleanup (after):** delete the events `Fake-Parcel wave 1 {timestamp}` and `Fake-Parcel wave 2 {timestamp}`
- **Known bugs on the way:** Bug 3 (the **Add sighting** button may show "Failed to add sighting"; note it)

**Phase 1 – Record the second email**

1. Open `/events/index` and click the **button** "Add Event".
2. Type `Fake-Parcel wave 2 {timestamp}` in the **textbox** "Event Info", choose **This community only** in **Distribution** and click the **button** "Create Event Entry".
3. Open the **menu** "Populate from…", click the **menu item** "Freetext Import", paste `Redeliver your parcel: hxxp://parcel-tracking[.]example/redeliver from 203.0.113[.]46` and click the **button** "Run Freetext Import".
4. Click the **button** "Create attributes".

**Phase 2 – Let MISP correlate**

5. Open the **tab** "Correlation".
6. Check that `Fake-Parcel wave 1 {timestamp}` is listed as a related event.
7. Open the **tab** "Attributes" and check that `parcel-tracking.example` shows a correlation to `Fake-Parcel wave 1 {timestamp}`.

**Phase 3 – Link the two waves**

8. Click the **button** "Edit Event", type the ID of `Fake-Parcel wave 1 {timestamp}` in the **textbox** "Extends" and click the **button** "Save Changes".
9. Check that the event page says it extends `Fake-Parcel wave 1 {timestamp}`.

**Phase 4 – Record what was seen in the logs**

10. In the **tab** "Attributes", click the **button** "Add sighting" of `parcel-tracking.example`.
11. Check that the sighting counter of `parcel-tracking.example` shows **1**.

**Expected:**
- `Fake-Parcel wave 2 {timestamp}` lists `Fake-Parcel wave 1 {timestamp}` as a related event, through `parcel-tracking.example`.
- `Fake-Parcel wave 2 {timestamp}` extends `Fake-Parcel wave 1 {timestamp}`.
- `parcel-tracking.example` in wave 2 has **1** sighting from `ADMIN`.
