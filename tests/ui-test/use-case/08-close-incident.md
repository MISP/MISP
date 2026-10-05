# MISP Web UI – Use Case – Close Incident Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Use case 8 – Close the incident](#use-case-close-incident) | |

---


# E2E Tests

### Use case 8 – Close the incident
<a id="use-case-close-incident"></a>

The campaign is over. The analyst completes the analysis, removes an indicator that was wrong, republishes, and checks that the history keeps track of everything. Story: *Operation Fake-Parcel*, a fictional phishing campaign that sends fake parcel-delivery emails. All data is fictional and harmless (documentation IP ranges, `.example` domains).

- **Role:** `org-admin` of the organisation `ADMIN`
- **Test data (before):** published event `Fake-Parcel closing {timestamp}` (analysis **Ongoing**) with `parcel-tracking.example` (`domain`) and `203.0.113.99` (`ip-dst`, added by mistake), created through the API
- **Cleanup (after):** delete the event
- **Known bugs on the way:** Bug 9 (**Unpublish Event** may open the old event page)

**Phase 1 – Remove the wrong indicator**

1. Open the event page of `Fake-Parcel closing {timestamp}` and the **tab** "Attributes".
2. Delete `203.0.113.99` (soft delete) and confirm.
3. Click the **button** "Deleted" and check that `203.0.113.99` is listed as deleted.
4. Click **Restore** on `203.0.113.99`, confirm, then delete it again (soft delete).

**Phase 2 – Complete the analysis**

5. Click the **button** "Edit Event", choose **Completed** in **Analysis Level** and click the **button** "Save Changes".
6. Check that the event is now shown as **Unpublished** (an edit unpublishes it).
7. Click the **button** "Publish Event" and confirm.

**Phase 3 – Check the history**

8. Open the **tab** "History".
9. Check that the history lists the deletion of `203.0.113.99`, its restore, the analysis change and the publication.

**Expected:**
- The event is **Published** with the analysis **Completed**.
- `203.0.113.99` is deleted (only visible with **Deleted**) and `parcel-tracking.example` is still active.
- The **History** tab lists the delete, the restore, the edit and the publication.
