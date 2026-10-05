# MISP Web UI – Use Case – Report and Attribution Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Use case 7 – Write the report and the attribution](#use-case-report-attribution) | |

---


# E2E Tests

### Use case 7 – Write the report and the attribution
<a id="use-case-report-attribution"></a>

The analyst writes the incident report for management, attributes the campaign to a threat actor, and the team lead reviews it with a note and an opinion. Story: *Operation Fake-Parcel*, a fictional phishing campaign that sends fake parcel-delivery emails. All data is fictional and harmless (documentation IP ranges, `.example` domains).

- **Role:** `org-admin` of the organisation `ADMIN` (analyst), then `site-admin` (team lead)
- **Test data (before):** event `Fake-Parcel report {timestamp}` with `parcel-tracking.example` (`domain`) and `203.0.113.45` (`ip-dst`), created through the API
- **Cleanup (after):** delete the event
- **Known bugs on the way:** Bug 10 (after saving the report the old event page may open), Bug 12 (an empty note is accepted), Bug 16 (deep notes are not shown)

**Phase 1 – Write the report (as `org-admin`)**

1. Open the event page of `Fake-Parcel report {timestamp}` and the **tab** "Reports".
2. Click the **button** "Add Event Report".
3. Type `Fake-Parcel – incident report` as name and, in **Content**, the Markdown text:
   `# Summary` / `Fake parcel emails lead to parcel-tracking.example (203.0.113.45).` / `## Actions` / `- Blocked on the proxy`
4. Save the report.
5. Check that the report shows the title "Summary" formatted as a heading and the list "Blocked on the proxy".

**Phase 2 – Attribute the campaign**

6. Click the **button** "Edit Galaxy Clusters", search a threat actor cluster (e.g. `APT28`, used here only for the exercise), choose it and save.
7. Check that the threat actor is shown in the galaxies of the event.

**Phase 3 – Review by the team lead (as `site-admin`)**

8. Log out and log in as `site-admin`.
9. Open the event, click **Add note**, type `Attribution based on infrastructure only, to be confirmed` and click the **button** "Create Note".
10. Click **Add opinion**, choose **Neutral**, type `Not enough evidence yet` and save.
11. Check that the note and the opinion are listed under **Analyst data** with the author `site-admin`.

**Expected:**
- The event has the report `Fake-Parcel – incident report` with a formatted heading and list.
- The event has the threat actor cluster chosen in step 6.
- The event has **1** note and **1** opinion (Neutral) from the team lead.
