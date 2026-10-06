# MISP Web UI – Use Case – Phishing Triage Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Use case 1 – Triage a phishing email](#use-case-phishing-triage) | |

---


# E2E Tests

### Use case 1 – Triage a phishing email
<a id="use-case-phishing-triage"></a>

A colleague reports a fake parcel-delivery email. The analyst records it in MISP, extracts the indicators, classifies the event and publishes it. Story: *Operation Fake-Parcel*, a fictional phishing campaign that sends fake parcel-delivery emails. All data is fictional and harmless (documentation IP ranges, `.example` domains).

- **Role:** `org-admin` of the organisation `ADMIN`
- **Test data (before):** `None`
- **Cleanup (after):** delete the event `Fake-Parcel phishing {timestamp}`
- **Known bugs on the way:** Bug 4 (adding an object may show a CSRF error; if it happens, note it and continue with step 15)

**Phase 1 – Create the event**

1. Open `/events/index`.
2. Click the **button** "Add Event".
3. In the **Add Event** window, type `Fake-Parcel phishing {timestamp}` in the **textbox** "Event Info".
4. Choose **This community only** in **Distribution**.
5. Choose **Medium** in **Threat Level** and **Initial** in **Analysis Level**.
6. Click the **button** "Create Event Entry".
7. Check that the URL is `/events/view2/<id>` and that the title `Fake-Parcel phishing {timestamp}` is visible.

**Phase 2 – Record the email**

8. Click the **button** "Add object".
9. Type `email` in the **combobox** "Template", choose `email` and click the **button** "Next".
10. Type `delivery@parcel-tracking.example` in the **textbox** "from".
11. Type `Your parcel could not be delivered` in the **textbox** "subject".
12. Click the **button** "Review", then the **button** "Submit".
13. Open the **tab** "Objects".
14. Check that the object `email` shows `delivery@parcel-tracking.example` and `Your parcel could not be delivered`.

**Phase 3 – Extract the indicators from the email text**

15. Open the **menu** "Populate from…" and click the **menu item** "Freetext Import".
16. Paste this text in the **textbox** of the **Freetext Import** window:
    `Dear customer, track your parcel at hxxp://parcel-tracking[.]example/track?id=48213 . Our server 203.0.113[.]45 will keep it 48h.`
17. Click the **button** "Run Freetext Import".
18. Check that the list shows `http://parcel-tracking.example/track?id=48213` (type `url`) and `203.0.113.45` (type `ip-dst`). The bare `.example` domain is not offered as a `domain`: MISP only accepts known top-level domains.
19. Click the **button** "Create attributes".
20. Open the **tab** "Attributes" and check that the 2 values are listed.

**Phase 4 – Classify**

21. Click the **button** "Edit Tags", type `tlp:amber` in the **textbox** "Search tags to add…", choose `tlp:amber` under **Global Tags** and click the **button** "Save Tags".
22. Click the **button** "Edit Galaxy Clusters", search `Phishing`, choose the MITRE ATT&CK technique `Phishing - T1566` and save.
23. Check that `tlp:amber` and `Phishing - T1566` are shown on the event.

**Phase 5 – Publish**

24. Click the **button** "Publish Event" and confirm (leave **Send notification email** off).
25. Check that the event is shown as **Published**.

**Expected:**
- The event `Fake-Parcel phishing {timestamp}` exists with the distribution **This community only**, threat level **Medium**, and is **Published**.
- It contains the object `email` (from `delivery@parcel-tracking.example`, subject `Your parcel could not be delivered`).
- It contains the attributes `http://parcel-tracking.example/track?id=48213` (`url`) and `203.0.113.45` (`ip-dst`).
- It has the tag `tlp:amber` and the galaxy cluster `Phishing - T1566`.
- No "An Internal Error Has Occurred." or CSRF page is shown at any step.
