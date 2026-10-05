# MISP Web UI – Use Case – False Positive Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Use case 5 – Handle a false positive](#use-case-false-positive) | |

---


# E2E Tests

### Use case 5 – Handle a false positive
<a id="use-case-false-positive"></a>

While importing indicators, a public DNS server (`8.8.8.8`) was added by mistake. MISP must warn about it; the analyst marks it as a false positive and makes sure it will not be blocked by the defence tools. Story: *Operation Fake-Parcel*, a fictional phishing campaign that sends fake parcel-delivery emails. All data is fictional and harmless (documentation IP ranges, `.example` domains).

- **Role:** `site-admin`
- **Test data (before):** event `Fake-Parcel false positive {timestamp}` with the attributes `203.0.113.45` (`ip-dst`, For IDS) and `8.8.8.8` (`ip-dst`, For IDS), created through the API
- **Cleanup (after):** delete the event; disable the warninglist `List of known IPv4 public DNS resolvers` if it was disabled before; delete the correlation exclusion `8.8.8.8`
- **Known bugs on the way:** Bug 3 (the false positive button may show "Failed to add sighting")

**Phase 1 – MISP warns**

1. Open `/warninglists/index`, search `List of known IPv4 public DNS resolvers` and make sure it is **Enabled**.
2. Open the event page of `Fake-Parcel false positive {timestamp}` and the **tab** "Attributes".
3. Check that `8.8.8.8` shows a warninglist hit naming `List of known IPv4 public DNS resolvers`, and `203.0.113.45` does not.

**Phase 2 – Mark it as a false positive**

4. Click the **button** "Mark as false positive" of `8.8.8.8`.
5. Check that the false positive counter of `8.8.8.8` shows **1**.

**Phase 3 – Keep it out of the defence tools and correlations**

6. Click **Edit** on `8.8.8.8`, untick the **checkbox** "For IDS" and click the **button** "Save Changes".
7. Check that `8.8.8.8` is shown with IDS off and `203.0.113.45` with IDS on.
8. Open `/correlation_exclusions/index`, click the **button** "Add Exclusion", type `8.8.8.8`, comment `Public DNS, false positive` and save.

**Expected:**
- `8.8.8.8` is flagged by the warninglist, has **1** false positive sighting, IDS is off, and it is in the correlation exclusions.
- `203.0.113.45` is not flagged and keeps IDS on.
