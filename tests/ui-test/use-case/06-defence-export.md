# MISP Web UI – Use Case – Defence Export Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Use case 6 – Feed the defence tools](#use-case-defence-export) | |

---


# E2E Tests

### Use case 6 – Feed the defence tools
<a id="use-case-defence-export"></a>

The security team needs the list of indicators to block. The analyst exports only the published indicators flagged for IDS, so that the false positive is not blocked. Story: *Operation Fake-Parcel*, a fictional phishing campaign that sends fake parcel-delivery emails. All data is fictional and harmless (documentation IP ranges, `.example` domains).

- **Role:** `site-admin`
- **Test data (before):** published event `Fake-Parcel export {timestamp}` with `parcel-tracking.example` (`domain`, For IDS), `203.0.113.45` (`ip-dst`, For IDS) and `8.8.8.8` (`ip-dst`, IDS off), created through the API
- **Cleanup (after):** delete the event and the downloaded files
- **Known bugs on the way:** Bug 2 (CSV does not neutralise formulas; not triggered by this data)

**Phase 1 – Export as text for a firewall**

1. Open the event page of `Fake-Parcel export {timestamp}` and click the **link** "Download as".
2. Click "Export all attribute values as a text file" (keep **Include non-IDS marked attributes** off).
3. Open the downloaded file and check its content.

**Phase 2 – Export as CSV for a SIEM**

4. Click the **link** "Download as" again and click "CSV (NOT FOR EXCEL…" (keep **Include non-IDS marked attributes** off).
5. Open the downloaded file and check its content.

**Expected:**
- The text file contains `parcel-tracking.example` and `203.0.113.45`, one per line, and does **not** contain `8.8.8.8`.
- The CSV file contains a row for `parcel-tracking.example` and for `203.0.113.45`, and no row for `8.8.8.8`.
