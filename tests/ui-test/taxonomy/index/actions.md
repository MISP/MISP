# MISP Web UI – Taxonomy Index – Actions Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Taxonomy enable and disable](#taxonomy-enable-disable) | |
| 2 | [Taxonomy required – publish without notification](#taxonomy-required-publish-no-email) | |
| 3 | [Taxonomy required – publish with notification](#taxonomy-required-publish-email) | |
| 4 | [Taxonomy required – publish with the required tag](#taxonomy-required-publish-tagged) | |
| 5 | [Taxonomy disabled – tag already on an event](#taxonomy-disabled-tag-on-event) | |
| 6 | [Taxonomy update](#taxonomy-update) | |
| 7 | [Taxonomy and galaxy disabled – tags on event, attribute and object](#taxonomy-galaxy-disabled-everywhere) | |

---


# E2E Tests

### Taxonomy enable and disable
<a id="taxonomy-enable-disable"></a>

An enabled taxonomy offers its tags on events, a disabled one does not

1. Log in to MISP as `site-admin`.
2. Go to `/taxonomies/index`.
3. Search for `pap` and click **Enable** on the `pap` taxonomy, then confirm.
4. Go to `/events/index` and open any event.
5. Click **Edit Tags** and type `pap:` in the tag search.
6. Close the tag window, go to `/taxonomies/index` and click **Disable** on `pap`, then confirm.
7. Open the same event again, click **Edit Tags** and type `pap:`.

**Expected:** after enabling, the `pap:` tags are offered in **Edit Tags**; after disabling, they are not offered anymore.

### Taxonomy required – publish without notification
<a id="taxonomy-required-publish-no-email"></a>

An event without a tag of a required taxonomy cannot be published, even without sending the notification email

1. Log in to MISP as `site-admin`.
2. Go to `/taxonomies/index`.
3. Click **Require** on the `tlp` taxonomy.
4. Go to `/events/index`.
5. Create an event `QA required tlp` with **Add Event** and stay on its detail page.
6. Click **Publish Event**.
7. Leave **Send notification email** off and confirm.
8. Go to `/taxonomies/index` and click **Optional** on `tlp` to remove the requirement.

**Expected:** the event is not published and the message "Could not publish event - no tag for required taxonomies missing: tlp" is shown.

### Taxonomy required – publish with notification
<a id="taxonomy-required-publish-email"></a>

An event without a tag of a required taxonomy cannot be published with the notification email

1. Log in to MISP as `site-admin`.
2. Go to `/taxonomies/index`.
3. Click **Require** on the `tlp` taxonomy.
4. Go to `/events/index`.
5. Create an event `QA required tlp email` with **Add Event** and stay on its detail page.
6. Click **Publish Event**.
7. Turn **Send notification email** on and confirm.
8. Go to `/taxonomies/index` and click **Optional** on `tlp` to remove the requirement.

**Expected:** the event is not published and the message "Could not publish event - no tag for required taxonomies missing: tlp" is shown.

### Taxonomy required – publish with the required tag
<a id="taxonomy-required-publish-tagged"></a>

An event with a tag of the required taxonomy can be published

1. Log in to MISP as `site-admin`.
2. Go to `/taxonomies/index`.
3. Click **Require** on the `tlp` taxonomy.
4. Go to `/events/index`.
5. Create an event `QA required tlp tagged` with **Add Event** and stay on its detail page.
6. Click **Edit Tags**, add `tlp:green` and save.
7. Click **Publish Event** and confirm.
8. Go to `/taxonomies/index` and click **Optional** on `tlp` to remove the requirement.

**Expected:** the event is published without error.

### Taxonomy disabled – tag already on an event
<a id="taxonomy-disabled-tag-on-event"></a>

Disabling a taxonomy does not break events that already use its tags

1. Log in to MISP as `site-admin`.
2. Go to `/taxonomies/index`.
3. Go to `/events/index`.
4. Create an event `QA disabled taxonomy` with **Add Event** and stay on its detail page.
5. Click **Edit Tags**, add an `admiralty-scale:` tag and save.
6. Go to `/taxonomies/index` and click **Disable** on `admiralty-scale`, then confirm.
7. Go to `/events/index` and open `QA disabled taxonomy`.
8. Go to `/taxonomies/index` and click **Enable** on `admiralty-scale`, then confirm.

**Expected:** the event still opens without error and still shows its `admiralty-scale:` tag while the taxonomy is disabled.

### Taxonomy update
<a id="taxonomy-update"></a>

Updating the taxonomies keeps the enabled taxonomies and their settings

1. Log in to MISP as `site-admin`.
2. Go to `/taxonomies/index`.
3. Note which taxonomies are **Enabled** (e.g. `tlp`, `admiralty-scale`).
4. Click **Update Taxonomies** and wait for the end.
5. Reload the page.

**Expected:** a success message is shown, no taxonomy disappears, and the same taxonomies are still **Enabled**.

### Taxonomy and galaxy disabled – tags on event, attribute and object
<a id="taxonomy-galaxy-disabled-everywhere"></a>

Disabling a taxonomy and a galaxy that are used on an event, an attribute and an object attribute

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA disable taxonomy and galaxy` with **Add Event**.
4. Add the tag `admiralty-scale:source-reliability="a"` and the cluster `APT28` (Threat Actor) to the event.
5. Add an attribute `ip-dst` `198.51.100.130` and give it the same tag and cluster.
6. Add a `domain-ip` object with the domain `qa-disable.example` and give its attribute the same tag and cluster.
7. Go to `/taxonomies/index` and click **Disable** on `admiralty-scale`; go to `/galaxies/index` and click **Disable** on `Threat Actor`.
8. Open `QA disable taxonomy and galaxy` and check the tags and galaxies of the event, the attribute and the object.
9. Click **Edit Tags** on the event and search `admiralty-scale:`; click **Edit Galaxy Clusters** and search `APT29`.
10. Enable `admiralty-scale` and `Threat Actor` again.

**Expected:** the event page opens without error and still shows the tag and `APT28` on the event, the attribute and the object attribute; the pickers do not offer `admiralty-scale:` tags or `Threat Actor` clusters while they are disabled (see Bug 15).

**Seeded data:** `QA disable taxonomy and galaxy` (tag `qa:taxonomy-galaxy-disabled-everywhere`): tag and cluster attached through the API to the event, the attribute `198.51.100.130` and the `domain-ip` object attribute. With `admiralty-scale` and `Threat Actor` disabled: the tags and the cluster were still listed everywhere (API and the event tags/galaxies cards), the Events list filtered on the tag still showed the event, and no new error.log entry. But a new tag `admiralty-scale:source-reliability="b"` and the cluster `APT29` could still be attached (HTTP 200). Both were enabled again afterwards.
