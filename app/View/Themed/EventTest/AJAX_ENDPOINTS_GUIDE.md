# EventTest Theme - AJAX Endpoints Guide

This document describes the decomposed event view endpoints introduced by the EventTest theme. The original monolithic `view()` action has been split into a lightweight metadata shell (`view2`) and several AJAX-loaded endpoints for attributes, objects, related events, and warninglist hits.

The view templates in this theme are **reference implementations** that demonstrate how to consume these endpoints. The new UX should call the same backend endpoints and can render the responses however it sees fit.

## Architecture Overview

```
/events/view2/{id}              Main page shell (metadata only)
  |
  +-- /events/viewAttributes/{id}      AJAX: paginated attributes
  +-- /events/viewObjects/{id}         AJAX: paginated objects
  +-- /events/viewRelatedEvents/{id}   AJAX: correlated events (side panel)
  +-- /events/viewWarninglistHits/{id} AJAX: warninglist summary (side panel)
```

All endpoints:
- Accept event ID or UUID as the `{id}` parameter
- Return JSON when called via REST (API key / `Accept: application/json`)
- Return layout-free HTML fragments when called from the browser (suitable for injecting into the DOM via AJAX)
- Enforce distribution-based ACL at the database query level
- Require `MISP.enable_themes` to be enabled (see ACL section below)

## ACL Requirements

All five endpoints are gated behind the `theming_enabled` dynamic check in `app/Controller/Component/ACLComponent.php`. This check reads `MISP.enable_themes` from the server configuration — if theming is disabled, the endpoints return a 403.

The ACL entries are defined in the `$__aclList['events']` array:

```php
'view2' => array('theming_enabled'),
'viewAttributes' => array('theming_enabled'),
'viewObjects' => array('theming_enabled'),
'viewRelatedEvents' => array('theming_enabled'),
'viewWarninglistHits' => array('theming_enabled'),
```

The `theming_enabled` dynamic check is registered in `ACLComponent::initialize()`:

```php
$this->dynamicChecks['theming_enabled'] = function (array $user) {
    return (bool)Configure::read('MISP.enable_themes');
};
```

If you add new endpoints for the decomposed event view, add them to the ACL list with the same `theming_enabled` check. If a different access policy is needed (e.g. restricting to specific themes or roles), create a new dynamic check rather than modifying the existing one.

## Endpoints

### GET /events/view2/{id}

The entry point. Loads only event metadata — no attributes or objects.

**Named parameters:**
- `viewAs:{userId}` (site admin only) — view the event as a different user

**What it loads:**
- Event fields (id, uuid, info, date, threat_level_id, analysis, distribution, published, timestamp, etc.)
- Org, Orgc, ThreatLevel, SharingGroup (with Organisation)
- EventTag with full Tag objects
- Galaxy clusters derived from galaxy tags (via `GalaxyCluster->getClustersByTags()`)
- Extension chain: `Event.Extends` (parent) and `Event.ExtendedBy[]` (children)
- Analyst data: Note, Opinion, Relationship

**REST response:** Full enriched event object as JSON.

**HTML rendering:** Uses `single_view` generic element with:
- Metadata fields (ID, UUID, creator org, owner org, tags, date, threat level, analysis, distribution, published status, timestamps, extends/extended-by, correlation toggle)
- Side panels: placeholder `<div>` elements for AJAX-loaded related events and warninglist hits
- Children: accordion panels for attributes and objects, loaded via AJAX on expand
- Galaxies: rendered inline via `galaxyQuickViewNew` element, positioned above the attribute accordion

**Key view variables set:**
| Variable | Description |
|---|---|
| `$event` | Enriched event array |
| `$analysisLevels` | Analysis level code-to-label mapping |
| `$eventDescriptions` | Field descriptions for tooltips |
| `$distributionLevels` | Distribution code-to-label mapping |
| `$shortDist` | Short distribution labels |

---

### GET /events/viewAttributes/{id}

Paginated, sorted, filterable list of attributes with full enrichment.

**Named parameters / POST data:**
| Parameter | Default | Description |
|---|---|---|
| `page` | 1 | Page number |
| `limit` | 60 | Results per page (max 500) |
| `sort` | timestamp | Sort field (see below) |
| `direction` | DESC | ASC or DESC |
| `deleted` | 0 | 0 = active only, 1 = all, 2 = deleted only |
| `category` | — | Filter by category |
| `type` | — | Filter by attribute type |
| `toIDS` | 0 | 0 = any, 1 = IDS only, 2 = non-IDS only |
| `searchFor` | — | LIKE search on attribute value |
| `flatten` | 0 | 1 = include object attributes, 0 = standalone only |

**Sortable fields:** `id`, `uuid`, `type`, `category`, `value`, `to_ids`, `timestamp`, `distribution`, `comment`, `first_seen`, `last_seen`

**REST response:**
```json
{
    "Attribute": [ ... ],
    "total": 142,
    "page": 1,
    "limit": 60,
    "sightings_csv": [ ... ]
}
```

**Attribute data structure (per item):**
```
id, type, category, value, to_ids, uuid, event_id, distribution,
timestamp, comment, sharing_group_id, deleted, disable_correlation,
first_seen, last_seen, object_id, object_relation

AttributeTag[] -> each has { id, attribute_id, tag_id, local,
                              relationship_type, Tag { id, name,
                              colour, exportable, is_galaxy, ... } }

SharingGroup { name }          // only when distribution == 4

RelatedAttribute[]             // correlations to other events
Sighting[]                     // sighting counts
Feed[]                         // feed correlation hits
Server[]                       // server correlation hits
warnings[]                     // warninglist matches

Note[], Opinion[], Relationship[]   // analyst data
```

**HTML rendering:** Wraps the existing `row_attribute.ctp` element for each attribute, providing full feature parity with the original event view (actions, tag editing, galaxy display, quick edit, correlation toggle, etc.).

The reference template includes a control bar with:
- Checkbox: "Include object attributes" (toggles `flatten`)
- Text input: "Filter by value..." (debounced search, sends `searchFor`)

**Key view variables set (in addition to attributes/pagination):**
| Variable | Description |
|---|---|
| `$mayModify` | Can the user modify this event |
| `$mayChangeCorrelation` | Can the user toggle correlation |
| `$attrDescriptions` | Attribute field descriptions |
| `$shortDist` | Short distribution labels |
| `$modules` | Enabled enrichment modules (if configured) |
| `$cortex_modules` | Enabled Cortex modules (if configured) |
| `$flatten` | Current flatten state |
| `$searchFor` | Current search term |

---

### GET /events/viewObjects/{id}

Paginated objects with fully enriched nested attributes.

**Named parameters / POST data:**
| Parameter | Default | Description |
|---|---|---|
| `page` | 1 | Page number |
| `limit` | 60 | Results per page (max 500) |
| `sort` | timestamp | Sort field (see below) |
| `direction` | DESC | ASC or DESC |
| `deleted` | 0 | 0 = active only, 1 = all, 2 = deleted only |
| `name` | — | Filter by object template name |
| `meta-category` | — | Filter by meta-category |
| `searchFor` | — | Search in nested attribute values (subquery) |

**Sortable fields:** `id`, `uuid`, `name`, `meta-category`, `timestamp`, `distribution`, `comment`, `first_seen`, `last_seen`

**REST response:**
```json
{
    "Object": [ ... ],
    "total": 38,
    "page": 1,
    "limit": 60
}
```

**Object data structure:**
```
id, name, meta-category, description, template_uuid, template_version,
event_id, uuid, timestamp, distribution, sharing_group_id, comment,
deleted, first_seen, last_seen

SharingGroup { name }           // only when distribution == 4

Attribute[] -> each nested attribute has the same enrichment
               as viewAttributes (tags, correlations, sightings,
               warninglists, feed/server hits, analyst data)
               plus ShadowAttribute[] (proposals)

Note[], Opinion[], Relationship[]   // analyst data on the object itself
```

---

### GET /events/viewRelatedEvents/{id}

Event-level correlation summary. Returns the list of events that share correlated attribute values with this event.

**Parameters:** None (beyond the event ID).

**REST response:**
```json
{
    "RelatedEvent": [
        {
            "Event": {
                "id": 1234,
                "date": "2025-01-15",
                "info": "Campaign X",
                "threat_level_id": 2,
                "analysis": 1,
                "distribution": 1,
                "org_id": 1,
                "orgc_id": 5,
                "published": true,
                "uuid": "...",
                "timestamp": "1705363200",
                "Org": { "id": 1, "name": "...", "uuid": "..." },
                "Orgc": { "id": 5, "name": "...", "uuid": "..." }
            }
        }
    ]
}
```

**HTML rendering:** The reference template reuses the existing `related_event.ctp` element for each entry, wrapped in the standard correlation container with:
- Expand/collapse for lists exceeding 10 entries
- Sort dropdown (by date or by correlation count)

**View variables:**
| Variable | Description |
|---|---|
| `$relatedEvents` | Array of related event records |
| `$correlationCounts` | Map of related event ID to correlation count |
| `$event` | Event shell (id, orgc_id, org_id) |

---

### GET /events/viewWarninglistHits/{id}

Aggregated warninglist hit summary across all attributes in the event.

**Parameters:** None (beyond the event ID).

**REST response:**
```json
{
    "false_positive": {
        "54": "List of known IPv6 public DNS resolvers",
        "12": "List of RFC 5735 CIDR blocks"
    },
    "known": {
        "3": "List of known Microsoft Azure Datacenter IP Ranges"
    }
}
```

Warninglists are categorised by their `category` field into `false_positive` and `known` buckets.

**HTML rendering:** The reference template shows warninglist names grouped by category, each linking to the warninglist detail page.

---

## Enrichment Pipeline

All attribute enrichment (whether standalone or nested inside objects) passes through a shared `__enrichAttributes()` method in the Event model. This ensures consistent data regardless of which endpoint serves the attributes.

The enrichment steps in order:
1. **Warninglist matching** — `Warninglist->attachWarninglistToAttributes()`
2. **Feed correlations** — `Feed->attachFeedCorrelations()`
3. **Server correlations** — `Feed->attachFeedCorrelations()` with server flag (conditional on admin status / `MISP.enable_feed_pull_scope` setting)
4. **Attribute correlations** — `Correlation->getAttributeCorrelations()` dispatches to the active correlation engine
5. **Sightings** — `Sighting->attachToAttributes()` with CSV output
6. **Analyst data** — `Attribute->attachAnalystDataBulk()`

## How the Reference Templates Load Data

In `view2.ctp`, the AJAX calls are fired on page load:

```javascript
// Side panels — fire immediately
$.ajax({
    url: baseurl + '/events/viewRelatedEvents/' + eventId,
    success: function(data) {
        $('#side-related-events').html(data);
    }
});

$.ajax({
    url: baseurl + '/events/viewWarninglistHits/' + eventId,
    success: function(data) {
        $('#side-warninglist-hits').html(data);
    }
});
```

Attributes and objects are loaded via the `single_view` element's built-in accordion system, which fetches the `url` of each child panel when it is opened:

```php
'children' => [
    [
        'title' => __('Attributes'),
        'url' => sprintf('/events/viewAttributes/%s', h($eventId)),
        'elementId' => 'attributes_panel',
        'open' => true,  // loads immediately
    ],
    [
        'title' => __('Objects'),
        'url' => sprintf('/events/viewObjects/%s', h($eventId)),
        'elementId' => 'objects_panel',
        // loads on first expand
    ],
],
```

Galaxies are rendered server-side (not via AJAX) since they are part of the enriched event metadata, using the `galaxyQuickViewNew` element.

## Reusable Elements

The reference templates reuse these existing elements rather than reimplementing rendering:

| Element | Used by | Purpose |
|---|---|---|
| `row_attribute.ctp` | viewAttributes | Full attribute row with actions, tags, galaxies, correlations, quick edit |
| `related_event.ctp` | viewRelatedEvents | Single related event display with org logo and correlation count |
| `galaxyQuickViewNew` | view2 (galaxies section) | Galaxy cluster listing with add/edit controls |
| `ajaxTags` | view2 (event tags field) | Tag display with add/remove controls |
| `single_view` | view2 | Generic metadata display with side panels and accordion children |

## Notes for Implementers

- All AJAX endpoints set `$this->layout = false` so they return bare HTML fragments without the full page layout.
- Pagination state is managed client-side. The `loadAttributePage()` / `loadObjectPage()` functions in the reference templates rebuild the URL with named parameters and replace the accordion panel content.
- The `flatten` toggle and `searchFor` filter reset pagination to page 1 to avoid landing on an out-of-range page.
- The `__eventViewCommon()` helper (called by `viewAttributes`) sets shared view variables needed by `row_attribute.ctp`: `$attrDescriptions`, `$distributionLevels`, `$shortDist`, `$modules`, `$cortex_modules`, etc.
- Global view variables like `$me`, `$isSiteAdmin`, `$isAclAdd`, `$hostOrgUser`, `$baseurl` are set by `AppController` and available in all views.
