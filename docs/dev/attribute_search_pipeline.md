# Attribute restSearch Pipeline

This document traces the full execution path of
`POST /attributes/restSearch` from HTTP request to response.

## Overview

```
HTTP Request
  → AppController::restSearch()          parameter harvesting, format selection
    → MispAttribute::restSearch()        defaults, export module, pagination
      → buildFilterConditions()          dispatch filters to set_filter_*()
        → set_filter_tags()              tag subquery generation (OR/NOT/AND)
        → buildConditions()              distribution-based ACL
      → fetchAttributes()               query assembly, execution, enrichment
        → __iteratedFetch()              batched streaming through export tool
  → HTTP Response                        headers + streamed body
```

## Detailed Pipeline

```
HTTP REQUEST
POST /attributes/restSearch  { type, tags, timestamp, ... }
│
▼
┌──────────────────────────────────────────────────────────────┐
│  AppController::restSearch()                                 │
│  app/Controller/AppController.php:1439                       │
│                                                              │
│  1. Determine scope (Attribute)                              │
│  2. _harvestParameters() ─── merge POST body, URL params,    │
│     │                        named params, query string      │
│     │                        against 76 known filter keys    │
│     ▼                        (RestSearchComponent::paramArray)│
│  3. Resolve returnFormat (json/xml/csv/stix/...)             │
│  4. Apply user role limit cap                                │
│  5. Call model→restSearch(user, format, filters)  ───────────┤
│                                                              │
└──────────────────────────────────────────────────────────────┘
│
▼
┌──────────────────────────────────────────────────────────────┐
│  MispAttribute::restSearch()                                 │
│  app/Model/MispAttribute.php:3317                            │
│                                                              │
│  1. Load export module (JSONExport, etc.)                     │
│  2. Apply restrictive defaults if export requires it         │
│     (to_ids=1, published=1)                                  │
│  3. Handle searchall → wildcard conversion                   │
│  4. Event::harvestSubqueryElements()  ── extract org/dist    │
│     Event::addFiltersFromSubqueryElements()    subqueries    │
│     Event::addFiltersFromUserSettings()                      │
│  5. buildFilterConditions() ─────────────────────────────────┤
│  6. Build fetchAttributes() params                           │
│     (fields, enrichment flags, pagination, sort order)       │
│  7. __iteratedFetch() ── stream pages through export tool    │
│                                                              │
└──────────────────────────────────────────────────────────────┘
│
▼
┌──────────────────────────────────────────────────────────────┐
│  MispAttribute::buildFilterConditions()                      │
│  app/Model/MispAttribute.php:3225                            │
│                                                              │
│  Iterates over user-supplied filters and dispatches each     │
│  to a specialised set_filter_*() method.                     │
│                                                              │
│  ┌─────────────────────┐  ┌──────────────────────┐           │
│  │ Attribute-scope     │  │ Event-scope           │           │
│  │                     │  │                       │           │
│  │ value  → set_filter │  │ eventid   → set_filter│           │
│  │ type   → set_filter │  │ published → set_filter│           │
│  │ category            │  │ from/to/last          │           │
│  │ to_ids              │  │ threat_level_id       │           │
│  │ uuid                │  │ org                   │           │
│  │ deleted             │  │ eventinfo             │           │
│  │ timestamp           │  │                       │           │
│  │ first_seen          │  │                       │           │
│  │ last_seen           │  │                       │           │
│  │ comment             │  │                       │           │
│  └─────────────────────┘  └──────────────────────┘           │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │ Tags → set_filter_tags()   (see detail below)           │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │ Wildcard → set_filter_wildcard_attributes()             │ │
│  │ (full-text OR across value1, value2, comment, uuid)     │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                              │
│  Returns: $conditions array (WHERE clause fragments)         │
└──────────────────────────────────────────────────────────────┘
│
▼
┌──────────────────────────────────────────────────────────────┐
│  set_filter_tags()  — Tag filtering detail                   │
│  app/Model/MispAttribute.php:1109                            │
│                                                              │
│  Input parsing: dissectArgs() splits tags into 3 groups      │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ Positive OR tags  (tagArray[0])                        │  │
│  │                                                        │  │
│  │ Tag names resolved → tag IDs via tags table            │  │
│  │                                                        │  │
│  │ (Attribute.id IN                                       │  │
│  │     (SELECT at.attribute_id                            │  │
│  │      FROM attribute_tags at                            │  │
│  │      WHERE at.tag_id IN ({pos_ids}))                   │  │
│  │  OR                                                    │  │
│  │  Attribute.event_id IN                                 │  │
│  │     (SELECT et.event_id                                │  │
│  │      FROM event_tags et                                │  │
│  │      WHERE et.tag_id IN ({pos_ids})))                  │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ Negative NOT tags  (tagArray[1])                       │  │
│  │                                                        │  │
│  │ NOT EXISTS (SELECT 1 FROM event_tags et_neg            │  │
│  │   WHERE et_neg.event_id = Attribute.event_id           │  │
│  │   AND et_neg.tag_id IN ({neg_ids}))                    │  │
│  │ AND                                                    │  │
│  │ NOT EXISTS (SELECT 1 FROM attribute_tags at_neg        │  │
│  │   WHERE at_neg.attribute_id = Attribute.id             │  │
│  │   AND at_neg.tag_id IN ({neg_ids}))                    │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ AND-group tags  (tagArray[2])                          │  │
│  │                                                        │  │
│  │ For EACH tag in the AND group, one pair of subqueries: │  │
│  │                                                        │  │
│  │ (Attribute.id IN (... tag_id = {id_N})                 │  │
│  │  OR Attribute.event_id IN (... tag_id = {id_N}))       │  │
│  │ AND                                                    │  │
│  │ (Attribute.id IN (... tag_id = {id_M})                 │  │
│  │  OR Attribute.event_id IN (... tag_id = {id_M}))       │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
└──────────────────────────────────────────────────────────────┘
│
▼
┌──────────────────────────────────────────────────────────────┐
│  MispAttribute::fetchAttributes()                            │
│  app/Model/MispAttribute.php:1848                            │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ A. Assemble final WHERE clause                        │  │
│  │                                                        │  │
│  │  1. Deletion filter   (Attribute.deleted = 0)          │  │
│  │  2. Attribute filters (type, category, value, ...)     │  │
│  │  3. Flatten filter    (Attribute.object_id = 0)        │  │
│  │  4. Object filters    (Object.*)                       │  │
│  │  5. Event filters     (Event.published, etc.)          │  │
│  │  6. ACL conditions    ◄── buildConditions(user)        │  │
│  │  7. Tag subqueries    (from set_filter_tags)           │  │
│  │  8. Remaining filters                                  │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ B. Build CakePHP find() params                        │  │
│  │                                                        │  │
│  │  fields:  Attribute.*, Event.id/info/org_id/dist/..., │  │
│  │           Object.id/dist/sharing_group_id              │  │
│  │  joins:   INNER JOIN events  ON Event.id = event_id    │  │
│  │           LEFT  JOIN objects ON Object.id = object_id  │  │
│  │  contain: [AttributeTag]                               │  │
│  │  order:   user-specified or default                    │  │
│  │  limit/page: pagination                                │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ C. Execute query & enrich (batched)                   │  │
│  │                                                        │  │
│  │  $this->find('all', $params)                           │  │
│  │          │                                             │  │
│  │          ▼                                             │  │
│  │  ┌─────────────────────────────────────────────────┐   │  │
│  │  │            MySQL query execution                │   │  │
│  │  │                                                 │   │  │
│  │  │  Tables hit:                                    │   │  │
│  │  │   • attributes (primary)                        │   │  │
│  │  │   • events     (INNER JOIN — ACL + event        │   │  │
│  │  │   │              filters)                       │   │  │
│  │  │   • objects    (LEFT JOIN — object filters)     │   │  │
│  │  │   • attribute_tags (contain — tag fetch)        │   │  │
│  │  │   • event_tags     (subquery — tag filters)     │   │  │
│  │  │   • tags           (subquery — name→ID)         │   │  │
│  │  └─────────────────────────────────────────────────┘   │  │
│  │          │                                             │  │
│  │          ▼                                             │  │
│  │  Post-query enrichment (per attribute):                │  │
│  │                                                        │  │
│  │  1. attachTagsToAttributes()   ── Tag objects          │  │
│  │  2. Org / Orgc lookup          ── from Event (cached)  │  │
│  │  3. ThreatLevel attachment                             │  │
│  │  4. Sightings                  ── if includeSightings  │  │
│  │  5. Correlations               ── if includeCorrel.    │  │
│  │  6. Warninglist check          ── if enforceWarninglist│  │
│  │  7. EventTag inheritance       ── if includeEventTags  │  │
│  │  8. Warninglist hits           ── if includeWLHits     │  │
│  │  9. Attachments (base64)       ── if withAttachments   │  │
│  │  10. Decay scores              ── if includeDecayScore │  │
│  │  11. Galaxy expansion          ── if includeGalaxy     │  │
│  │  12. Proposal blocking         ── if allow_proposal_bl.│  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
│  Returns: enriched attribute array                           │
└──────────────────────────────────────────────────────────────┘
│
▼
┌──────────────────────────────────────────────────────────────┐
│  __iteratedFetch()  → Export tool                            │
│  app/Model/MispAttribute.php:3472                            │
│                                                              │
│  For each page of fetchAttributes() results:                 │
│   • Pass each attribute through exportTool->handler()        │
│   • Write formatted output to TmpFileTool (streaming)        │
│   • Advance page until exhausted or limit reached            │
│                                                              │
└──────────────────────────────────────────────────────────────┘
│
▼
┌──────────────────────────────────────────────────────────────┐
│  AppController::restSearch()  — response                     │
│  app/Controller/AppController.php:1565                       │
│                                                              │
│  Headers:                                                    │
│   X-Result-Count, X-Export-Module-Used,                      │
│   X-Response-Format, X-Skipped-Elements-Count,               │
│   Content-Disposition                                        │
│                                                              │
│  Body: streamed from TmpFileTool via RestResponse->viewData()│
└──────────────────────────────────────────────────────────────┘
│
▼
HTTP RESPONSE
```

## ACL: buildConditions()

Distribution-based access control applied at the SQL level inside
`fetchAttributes()`.  Cached per `{is_site_admin}-{org_id}`.

```
buildConditions(user)
app/Model/MispAttribute.php:1661
│
├─ Site admin?  → return [] (no restrictions)
│
└─ Regular user:
   │
   ▼
   OR (
     ├─ Event.org_id = {user.org_id}          ◄── own org: full access
     │
     └─ AND (
          ├─ Event.distribution IN (1,2,3)     ◄── community/connected/all
          │  OR (Event.distribution = 4        ◄── sharing group
          │      AND Event.sharing_group_id
          │          IN ({user's SG ids}))
          │
          └─ AND (
               ├─ Attribute.distribution        ◄── attr-level dist check
               │  IN (1,2,3,5)                      (5 = inherit from event)
               │  OR (Attribute.distribution = 4
               │      AND Attribute.sharing_group_id
               │          IN ({user's SG ids}))
               │
               └─ AND (Object.distribution      ◄── object-level dist check
                    IN (1,2,3,5)                     (only for object attrs)
                    OR Object.distribution = 4
                       AND Object.sharing_group_id
                           IN ({user's SG ids})
                    OR Attribute.object_id = 0)     (standalone attrs skip)
          )
   )
   │
   └─ Optional: AND Event.published = 1       ◄── if MISP.unpublishedprivate
```

## Tables involved

For reference, the tables that each filter axis touches:

| Filter | Primary table | Secondary table(s) |
|---|---|---|
| `type`, `category`, `to_ids`, `value`, `deleted` | `attributes` | — |
| `timestamp`, `first_seen`, `last_seen` | `attributes` | — |
| `published`, `threat_level_id`, `org` | `events` (joined) | — |
| Positive tags | `attribute_tags` OR `event_tags` | `tags` (name→ID resolution) |
| Negative tags | `attribute_tags` AND `event_tags` (anti-join) | `tags` |
| AND tags | `attribute_tags` OR `event_tags` (per tag) | `tags` |
| ACL distribution | `events`, `attributes`, `objects` | `sharing_groups` (pre-resolved to ID list) |

## Key files

| File | Methods | Purpose |
|---|---|---|
| `app/Controller/AppController.php` | `restSearch()`, `_harvestParameters()` | HTTP entry, parameter merging, response formatting |
| `app/Controller/Component/RestSearchComponent.php` | `$paramArray` | Defines the 76 accepted filter keys per scope |
| `app/Model/MispAttribute.php` | `restSearch()` | Export module loading, defaults, pagination, streaming |
| `app/Model/MispAttribute.php` | `buildFilterConditions()` | Filter dispatch loop |
| `app/Model/MispAttribute.php` | `set_filter_tags()` | Tag subquery generation (OR/NOT/AND) |
| `app/Model/MispAttribute.php` | `buildConditions()` | Distribution-based ACL condition generation |
| `app/Model/MispAttribute.php` | `fetchAttributes()` | Final query assembly, execution, post-query enrichment |
| `app/Model/MispAttribute.php` | `__iteratedFetch()` | Batched page-through with memory management |
| `app/Model/Event.php` | `harvestSubqueryElements()`, `addFiltersFromSubqueryElements()`, `addFiltersFromUserSettings()` | Pre-filter processing (org/distribution subqueries, user defaults) |
