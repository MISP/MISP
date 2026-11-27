# Complex queries in restSearch

`POST /attributes/restSearch`, `POST /events/restSearch`,
`POST /objects/restSearch` and `POST /galaxy_clusters/restSearch` accept an
additional `query` key carrying a boolean tree of field conditions, so that
requests such as `type = "domain" OR (id > 50000 AND tags = "tlp:white")` can
be expressed. Requests without `query` behave exactly as before.
`POST /event_reports/restSearch`, `POST /analyst_data/restSearch/<Type>`,
`POST /collections/restSearch`, `POST /tags/restSearch` and
`POST /organisations/restSearch` are built around `query` and take no legacy
filters.

The grammar, operators, limits and errors are the same on every endpoint.
What differs is the list of fields and what the tree selects: see
[Attributes](#attributes), [Events](#events), [Objects](#objects),
[Galaxy clusters](#galaxy-clusters), [Event reports](#event-reports),
[Analyst data](#analyst-data), [Collections](#collections), [Tags](#tags)
and [Organisations](#organisations).

[MispQL](mispql.md), an SQL-like language, compiles its `WHERE` into this tree
and runs it through these endpoints.

## Availability

- Only on the restSearch endpoints above, and only as a JSON object in
  the body of a `POST` request. A `query` in the query string or the URL (also
  next to one in the body), in a `GET` request or of any other type is
  rejected with HTTP 400. Other endpoints that take restSearch filters, such
  as the `filters` of `/sightings/add`, reject a `query` with HTTP 400 as well.
- The user's role needs the **Complex query** permission
  (`perm_complex_query`), unless the user is a site admin. It is on for every
  role; untick it for accounts, such as a misbehaving integration, that should
  not send complex queries. Without it the request is answered with HTTP 403. On
  `/event_reports/restSearch`, `/analyst_data/restSearch/<Type>`,
  `/collections/restSearch`, `/tags/restSearch` and
  `/organisations/restSearch` this holds for every request, with or without
  `query`.
- `query` can be combined with the legacy filters. The result is
  `ACL AND legacy filters AND query`: the tree can only narrow what the user
  is allowed to see anyway, never widen it.
- `returnFormat` and the other output parameters work as usual. `query` only
  selects which attributes, events or objects are returned; on events and
  objects, a negated `tags` also strips the attributes carrying the tag.
- When a role reduces or imposes the page size (a `limit` above the role's,
  or no `limit`), the search response includes `X-Result-Page-Limit` with the
  applied size; a `count` never does. Page numbers are interpreted using that
  size. This header lets clients detect when a requested page would start at
  a different offset, or that a search without `limit` was cut at that size.
- `offset` skips that many rows before the page starts, as in SQL:
  `"limit": 3, "offset": 4` returns the 5th to the 7th row, and the offset
  need not be a multiple of the limit. It is a non-negative integer or a
  string of digits, and it needs a limit: a `limit` above 0, or the role's
  page size in its place. Any other value, or an `offset` without a limit,
  is answered with HTTP 400 naming `offset`, also where `offset` would then
  be ignored. `page` wins: with a `page` key in the request, whatever its
  value, `offset` is ignored and the request pages as before. Every endpoint
  above applies it; `/sightings/restSearch` and `"returnFormat": "count"`
  ignore it.
- A response whose page started at `offset` carries `X-Result-Offset` with
  that number; without it, the server ignored the filter (an older MISP drops
  it and serves the first page). Rows are counted as read: attributes left
  out after reading them (warninglists, decaying models, proposal blocking,
  counted in `X-Skipped-Elements-Count`) make the page shorter and never move
  it, and a role's page size shortens the page without moving its start.

## Grammar

```
node := {"AND": [node, ...]}
      | {"OR":  [node, ...]}
      | {"NOT": node}
      | leaf
leaf := {"<field>": value}                 // shorthand for {"=": value}
      | {"<field>": {"<operator>": operand}}
```

- A node is an object with exactly one key.
- `AND` and `OR` take a non-empty list; `NOT` takes exactly one node.
- A leaf has exactly one field and one operator.
- The legacy list shapes (`["a", "!b"]`, `{"OR": [...], "NOT": [...]}`) are not
  valid inside a leaf. Use `IN`, `NOT IN` and `NOT` instead.

Example, on attributes:

```json
{
  "query": {
    "AND": [
      {"OR": [{"type": "domain"}, {"type": {"IN": ["ip-src", "ip-dst"]}}]},
      {"id": {">": 50000}},
      {"NOT": {"tags": "tlp:red"}},
      {"timestamp": {">=": "7d"}}
    ]
  },
  "limit": 100
}
```

### Operators

| Operator | Meaning |
|---|---|
| `=`, `!=` | equals, not equals |
| `>`, `<`, `>=`, `<=` | numeric, timestamp, date and datetime fields only |
| `IN`, `NOT IN` | operand is a non-empty list |
| `LIKE`, `NOT LIKE` | string fields only; see below |

`!=`, `NOT IN` and `NOT LIKE` are shorthand for `NOT` over `=`, `IN` and
`LIKE`.

### Types

Types are strict, nothing is coerced: strings for string fields, JSON integers
for numeric fields (`"50000"` for `id` is an error) and `true`/`false` for
booleans. Timestamp fields take an integer (Unix time) or a relative string
made of digits and one of `d`, `h`, `m`, `s` (`"7d"` is seven days ago).
Date fields (`date`, the event date) take a `"YYYY-MM-DD"` string or a number
of days (`"30d"`); `h`, `m` and `s` are rejected there. Datetime fields
(`created` and `modified` on analyst data and collections, `date_created`
and `date_modified` on organisations) take what timestamp fields take, or a
`"YYYY-MM-DD"` or `"YYYY-MM-DD HH:MM:SS"` string, in UTC on analyst data
and in the server's time zone on collections and organisations, as each
stores them.

### Wildcards

Wildcards are only available through `LIKE` and `NOT LIKE`, with a leading
and/or trailing `%` and nothing else (`%evil`, `evil%`, `%evil%`). An `=`,
`!=`, `IN` or `NOT IN` value starting or ending with `%` is rejected, on
`tags` too, so these operators compare literally. The exception is `tags`,
as in the legacy filter: a value is matched against tag names as a pattern,
`_` standing for any one character and a `%` inside the value for any run
of them, and an all-digit value is a tag id. `{"tags": {"LIKE": "tlp:%"}}`
selects anything carrying a `tlp:` tag.

### NULL handling

`object_relation` and `comment` on attributes, `object_name` and
`object_template_uuid` on objects, `description`, `version`,
`extends_uuid` and `extends_version` on galaxy clusters, `content` on
event reports, and on analyst data the addresses (`object_uuid`,
`object_sha256` and their `related_object_` forms), `authors`, `note`,
`language`, `opinion`, `comment` and `relationship_type`, and `description`
on collections, `numerical_value` on tags, and `description`, `contacts`
and `landingpage` on organisations can be NULL. Inside a
`query`, `!=`,
`NOT IN` and `NOT` also match rows where the column is NULL. The legacy
filters (for example `object_relation: "!ip"`) do not. This difference is
intentional.

### Field names

A field name means the same thing on every endpoint that has it. Only `id`,
`uuid`, `distribution` and `timestamp` refer to the endpoint's own record
(the attribute, the event or the object). Conditions on the event use the
same names everywhere (`event_id`, `event_timestamp`, `eventinfo`, `org`,
...), so they can be copied from one endpoint's query to another's, where
that endpoint has the field. On events, `event_id` and `event_timestamp` are
the same as `id` and `timestamp`. Galaxy clusters have no event: there,
`org`, `org_id` and `orgc_id` are the cluster's own organisations, as they
are the collection's own on collections, and analyst data's `org`,
`org_uuid` and `orgc_uuid` are its own. Event
reports are searched as children of their event, with the event fields
under the same names.

## Attributes

`POST /attributes/restSearch`. The tree selects attributes.

With a `query` tree, `"returnFormat": "count"` returns the number of matching
attributes as the body and in `X-Result-Count`, counted in the database,
without applying `limit`, `page`, or the role's page size. With
`enforceWarninglist` or `excludeDecayed`, the matching attributes are read and
the body counts those the filter keeps; `X-Result-Count` is then the number
read.

| Field | Type | Operators | Notes |
|---|---|---|---|
| `id`, `event_id`, `object_id`, `distribution` | integer | `= != > < >= <= IN NOT IN` | |
| `threat_level_id` | integer | same | of the event |
| `timestamp` | timestamp | same | attribute timestamp |
| `event_timestamp`, `publish_timestamp` | timestamp | same | of the event |
| `to_ids` | boolean | `= !=` | |
| `published` | boolean | `= !=` | of the event |
| `uuid` | string | `= != IN NOT IN` | |
| `type`, `category`, `object_relation`, `comment`, `value` | string | `= != IN NOT IN LIKE NOT LIKE` | `value` matches both value fields |
| `eventinfo` | string | `= != IN NOT IN LIKE NOT LIKE` | info of the event |
| `tags` | string | `= != IN NOT IN LIKE NOT LIKE` | attribute or event tag; negated means neither carries it (as in the legacy filter); see Wildcards |
| `org` | string | `= != IN NOT IN` | name, uuid or id of the event's creator organisation, as in the legacy filter |

Anything not listed is rejected as `unknown_field`. The same list is
available programmatically, see [Discovery](#discovery).

`order` works as before (`"timestamp desc"`, `["type", "id desc"]`). The
sortable fields are the attribute fields `id`, `event_id`, `object_id`,
`type`, `category`, `value`, `distribution`, `timestamp`, `object_relation`
and `Event.publish_timestamp`. When `query` is present, an unknown or
malformed `order` is rejected with an error at path `order[i]`; without
`query` it is silently dropped, as it always was. Unless it already sorts by
`id`, an `order` is completed with `id` in the direction of its last field, so
pages of it never overlap or skip rows. Without `order`, rows come in the
database's order, which is not guaranteed to be the same from one page to the
next: page with an `order` when that matters (sorting has a cost on large
searches).

## Events

`POST /events/restSearch`. The tree selects events, and each one is returned
as it would be without `query`.

- Event fields are conditions on the event itself and can be negated freely.
- Attribute and object fields select an event that holds at least one
  element that matches, is not deleted and is visible to the user. They take
  positive operators only: `!=`, `NOT IN` and `NOT LIKE` on them are
  rejected as `unknown_operator`, and a `NOT` over a subtree holding one of
  them, or `tags`, as `bad_shape`. "Events without a `btc` attribute" cannot
  be expressed.
- `tags` selects an event that carries the tag itself or holds a visible,
  non-deleted attribute carrying it. Negated (`!=`, `NOT IN`, `NOT LIKE`),
  it excludes the events carrying a matching tag as an event tag and strips
  the attributes and event reports carrying one from the events returned.
  Since it acts on the output, a negated `tags` is only allowed where every
  enclosing node is an `AND`; under `OR` it is rejected as `bad_shape`.
  Write `{"tags": {"!=": "x"}}` or `{"tags": {"NOT LIKE": "x%"}}`, not
  `{"NOT": {"tags": ...}}`.
- So `{"tags": {"NOT LIKE": "tlp:%"}}` returns the events that carry no
  `tlp:` tag themselves; an event holding a `tlp:red` attribute is returned
  without that attribute.
- The `MISP.attribute_filters_block_only` setting does not apply: attribute
  fields inside `query` always select events.

| Field | Level | Type | Operators | Notes |
|---|---|---|---|---|
| `id`, `event_id` | event | integer | `= != > < >= <= IN NOT IN` | the same |
| `distribution`, `analysis`, `threat_level_id` | event | integer | same | |
| `org_id`, `orgc_id` | event | integer | same | owner and creator organisation |
| `timestamp`, `event_timestamp` | event | timestamp | same | the same |
| `publish_timestamp` | event | timestamp | same | |
| `date` | event | date | same | |
| `published` | event | boolean | `= !=` | |
| `uuid` | event | string | `= != IN NOT IN` | |
| `eventinfo` | event | string | `= != IN NOT IN LIKE NOT LIKE` | info of the event |
| `org` | event | string | `= != IN NOT IN` | name, uuid or id of the creator organisation |
| `tags` | event, attribute | string | `= != IN NOT IN LIKE NOT LIKE` | see above |
| `type`, `category`, `object_relation`, `comment`, `value` | attribute | string | `= IN LIKE` | `value` matches both value fields |
| `to_ids` | attribute | boolean | `=` | |
| `object_name` | object | string | `= IN LIKE` | such as `domain-ip` |
| `object_template_uuid` | object | string | `= IN` | |

Example: events of the last 30 days holding a `btc` attribute or a
`bank-account` object, not tagged `tlp:red`, without their `tlp:red`
attributes:

```json
{
  "query": {
    "AND": [
      {"date": {">=": "30d"}},
      {"OR": [{"type": "btc"}, {"object_name": "bank-account"}]},
      {"tags": {"!=": "tlp:red"}}
    ]
  },
  "limit": 20
}
```

`order` works as before, with the legacy names: `id`, `info`, `analysis`,
`threat_level_id`, `distribution`, `timestamp` and `publish_timestamp`. When
`query` is present, an unknown or malformed `order` is rejected as on
attributes. As there, an `order` that does not sort by `id` is completed with
`id` in the direction of its last field, so pages never overlap or skip
events, and without `order` events come in the database's order.

## Objects

`POST /objects/restSearch`. The tree selects objects, and each one is
returned as it would be without `query`, with the attributes of it the user
may see.

- Object and event fields are conditions on the object and on its event, and
  can be negated freely.
- Attribute fields select an object that holds at least one attribute that
  matches, is not deleted and is visible to the user. They take positive
  operators only, as on events.
- `tags` selects an object whose event carries the tag, or that holds a
  visible, non-deleted attribute carrying it. Negated (`!=`, `NOT IN`,
  `NOT LIKE`), it excludes the objects whose event carries a matching tag as
  an event tag and strips the attributes carrying one from the objects
  returned; an object left without attributes is still returned. A negated
  `tags` is only allowed under `AND`, as on events.
- Objects cannot be sorted: an `order` next to `query` is rejected with
  HTTP 400. Without `query`, `order` is ignored, as it always was.
- `"returnFormat": "count"` returns the number of matching objects as the
  body and in `X-Result-Count`, counted in the database, with legacy filters
  or `query`; `limit` and `page` are ignored. A plain request does not
  compute a total: its `X-Result-Count` is the number of objects returned.

| Field | Level | Type | Operators | Notes |
|---|---|---|---|---|
| `id`, `object_id` | object | integer | `= != > < >= <= IN NOT IN` | the same |
| `distribution` | object | integer | same | |
| `timestamp` | object | timestamp | same | object timestamp |
| `uuid` | object | string | `= != IN NOT IN` | |
| `object_name` | object | string | `= != IN NOT IN LIKE NOT LIKE` | such as `domain-ip` |
| `object_template_uuid` | object | string | `= != IN NOT IN` | |
| `event_id`, `threat_level_id` | event | integer | `= != > < >= <= IN NOT IN` | |
| `orgc_id` | event | integer | same | creator organisation |
| `event_timestamp`, `publish_timestamp` | event | timestamp | same | |
| `date` | event | date | same | |
| `published` | event | boolean | `= !=` | |
| `eventinfo` | event | string | `= != IN NOT IN LIKE NOT LIKE` | info of the event |
| `org` | event | string | `= != IN NOT IN` | name, uuid or id of the creator organisation |
| `tags` | event, attribute | string | `= != IN NOT IN LIKE NOT LIKE` | see above |
| `type`, `category`, `object_relation`, `comment`, `value` | attribute | string | `= IN LIKE` | `value` matches both value fields |
| `to_ids` | attribute | boolean | `=` | |

Example: `domain-ip` and `url` objects from events changed in the last week,
holding a value under `example.com`:

```json
{
  "query": {
    "AND": [
      {"object_name": {"IN": ["domain-ip", "url"]}},
      {"event_timestamp": {">=": "7d"}},
      {"value": {"LIKE": "%.example.com"}}
    ]
  }
}
```

## Galaxy clusters

`POST /galaxy_clusters/restSearch`. The tree selects the clusters the user
can see, returned as they would be without `query`.

- Text fields compare case-insensitively.
- `galaxy_*` fields are conditions on the cluster's galaxy; `org` is the
  cluster's creator organisation, by name in any case or by uuid (its id is
  `orgc_id`). `MISP` is reserved for the default clusters the MISP project
  maintains (creator `0`, shown as the MISP organisation): `org = 'MISP'`
  selects them, and an organisation of that name if there is one.
- `order` works as on attributes, also without `query`: the sortable fields
  are `id`, `version`, `type`, `value`, `distribution`, `orgc_id`, `org_id`,
  `tag_name` and `galaxy_id`.
- `"returnFormat": "count"` returns the number of matching clusters as the
  body, counted in the database, with legacy filters or `query`. A plain
  request does not compute a total.

| Field | Level | Type | Operators | Notes |
|---|---|---|---|---|
| `id`, `version`, `distribution`, `org_id`, `orgc_id`, `galaxy_id`, `extends_version` | galaxy_cluster | integer | `= != > < >= <= IN NOT IN` | |
| `default`, `locked`, `published`, `deleted` | galaxy_cluster | boolean | `= !=` | |
| `uuid`, `collection_uuid`, `extends_uuid` | galaxy_cluster | string | `= != IN NOT IN` | |
| `type`, `value`, `tag_name`, `description`, `source`, `authors` | galaxy_cluster | string | `= != IN NOT IN LIKE NOT LIKE` | `authors` is the JSON list as stored |
| `org` | galaxy_cluster | string | `= != IN NOT IN` | name or uuid of the creator organisation |
| `galaxy_uuid` | galaxy | string | `= != IN NOT IN` | |
| `galaxy_name`, `galaxy_namespace` | galaxy | string | `= != IN NOT IN LIKE NOT LIKE` | |
| `meta.<key>` | galaxy_element | string | `= != IN NOT IN LIKE NOT LIKE` | one of the cluster's own meta values (`galaxy_elements`) under that key |

`meta.<key>` takes any key after `meta.`, dots and spaces included
(`meta.synonyms`, `meta.access_privilege.rule_effect`); keys and values
compare case-insensitively. A cluster matches when one of its elements has
that key and a matching value, so a negation (`!=`, `NOT IN`, `NOT LIKE`,
`NOT`) selects the clusters with no such element, including those without
the key. A key no cluster has is not an error: it matches nothing. Error
paths name the field `meta.<key>`, never the key sent.

Example: threat actors named after an APT whose description mentions China,
in reverse name order:

```json
{
  "query": {
    "AND": [
      {"galaxy_name": "Threat Actor"},
      {"value": {"LIKE": "apt%"}},
      {"description": {"LIKE": "%china%"}}
    ]
  },
  "order": "value desc"
}
```

## Event reports

`POST /event_reports/restSearch`. The body takes `query`, `page`, `limit`,
`order` and `returnFormat` only; other keys are ignored. Without `query` it
returns every report the user can see, as `/event_reports/index` does.

- The tree selects the reports the user can see: those of a visible event
  whose own distribution reaches the user. The organisation owning the event
  sees all of its reports.
- Deleted reports are left out unless the tree names `deleted`
  (`{"deleted": true}`). Users without the sync permission only ever get the
  deleted reports of their own organisation's events.
- Event fields are conditions on the report's event. `tags` selects a
  report that carries the tag or whose event does, matched as on attributes
  (see Wildcards); negated, neither of them carries it.
- `order` takes `id`, `event_id`, `name`, `timestamp` and `distribution`;
  anything else is rejected with HTTP 400, with or without `query`. Without
  `order` the reports come by `id`, and `id` breaks every tie, so pages
  never overlap.
- `"returnFormat": "count"` returns the number of matching reports as the
  body. A plain request does not compute a total.
- Each row is the report with its event (`Event`, with `Orgc` and `Org`),
  its sharing group when it has one, its analyst data and its own tags
  (`Tag`), under `EventReport`.

| Field | Level | Type | Operators | Notes |
|---|---|---|---|---|
| `id`, `event_id`, `distribution` | event_report | integer | `= != > < >= <= IN NOT IN` | |
| `timestamp` | event_report | timestamp | same | report timestamp |
| `deleted` | event_report | boolean | `= !=` | see above |
| `uuid` | event_report | string | `= != IN NOT IN` | |
| `name`, `content` | event_report | string | `= != IN NOT IN LIKE NOT LIKE` | `content` is the Markdown as stored; matching it reads every visible report |
| `tags` | event_report, event | string | `= != IN NOT IN LIKE NOT LIKE` | see above |
| `org_id`, `orgc_id`, `threat_level_id`, `analysis` | event | integer | `= != > < >= <= IN NOT IN` | owner and creator organisation |
| `event_timestamp`, `publish_timestamp` | event | timestamp | same | |
| `date` | event | date | same | |
| `published` | event | boolean | `= !=` | |
| `eventinfo` | event | string | `= != IN NOT IN LIKE NOT LIKE` | info of the event |
| `org` | event | string | `= != IN NOT IN` | name, uuid or id of the creator organisation |

Example: reports of the last month's published events marked `tlp:clear`,
newest first:

```json
{
  "query": {
    "AND": [
      {"tags": "tlp:clear"},
      {"published": true},
      {"date": {">=": "30d"}}
    ]
  },
  "order": "timestamp desc",
  "limit": 20
}
```

## Analyst data

`POST /analyst_data/restSearch/Note`, `/Opinion` and `/Relationship`, one
endpoint per type. The body takes `query`, `page`, `limit`, `order` and
`returnFormat` only; other keys are ignored. Without `query` it returns every
record of that type the user can see, as `/analyst_data/index/<Type>` does.
Workspaces cannot be searched.

- The tree selects the records the user can see: those held by the user's
  organisation, and those whose own distribution reaches the user. Whether
  the user can see the record they are attached to is not checked, as in
  the index; the target is therefore matched by its address
  (`object_type`, `object_uuid`, `object_sha256`) only.
- `order` takes `id`, `created`, `modified` and `distribution`, plus
  `opinion` on opinions and `relationship_type` on relationships; anything
  else is rejected with HTTP 400, with or without `query`. Without `order`
  the records come by `id`, and `id` breaks every tie.
- `"returnFormat": "count"` returns the number of matching records as the
  body. A plain request does not compute a total.
- Each row is the record as the index returns it, under its type (`Note`,
  `Opinion`, `Relationship`): its organisations (`Orgc`, `Org`) when known
  locally, its sharing group when the user can see it, and on relationships
  the related record as the user sees it (`related_object`, empty when
  hidden).

| Field | Types | Type | Operators | Notes |
|---|---|---|---|---|
| `id`, `distribution` | all | integer | `= != > < >= <= IN NOT IN` | |
| `created`, `modified` | all | datetime | same | see Types |
| `locked` | all | boolean | `= !=` | |
| `uuid`, `object_type`, `object_uuid`, `org_uuid`, `orgc_uuid` | all | string | `= != IN NOT IN` | `org_uuid` holds the record locally, `orgc_uuid` created it |
| `object_sha256` | all | string | `= != IN NOT IN` | a value target, in any case |
| `org` | all | string | `= != IN NOT IN` | name in any case, or uuid, of the creator organisation |
| `authors` | all | string | `= != IN NOT IN LIKE NOT LIKE` | |
| `note`, `language` | notes | string | same | |
| `opinion` | opinions | integer | `= != > < >= <= IN NOT IN` | |
| `comment` | opinions | string | `= != IN NOT IN LIKE NOT LIKE` | |
| `relationship_type` | relationships | string | same | |
| `related_object_type`, `related_object_uuid`, `related_object_sha256` | relationships | string | `= != IN NOT IN` | the related record's address |

Example: the opinions below 50 on one event, created this month:

```json
{
  "query": {
    "AND": [
      {"object_uuid": "5f1b2c3d-..."},
      {"opinion": {"<": 50}},
      {"created": {">=": "2026-11-01"}}
    ]
  },
  "order": "opinion"
}
```

## Collections

`POST /collections/restSearch`. The body takes `query`, `page`, `limit`,
`order` and `returnFormat` only; other keys are ignored. Without `query` it
returns every collection the user can see, as `/collections/index` does.

- The tree selects the collections the user can see: those held by the
  user's organisation, those with distribution 1, 2 or 3, and those shared
  with a sharing group the user's organisation belongs to. Whether the user
  can see an element's target is not checked, as in the index; elements are
  therefore matched by their address and description only.
- An element field matches when any element of the collection does; two
  element conditions need not hold for the same element. A negation selects
  the collections with no such element, including the empty ones:
  `{"NOT": {"element_type": {"IN": ["Event", "GalaxyCluster", "Attribute",
  "Object", "AttributeValue"]}}}` selects the empty collections.
- `name`, `type`, `description` and `element_description` compare
  case-insensitively. `org` is the creator organisation, by name in any case
  or by uuid (its id is `orgc_id`); `org_id` holds the collection on this
  instance. `modified` also changes when an element is added or removed.
- `order` takes `id`, `name`, `type`, `created`, `modified` and
  `distribution`; anything else is rejected with HTTP 400, with or without
  `query`. Without `order` the collections come by `id`, and `id` breaks
  every tie.
- `"returnFormat": "count"` returns the number of matching collections as
  the body. A plain request does not compute a total.
- Each row is the collection as the index returns it: under `Collection`,
  with its element count and analyst data; its creator (`Orgc`); its
  sharing group when its distribution is 4; and all its elements
  (`CollectionElement`).

| Field | Level | Type | Operators | Notes |
|---|---|---|---|---|
| `id`, `distribution`, `org_id`, `orgc_id`, `user_id` | collection | integer | `= != > < >= <= IN NOT IN` | `user_id` created it |
| `created`, `modified` | collection | datetime | same | see Types |
| `locked` | collection | boolean | `= !=` | a copy received through synchronisation |
| `uuid` | collection | string | `= != IN NOT IN` | |
| `name`, `type`, `description` | collection | string | `= != IN NOT IN LIKE NOT LIKE` | `type` is `campaign`, `intrusion_set`, `named_threat`, `research` or `other` |
| `org` | collection | string | `= != IN NOT IN` | name in any case, or uuid, of the creator organisation |
| `element_type`, `element_uuid` | collection_element | string | `= != IN NOT IN` | type `Event`, `GalaxyCluster`, `Attribute`, `Object` or `AttributeValue` |
| `element_sha256` | collection_element | string | `= != IN NOT IN` | an `AttributeValue` element, in any case |
| `element_description` | collection_element | string | `= != IN NOT IN LIKE NOT LIKE` | |

Example: the campaign collections holding one event, last changed first:

```json
{
  "query": {
    "AND": [
      {"type": "campaign"},
      {"element_uuid": "5f1b2c3d-..."}
    ]
  },
  "order": "modified desc"
}
```

## Tags

`POST /tags/restSearch`. The body takes `query`, `page`, `limit`, `order`
and `returnFormat` only; other keys are ignored. Without `query` it returns
every tag, as `/tags/index` does.

- The tree selects among all tags: the index shows every tag to every user,
  including hidden ones and those restricted to another organisation or
  user, so the tree can reach them too.
- `name` compares case-insensitively; `colour` matches exactly but in any
  case. `org_id` and `user_id` restrict the tag to that organisation or
  user, 0 meaning no restriction.
- `numerical_value` is the tag's own value. A user's override (the
  `tag_numerical_value_override` setting) is not searched: the row shows
  the overriding value, and the tag's own as `original_numerical_value`.
- `order` takes `id`, `name` and `numerical_value`; anything else is
  rejected with HTTP 400, with or without `query`. Without `order` the
  tags come by `id` (the index sorts by name), and `id` breaks every tie.
- `"returnFormat": "count"` returns the number of matching tags as the
  body. A plain request does not compute a total.
- Each row is the tag as the index returns it, under `Tag`: its columns,
  `favourite` (the user's own), `Taxonomy` when the tag is an entry of an
  enabled taxonomy, `count` (the events the user can see that carry it) and
  `attribute_count` (every attribute carrying it). None of these can be
  searched or sorted on.

| Field | Level | Type | Operators | Notes |
|---|---|---|---|---|
| `id`, `org_id`, `user_id`, `numerical_value` | tag | integer | `= != > < >= <= IN NOT IN` | |
| `name` | tag | string | `= != IN NOT IN LIKE NOT LIKE` | |
| `colour` | tag | string | `= != IN NOT IN` | `#rrggbb`, in any case |
| `exportable`, `hide_tag`, `is_galaxy`, `is_custom_galaxy`, `local_only` | tag | boolean | `= !=` | |

Example: the visible galaxy tags with an ATT&CK name, by name:

```json
{
  "query": {
    "AND": [
      {"is_galaxy": true},
      {"hide_tag": false},
      {"name": {"LIKE": "misp-galaxy:mitre-attack-pattern=%"}}
    ]
  },
  "order": "name"
}
```

## Organisations

`POST /organisations/restSearch`. The body takes `query`, `page`, `limit`,
`order` and `returnFormat` only; other keys are ignored. Without `query` it
returns every organisation, as `/organisations/index/scope:all` does.

- The tree selects among all organisations, local and external (`local`).
  When `Security.hide_organisation_index_from_users` hides the index from
  roles without the sharing group permission, both endpoints refuse those
  roles with HTTP 403 as well.
- `name` and the other text fields compare case-insensitively; `uuid`
  matches exactly, in any case. The creator (`created_by`), the user count
  and `restricted_to_domain` cannot be searched.
- `order` takes `id`, `name`, `date_created` and `date_modified`; `name`
  sorts case-insensitively, as on the index. Anything else is rejected with
  HTTP 400, with or without `query`. Without `order` the organisations come
  by `id` (the index sorts by name), and `id` breaks every tie.
- `"returnFormat": "count"` returns the number of matching organisations as
  the body. A plain request does not compute a total.
- Each row is the organisation as the index returns it, under
  `Organisation`, with its `user_count`; for a site admin also `created_by`
  and `created_by_email`.

| Field | Level | Type | Operators | Notes |
|---|---|---|---|---|
| `id` | organisation | integer | `= != > < >= <= IN NOT IN` | |
| `date_created`, `date_modified` | organisation | datetime | same | see Types |
| `local` | organisation | boolean | `= !=` | an organisation of this instance |
| `uuid` | organisation | string | `= != IN NOT IN` | |
| `name`, `type`, `nationality`, `sector`, `description`, `contacts`, `landingpage` | organisation | string | `= != IN NOT IN LIKE NOT LIKE` | |

Example: the external organisations of the financial sector, by name:

```json
{
  "query": {
    "AND": [
      {"local": false},
      {"sector": {"IN": ["Financial", "Banking"]}}
    ]
  },
  "order": "name"
}
```

## Limits

Checked before the database is touched. Server settings (all in the `MISP`
section, administrator-level):

| Setting | Default | Limits |
|---|---|---|
| `MISP.complex_query_max_depth` | 5 | nesting depth of the tree |
| `MISP.complex_query_max_nodes` | 50 | operators plus conditions |
| `MISP.complex_query_max_list` | 100 | operands of one `IN` / `NOT IN` |
| `MISP.complex_query_max_value_length` | 1024 | length of one string value |

## Errors

An invalid query is rejected as a whole with HTTP 400; nothing is partially
applied.

```json
{
  "name": "Invalid query",
  "message": "2 errors",
  "url": "/attributes/restSearch",
  "errors": [
    {"path": "query.AND[1].OR[0]", "code": "unknown_field", "message": "unknown field"},
    {"path": "query.AND[0].id", "code": "bad_type", "message": "this field expects an integer"}
  ]
}
```

| Code | Meaning |
|---|---|
| `unknown_field` | not a whitelisted field (path shows `<unknown>`), or an unknown sort field |
| `unknown_operator` | operator not allowed for the field, including a negated attribute or object field on events and objects |
| `bad_type` | wrong value type, malformed `LIKE`, or a value the field cannot use |
| `bad_shape` | malformed node, empty list, extra keys; on events and objects also a `NOT` over an attribute, object or tag field, or a negated `tags` outside an `AND` |
| `limit_exceeded` | depth, node, list or value length limit |

Paths are built from indices and field names only. Messages are fixed texts;
nothing the client sent is echoed back. At most 10 errors are reported.
Missing permission is not part of this format: it is a plain HTTP 403.

## Discovery

`GET /attributes/queryDescribe`, `GET /events/queryDescribe`,
`GET /objects/queryDescribe`, `GET /galaxy_clusters/queryDescribe`,
`GET /event_reports/queryDescribe`, `GET /analyst_data/queryDescribe/<Type>`
`GET /collections/queryDescribe`, `GET /tags/queryDescribe` and
`GET /organisations/queryDescribe` (API only, same permission as `query`)
return the fields of that endpoint,
their types and operators, the sortable fields and the limits in effect. A
field's `level` says what it is matched against: `attribute`, `object`,
`event`, `galaxy_cluster`, `galaxy`, `event_report`, `note`, `opinion`,
`relationship`, `collection`, `collection_element`, `tag` or
`organisation`, or more than one
(`tags`). On events and
objects, a field whose only level is `attribute` (or `object`, on events) is
matched against the elements inside the record and takes positive operators
only. `sortable` is empty for objects.

```json
{
  "tables": {
    "attributes": {
      "endpoint": "/attributes/restSearch",
      "fields": {
        "id": {"type": "int", "operators": ["=", "!=", ">", "<", ">=", "<=", "IN", "NOT IN"], "level": ["attribute"]},
        "published": {"type": "bool", "operators": ["=", "!="], "level": ["event"]}
      },
      "sortable": ["id", "event_id", "...", "Event.publish_timestamp"]
    }
  },
  "limits": {"max_depth": 5, "max_nodes": 50, "max_list": 100, "max_value_length": 1024}
}
```

## Performance

An `OR` whose branches share no index, or a `NOT` over tags, cannot be driven
by an index and may scan every attribute the user can see when matches are
rare. Anchoring such a tree with an `event_id`, `timestamp` or other selective
condition in an enclosing `AND` keeps it bounded.

On events and objects, each attribute, object or tag field is a subquery over
the attributes (or objects) the user can see, so a leaf matching a large
share of them, such as a common `category`, is the expensive part of a tree.
