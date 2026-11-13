# Complex queries in restSearch

`POST /attributes/restSearch`, `POST /events/restSearch`,
`POST /objects/restSearch` and `POST /galaxy_clusters/restSearch` accept an
additional `query` key carrying a boolean tree of field conditions, so that
requests such as `type = "domain" OR (id > 50000 AND tags = "tlp:white")` can
be expressed. Requests without `query` behave exactly as before.

The grammar, operators, limits and errors are the same on every endpoint.
What differs is the list of fields and what the tree selects: see
[Attributes](#attributes), [Events](#events), [Objects](#objects) and
[Galaxy clusters](#galaxy-clusters).

## Availability

- Only on the restSearch endpoints above, and only as a JSON object in
  the body of a `POST` request. A `query` in the query string or the URL (also
  next to one in the body), in a `GET` request or of any other type is
  rejected with HTTP 400. Other endpoints that take restSearch filters, such
  as the `filters` of `/sightings/add`, reject a `query` with HTTP 400 as well.
- The user's role needs the **Complex query** permission
  (`perm_complex_query`, off for every role by default), unless the user is
  a site admin. Without it the request is answered with HTTP 403.
- `query` can be combined with the legacy filters. The result is
  `ACL AND legacy filters AND query`: the tree can only narrow what the user
  is allowed to see anyway, never widen it.
- `returnFormat` and the other output parameters work as usual. `query` only
  selects which attributes, events or objects are returned; on events and
  objects, a negated `tags` also strips the attributes carrying the tag.

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
| `>`, `<`, `>=`, `<=` | numeric, timestamp and date fields only |
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
of days (`"30d"`); `h`, `m` and `s` are rejected there.

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
`object_template_uuid` on objects, and `description`, `version`,
`extends_uuid` and `extends_version` on galaxy clusters can be NULL. Inside a `query`, `!=`,
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
`org`, `org_id` and `orgc_id` are the cluster's own organisations.

## Attributes

`POST /attributes/restSearch`. The tree selects attributes.

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
`query` it is silently dropped, as it always was.

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
attributes.

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
  `orgc_id`).
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
`GET /objects/queryDescribe` and `GET /galaxy_clusters/queryDescribe` (API
only, same permission as `query`) return the fields of that endpoint, their
types and operators, the sortable fields and the limits in effect. A field's
`level` says what it is matched against: `attribute`, `object`, `event`,
`galaxy_cluster` or `galaxy`, or more than one (`tags`). On events and
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
