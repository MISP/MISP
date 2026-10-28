# Complex queries in attribute restSearch

`POST /attributes/restSearch` accepts an additional `query` key carrying a
boolean tree of field conditions, so that requests such as
`type = "domain" OR (id > 50000 AND tags = "tlp:white")` can be expressed.
Requests without `query` behave exactly as before.

## Availability

- Only on `/attributes/restSearch`, and only as a JSON object in the body of a
  `POST` request. A `query` in the query string, in a `GET` request or of any
  other type is rejected with HTTP 400.
- The user's role needs the **Complex query** permission
  (`perm_complex_query`, off for every role by default). Without it the
  request is answered with HTTP 403.
- `query` can be combined with the legacy filters. The result is
  `ACL AND legacy filters AND query`: the tree can only narrow what the user
  is allowed to see anyway, never widen it.
- `returnFormat` and the other output parameters work as usual; `query` only
  selects which attributes are returned.

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

Example:

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
| `>`, `<`, `>=`, `<=` | numeric and timestamp fields only |
| `IN`, `NOT IN` | operand is a non-empty list |
| `LIKE` | string fields only; see below |

`!=` and `NOT IN` are shorthand for `NOT` over `=` and `IN`.

### Types

Types are strict, nothing is coerced: strings for string fields, JSON integers
for numeric fields (`"50000"` for `id` is an error) and `true`/`false` for
booleans. Timestamp fields take an integer (Unix time) or a relative string
made of digits and one of `d`, `h`, `m`, `s` (`"7d"` is seven days ago).

### Wildcards

Wildcards are only available through `LIKE`, with a leading and/or trailing
`%` and nothing else (`%evil`, `evil%`, `%evil%`). `=`, `!=`, `IN` and
`NOT IN` values starting or ending with `%` are rejected, so these operators
always compare literally.

### NULL handling

`object_relation` and `comment` can be NULL. Inside a `query`, `!=`, `NOT IN`
and `NOT` also match rows where the column is NULL. The legacy filters (for
example `object_relation: "!ip"`) do not. This difference is intentional.

## Fields

| Field | Type | Operators | Notes |
|---|---|---|---|
| `id`, `event_id`, `object_id`, `distribution` | integer | `= != > < >= <= IN NOT IN` | |
| `threat_level_id` | integer | same | of the event |
| `timestamp` | timestamp | same | attribute timestamp |
| `event_timestamp`, `publish_timestamp` | timestamp | same | of the event |
| `to_ids` | boolean | `= !=` | |
| `published` | boolean | `= !=` | of the event |
| `uuid` | string | `= != IN NOT IN` | |
| `type`, `category`, `object_relation`, `comment`, `value` | string | `= != IN NOT IN LIKE` | `value` matches both value fields |
| `eventinfo` | string | `= != IN NOT IN LIKE` | info of the event |
| `tags` | string | `= != IN NOT IN` | attribute or event tag; negated means neither carries it (as in the legacy filter) |
| `org` | string | `= != IN NOT IN` | name, uuid or id of the event's creator organisation, as in the legacy filter |

Anything not listed is rejected as `unknown_field`. The same list is
available programmatically, see [Discovery](#discovery).

## Ordering

`order` works as before (`"timestamp desc"`, `["type", "id desc"]`). The
sortable fields are the attribute fields `id`, `event_id`, `object_id`,
`type`, `category`, `value`, `distribution`, `timestamp`, `object_relation`
and `Event.publish_timestamp`. When `query` is present, an unknown or
malformed `order` is rejected with an error at path `order[i]`; without
`query` it is silently dropped, as it always was.

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
| `unknown_field` | not a whitelisted field (path shows `<unknown>`) |
| `unknown_operator` | operator not allowed for the field |
| `bad_type` | wrong value type, malformed `LIKE`, or a value the field cannot use |
| `bad_shape` | malformed node, empty list, extra keys |
| `limit_exceeded` | depth, node, list or value length limit |

Paths are built from indices and field names only. Messages are fixed texts;
nothing the client sent is echoed back. At most 10 errors are reported.
Missing permission is not part of this format: it is a plain HTTP 403.

## Discovery

`GET /attributes/queryDescribe` (API only) returns the fields, their types and
operators, the sortable fields and the limits in effect:

```json
{
  "tables": {
    "attributes": {
      "endpoint": "/attributes/restSearch",
      "fields": {"id": {"type": "int", "operators": ["=", "!=", ">", "<", ">=", "<=", "IN", "NOT IN"]}},
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
