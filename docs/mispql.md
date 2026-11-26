# MispQL

MispQL is an SQL-like language for searching MISP:

```sql
SELECT id, event_id, type, value FROM attributes
WHERE type IN ('domain', 'ip-dst') AND timestamp >= '7d' AND tags != 'tlp:red'
LIMIT 50 FORMAT table
```

MISP parses the statement, checks it, compiles it into one request to the
table's restSearch endpoint, with the conditions as the boolean `query` tree
described in [Complex queries in restSearch](restsearch-complex-query.md),
and runs that request as the user. The statement above is this request:

```
POST /attributes/restSearch
{
  "returnFormat": "json",
  "limit": 50,
  "page": 1,
  "query": {
    "AND": [
      {"type": {"IN": ["domain", "ip-dst"]}},
      {"timestamp": {">=": "7d"}},
      {"tags": {"!=": "tlp:red"}}
    ]
  }
}
```

A statement sees exactly what its user may see through any other API call:
conditions can only narrow that, never widen it. MispQL only reads; no
statement writes to MISP. What the query console does with rows, such as
adding them to a collection, goes through MISP's own controls, under their
own permissions.

This page describes MispQL 1.0, the language that
[mispql](https://github.com/MISP/MispQL), the command-line client, speaks as
well. Every reply carries the version as `"language": "1.0"`.

- [Where to use it](#where-to-use-it)
- [Access](#access)
- [The query console](#the-query-console)
- [The API](#the-api): [explain](#post-mispqlexplain), [run](#post-mispqlrun),
  [errors](#errors)
- [The language](#the-language): [statements](#statements),
  [conditions](#conditions), [columns](#columns),
  [sorting and paging](#sorting-and-paging), [output](#output),
  [counting](#counting), [discovery](#discovery)
- [Tables](#tables)
- [Limits](#limits)
- [Large events and performance](#large-events-and-performance)

## Where to use it

- **The query console**, at `/mispql`, listed as **Query console** in the
  **API** menu: a writer that checks statements as you type and suggests what
  fits, with the result underneath. See [The query console](#the-query-console).
- **The API**: `POST /mispql/explain` checks statements and returns what they
  compile to, without reading data; `POST /mispql/run` runs one statement. See
  [The API](#the-api).
- **[mispql](https://github.com/MISP/MispQL)**, the command-line client, for an
  interactive prompt and for shell scripts.

## Access

- The user's role needs the **Complex query** permission
  (`perm_complex_query`). Every role has it unless an administrator unticks
  it, and site admins always have it. Without it the console, `/mispql/explain`
  and `/mispql/run` answer HTTP 403, and the console is not listed in the menu.
- Each table keeps the access rules of its own endpoint: a search or a count
  needs access to the table's `restSearch`, `DESCRIBE` to its
  `queryDescribe`, and `SHOW TABLES` lists only the tables whose
  `queryDescribe` the user may call. When an instance hides the organisation
  index from a role, the `organisations` table answers HTTP 403 to it, as the
  index does.
- A statement runs as the user, through the same code as restSearch: the
  same access rules, the same export modules and the role's restSearch limit.
  When that limit, rather than the statement's `LIMIT`, ends a search, the
  reply says so in a warning.

## The query console

`/mispql` holds a writer on top, the result of the last statement run below
it, and a side list with two tabs, **History** and **Tables**.

- **The writer** colours the text, and MISP checks it as you type: a mistake
  is underlined where it is, with the reason on hover and in the line under
  the writer, before anything runs. Suggestions fit the position: the tables
  after `FROM`, the table's fields after `WHERE` with what each means, only
  the operators a field takes, `TRUE` and `FALSE` after a boolean field,
  MISP's attribute types, categories and levels after `=`, names looked up
  as you type for tags, organisations, galaxies and clusters, the sort names
  after `ORDER BY`, the table's formats after `FORMAT`. Resting the pointer
  on a table, a field or a column shows what it means, its type and the
  operators it takes.
- **Run** runs the statement under the caret. The writer can hold several
  statements separated by `;`.
- **Explain** shows what the statement under the caret compiles to, without
  running it: the request MISP would send, what comes back, the columns, and
  the API call as `/mispql/explain`, `/mispql/run`, the restSearch request,
  curl and PyMISP.
- **The result** is rows in a grid with a pager, a count, a table's fields
  for `DESCRIBE`, the tables for `SHOW TABLES`, the user for `WHOAMI`, or
  MISP's export as a preview and a download. Rows can also be seen as JSON
  (`SELECT *` without a `FORMAT`) or as CSV (`FORMAT flat`). **Download**
  saves the page shown: first as it ran (JSON without a `FORMAT`, CSV for
  `table` and `flat`), or as CSV or JSON. A refused statement shows its
  errors on the text; a click on one selects it in the writer. **API call**
  shows the request behind a result.
- **In the grid**, an id or a value opens its record or its value page in a
  new tab, and tags show as on the events index, +N listing them all. A
  cell's funnel adds a condition on its value to the statement and runs it
  (keep only this, leave it out, and on times and numbers from it on or up
  to it), or copies the value; Ctrl+Z in the writer gives the previous
  statement back. A column header sorts by that column, Shift+click adding
  it as a further key.
- **Opened in place.** A caret beside a link opens the record in the view
  MISP has for it elsewhere: an object with its attributes, as the workspace
  shows it; an event's peek and a sharing group's, as the indexes show
  them; a value's hover card, where the instance has it on; a report in the
  event page's reader; a collection's members, as its page lists them. The
  event, sharing group and collection views need the Overmind theme. The
  cell's funnel offers the same first, for the keyboard.
- **Acting on rows.** On attributes, events, objects and galaxy clusters,
  ticking rows shows a bar that adds them to your workspace, to another
  collection or to a new one (see
  [Workspace and saved graphs](workspace-and-saved-graphs.md)); it acts on
  the rows the grid shows, at most 500. With the workspace dock open beside
  it, the console gives the dock its side of the window.
- **History** lists the last 50 statements the user ran, from any device. A
  statement run earlier on the page shows its result again without asking
  MISP, marked with the time it ran.
- **Tables** lists the tables the user may query, with their fields, their
  types and what each means; a click on a field inserts it at the caret.
- `/mispql?q=<statement>` opens the console with that statement in the
  writer. Otherwise the writer opens on the user's last draft, kept in the
  browser. Nothing runs until asked.

| Key | |
|---|---|
| Ctrl+Enter | run the statement under the caret |
| Ctrl+Shift+Enter | explain the statement under the caret |
| Ctrl+Space | show suggestions |
| ↑ ↓, Enter or Tab, Esc | in the suggestions: choose, insert, close |
| ↑ ↓ in an empty writer | step through History |
| Tab | from the writer on to the result; the grid is one stop |
| Arrows, Home, End | in the grid: move between cells and up to the headers |
| Enter | on a cell, its menu; on a header, sort by it (Shift+Enter adds it as a further key) |
| Space | in the checkbox column: tick the row (Shift+Space: the rows between) |
| Ctrl+Enter on a cell | open its link in a new tab |
| Esc | close a cell's menu or a view opened in place, back to the cell |
| ← → on History or Tables | switch between the two tabs |

On macOS, Cmd works in place of Ctrl.

## The API

Both endpoints take a JSON body by `POST` and answer JSON. They take the API
key in the `Authorization` header, like any other MISP API call:

```sh
curl -X POST https://misp.example.org/mispql/run \
  -H "Authorization: $MISP_KEY" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{"statement": "SELECT COUNT(*) FROM events WHERE published = TRUE"}'
```

A body without the expected key as a string is answered HTTP 400, and any
method other than `POST` HTTP 405.

### POST /mispql/explain

`{"script": "…"}`: one or more statements, separated by `;`. MISP parses and
compiles every statement and checks it against this instance (fields,
operators, types, [limits](#limits)), reading no data. The reply has one entry
per statement, or every error found (see [Errors](#errors)).

```
POST /mispql/explain
{"script": "SELECT COUNT(*) FROM events WHERE date >= '7d'; SELECT id, date, info FROM events WHERE date >= '7d' ORDER BY event_id DESC LIMIT 10 OFFSET 5 FORMAT table; USE test; DESCRIBE tags"}
```

```json
{
  "language": "1.0",
  "statements": [
    {"kind": "count", "start": 0, "end": 46, "validated": true, "table": "events",
     "request": {"method": "POST", "endpoint": "/events/restSearch",
                 "body": {"returnFormat": "json", "limit": 1, "page": 1, "metadata": 1,
                          "query": {"date": {">=": "7d"}}}}},
    {"kind": "search", "start": 48, "end": 154, "validated": true, "table": "events",
     "request": {"method": "POST", "endpoint": "/events/restSearch",
                 "body": {"returnFormat": "json", "metadata": 1, "limit": 10, "page": 1,
                          "order": ["id desc"], "query": {"date": {">=": "7d"}}}},
     "next_page": {"method": "POST", "endpoint": "/events/restSearch",
                   "body": {"returnFormat": "json", "metadata": 1, "limit": 10, "page": 2,
                            "order": ["id desc"], "query": {"date": {">=": "7d"}}}},
     "output": "table", "columns": ["id", "date", "info"], "skip": 5},
    {"kind": "use", "start": 156, "end": 164, "validated": true, "database": "test"},
    {"kind": "describe", "start": 166, "end": 179, "validated": false, "table": "tags",
     "request": {"method": "GET", "endpoint": "/tags/queryDescribe"}}
  ]
}
```

| Key | |
|---|---|
| `kind` | `search`, `count`, `describe`, `show_tables`, `whoami`, `use` or `show_databases` |
| `start`, `end` | where the statement is in the script, in Unicode code points |
| `validated` | `false` for the statements after a `USE`: they are compiled but not checked, since they may be meant for another MISP |
| `table` | the table, for searches, counts and `DESCRIBE` |
| `request` | the request the statement compiles to: `method`, `endpoint` and, for `POST`, `body` |
| `next_page` | the second request an `OFFSET` that is not a multiple of the `LIMIT` may need (see [Sorting and paging](#sorting-and-paging)) |
| `output` | for searches: `default` (no `FORMAT`), `table`, `flat`, or `verbatim` for one of MISP's formats |
| `columns` | for searches: the column list, `null` for `*` |
| `skip` | for searches: the rows dropped from the first page for the `OFFSET` |
| `database` | for `USE` |

### POST /mispql/run

`{"statement": "…"}`: exactly one statement. MISP runs it and answers
according to its kind. A body holding more than one statement is refused
(`syntax`, "run takes one statement").

**A search** answers its rows:

```
POST /mispql/run
{"statement": "SELECT id, event_id, type, value FROM attributes WHERE type = 'domain' LIMIT 2"}
```

```json
{
  "language": "1.0",
  "kind": "search",
  "table": "attributes",
  "output": "default",
  "columns": ["id", "event_id", "type", "value"],
  "rows": [
    {"id": "3", "event_id": "1", "type": "domain", "value": "circl.lu"},
    {"id": "1", "event_id": "1", "type": "domain", "value": "google.com"}
  ],
  "records": [
    {"type": "Attribute", "id": "3", "uuid": "5e2a…", "label": "circl.lu"},
    {"type": "Attribute", "id": "1", "uuid": "9c41…", "label": "google.com"}
  ],
  "total": null,
  "warnings": [],
  "request": {"method": "POST", "endpoint": "/attributes/restSearch",
              "body": {"returnFormat": "json", "limit": 2, "page": 1, "query": {"type": "domain"}}}
}
```

- `rows`: the records MISP found, taken out of restSearch's envelope (one
  attribute, event, object… per row). With a column list, `FORMAT table` or
  `FORMAT flat`, they are flattened and cut to the columns (see
  [Columns](#columns)).
- `records`: the record behind each row, in the same order, whatever the
  columns: its `type` (`Attribute`, `Event`, `Object`, `GalaxyCluster`,
  `EventReport`, `Note`, `Opinion`, `Relationship`, `Collection`, `Tag` or
  `Organisation`), `id` and `uuid` (`null` for a tag). An attribute, event,
  object or cluster also has a `label`: its value, info, name or value.
  `"deleted": true` marks a deleted record. MISP added this key after
  mispql 1.0, which does not read it.
- `columns`: the columns of the rows, `null` for `SELECT *` without a
  `FORMAT`.
- `output`: as in `explain`. `table` and `flat` are drawn by the client: the
  console as a grid, mispql as a text table or CSV.
- `total`: on `events`, the number of matching events; `null` on the other
  tables.
- `warnings`: for instance "no row has a column nope", or the role's
  restSearch limit ending the search.
- `request`: the request that ran.

**A count**: `{"language": "1.0", "kind": "count", "table": "events",
"count": 4214, "request": {…}}`.

**`DESCRIBE`**: `table`; `fields`, each with its `type`, its `operators`,
its `level` (what it is matched against: the record, its event, its
attributes…) and its `description`, a sentence saying what it means;
`order_by`, the names `ORDER BY` takes; `limits`, the [limits](#limits) in
effect.

**`SHOW TABLES`**: `tables`, the names of the tables the user may query.

**`WHOAMI`**: the user's `email`, `role` and `org`.

**A search with one of MISP's formats** (`FORMAT csv`, `stix2`, `xlsx`, …)
answers MISP's export as restSearch sends it: its content type, the
`X-Export-Module-Used` header, and the file as an attachment.

**`USE` and `SHOW DATABASES`** are refused with `client_statement`: see
[Client statements](#client-statements).

`"remember": true` in the body adds the statement to the user's History in
the console; only the console sends it.

### Errors

A refused statement is answered HTTP 400 with MISP's error envelope:

```json
{
  "name": "Invalid query",
  "message": "1 error",
  "url": "/mispql/explain",
  "language": "1.0",
  "errors": [
    {
      "statement": 0,
      "start": 64,
      "end": 77,
      "code": "unknown_operator",
      "message": "attribute and object fields cannot be negated when searching events",
      "path": "query.AND[1].OR[1].type"
    }
  ]
}
```

for

```sql
SELECT * FROM events WHERE event_id > 0 AND (eventinfo = 'x' OR type != 'btc') LIMIT 1
```

- `statement`: the index of the statement in the script, from 0 (always 0 for
  `run`); `null` when the script could not be split into statements.
- `start`, `end`: the text the error is about, as offsets in Unicode code
  points from the start of the text sent, `end` excluded. An emoji counts as
  one.
- `code`: what kind of error, from the table below.
- `path`: for errors found in the compiled `query` tree, where in the tree.
- `message`: a fixed text. It never repeats what was sent: the position says
  what it is about.

`explain` reports the errors of every statement together, up to 10. A syntax
error is reported alone, with `statement` set to `null`: the script cannot be
split into statements past it.

| Code | |
|---|---|
| `syntax` | the text does not parse |
| `unknown_table` | no such table |
| `wrong_table` | a field qualified with another table than the one queried |
| `not_sortable` | not a sort name of this table, or a table that cannot be sorted |
| `bad_clause` | a clause the statement cannot take, such as `COUNT(*)` with a `LIMIT`, or a column list with one of MISP's formats |
| `missing_clause` | a clause the statement needs: a search without `WHERE` or `LIMIT`, `COUNT(*)` without `WHERE`, `OFFSET` without `LIMIT` |
| `limit_exceeded` | past one of the [limits](#limits) |
| `client_statement` | `USE` or `SHOW DATABASES`, which run in mispql |
| `unknown_field` | not a field of this table |
| `unknown_operator` | an operator the field does not take, or a negation the field does not allow there |
| `bad_type` | a value of the wrong type |
| `bad_shape` | a condition MISP cannot evaluate in this place |

The last four come from restSearch's own check of the `query` tree, so they
are the codes described in
[Complex queries in restSearch](restsearch-complex-query.md#errors). A user or
a table refused by the access rules gets a plain HTTP 403.

## The language

### Statements

```
SELECT * | COUNT(*) | column, ... FROM table
  [WHERE condition]
  [ORDER BY field [ASC | DESC], ...]
  [LIMIT n [OFFSET n]]
  [FORMAT word]
DESCRIBE table
SHOW TABLES
WHOAMI
USE database
SHOW DATABASES
```

- Keywords can be written in any case. Table and field names are
  case-insensitive. `DESC` is short for `DESCRIBE`.
- A name in backticks is taken as written: for a keyword used as a name
  (`` `count` ``), for a name with characters other than letters, digits and
  `_`, or to keep its case. The keywords are `AND`, `ASC`, `BY`, `COUNT`,
  `DATABASES`, `DESC`, `DESCRIBE`, `FALSE`, `FORMAT`, `FROM`, `IN`, `LIKE`,
  `LIMIT`, `NOT`, `OFFSET`, `OR`, `ORDER`, `SELECT`, `SHOW`, `TABLES`, `TRUE`,
  `USE`, `WHERE` and `WHOAMI`.
- Strings take single or double quotes; a doubled quote inside stands for one
  (`'O''Brien'`). Numbers are whole numbers, negative ones too, up to
  9223372036854775807 either way. A word starting with a digit, such as
  `'7d'`, needs quotes. `TRUE` and `FALSE` are booleans.
- Any Unicode space separates words, so a no-break space pasted from a web
  page does too.
- `--` starts a comment that runs to the end of the line.
- Statements are separated by `;`. The last one needs none.
- A search needs a `WHERE` or a `LIMIT`: MISP takes no search without either.

### Conditions

| Condition | Meaning |
|---|---|
| `field = value`, `field != value` | equals, does not equal (`<>` is the same as `!=`) |
| `<`, `>`, `<=`, `>=` | numbers, timestamps, dates and datetimes only |
| `field IN (v, ...)`, `field NOT IN (v, ...)` | one of the values, none of them |
| `field LIKE 'pattern'`, `field NOT LIKE 'pattern'` | text fields only; see [Patterns](#patterns) |
| `AND`, `OR`, `NOT`, `( )` | combine conditions |

`NOT` binds tighter than `AND`, and `AND` tighter than `OR`; parentheses
group. Each table's fields, with the operators each one takes, are listed by
[`DESCRIBE`](#discovery) and described in
[Complex queries in restSearch](restsearch-complex-query.md).

```sql
SELECT * FROM attributes
WHERE category = 'Network activity' AND (type = 'domain' OR type IN ('ip-src', 'ip-dst'))
  AND id > 50000
LIMIT 100
```

```
POST /attributes/restSearch
{
  "returnFormat": "json",
  "limit": 100,
  "page": 1,
  "query": {
    "AND": [
      {"category": "Network activity"},
      {"OR": [
        {"type": "domain"},
        {"type": {"IN": ["ip-src", "ip-dst"]}}
      ]},
      {"id": {">": 50000}}
    ]
  }
}
```

#### Values and types

Types are strict and nothing is converted: text fields take strings, numeric
fields numbers (`id = '50000'` is an error), booleans `TRUE` or `FALSE`.

- Timestamps (`timestamp`, `event_timestamp`, `publish_timestamp`, …) take a
  Unix time or a relative time: digits and one of `d`, `h`, `m`, `s`, so
  `'7d'` is seven days ago.
- Dates (`date`, the event date) take `'YYYY-MM-DD'` or a number of days
  (`'30d'`).
- Datetimes (`created` and `modified` on analyst data and collections,
  `date_created` and `date_modified` on organisations) take what timestamps
  take, or `'YYYY-MM-DD'` and `'YYYY-MM-DD HH:MM:SS'`.

```sql
SELECT * FROM events WHERE date >= '2026-01-01' AND publish_timestamp >= '12h' LIMIT 50
```

#### Patterns

`LIKE` takes a `%` at the start, the end or both (`'%evil'`, `'evil%'`,
`'%evil%'`), and nowhere else. `=` and `IN` compare literally: a value
starting or ending with `%` is refused there.

`tags` is the exception, as in MISP's classic tag filter: its value is always
matched against tag names as a pattern, `_` standing for any one character
and a `%` inside the value for any run of them, and a value of digits only is
a tag id.

```sql
SELECT * FROM attributes
WHERE tags LIKE 'tlp:%' AND tags NOT IN ('tlp:red', 'tlp:amber+strict') AND timestamp >= '1d'
LIMIT 100
```

#### Empty fields

Some fields can be empty (NULL), such as an attribute's `comment` or an
object's `object_name`. `!=`, `NOT IN`, `NOT LIKE` and `NOT` also match rows
where the field is empty: `comment NOT LIKE '%test%'` includes the attributes
without a comment.

### Columns

`SELECT *` returns whole records. A column list returns only those columns,
in that order:

- Nested values are reached with dots: `Event.info`, `Event.Orgc.name`.
- The names conditions use work as columns too, where the record holds the
  value: on attributes, `eventinfo` is the event's `info` and `org` its
  creator organisation's name. Each table's list is in [Tables](#tables). The
  column is named as the record names it (`Event.info`).
- `Tag` is one value: the tag names joined by commas.
- Columns match the record's keys in any case. A column no row has gets a
  warning, and no value.

```sql
SELECT id, type, value, Event.info, Event.Orgc.name, Tag FROM attributes
WHERE type = 'btc' LIMIT 20 FORMAT table
```

A keyword used as a column name goes in backticks, as the tag column `count`
does:

```sql
SELECT id, name, `count`, attribute_count FROM tags
WHERE is_galaxy = FALSE ORDER BY name LIMIT 20 FORMAT table
```

### Sorting and paging

`ORDER BY` takes one or more fields, each `ASC` (the default) or `DESC`. Each
table sorts by a fixed set of names, listed in [Tables](#tables) and by
`DESCRIBE`; objects cannot be sorted. A name the table does not sort by is
refused (`not_sortable`) before anything runs.

```sql
SELECT * FROM events WHERE published = TRUE
ORDER BY publish_timestamp DESC, event_id LIMIT 25 FORMAT table
```

`LIMIT n` asks for `n` rows, at least 1, and `OFFSET` skips rows before them;
restSearch pages by `limit` and `page`. An offset that is a multiple of the
limit is one page. Any other offset reads the page it starts in and, when that
page is full, the next one, and keeps the rows asked for: `LIMIT 10 OFFSET 15`
reads page 2 and, if needed, page 3, and returns rows 16 to 25. With one of
MISP's formats, which is sent as MISP produces it, the offset must be a
multiple of the limit.

### Output

| `FORMAT` | `/mispql/run` answers |
|---|---|
| none | `SELECT *`: the records as MISP returns them. A column list: flattened rows with those columns |
| `table` | flattened rows, for a client to draw as a table; without a column list, the table's [default columns](#tables) |
| `flat` | flattened rows, for a client to write as CSV; without a column list, every column the rows have, in the order first seen |
| any other word | one of MISP's export formats, passed as `returnFormat` and sent as MISP produces it: `csv`, `text`, `xlsx`, `stix2`, `suricata`, … |

**Flattening.** For a column list, `FORMAT table` and `FORMAT flat`, rows are
flattened: nested objects become dotted names (`Event.Orgc.name`), `Tag`
becomes one value of names, and every other list (an event's attributes and
objects, an object's attributes, galaxies, …) is left out. Those stay in
`SELECT *` and in MISP's own formats.

**MISP's formats.** Each table takes the formats its restSearch endpoint
knows (the console suggests them after `FORMAT`); MISP refuses the others. A
column list needs `FORMAT table`, `FORMAT flat` or no `FORMAT`. `FORMAT json`
is MISP's own JSON export, sent as a file.

A value written to CSV as it is can act as a formula when the file is opened
in a spreadsheet, if it starts with `=`; `FORMAT xlsx` is the safer choice
there.

```sql
SELECT * FROM attributes
WHERE type IN ('ip-src', 'ip-dst') AND to_ids = TRUE AND timestamp >= '30d'
LIMIT 1000 FORMAT csv
```

### Counting

`SELECT COUNT(*)` answers the number of records that meet the conditions,
counted by MISP; no rows are sent. It needs a `WHERE` and takes no
`ORDER BY`, `LIMIT`, `OFFSET` or `FORMAT`.

```sql
SELECT COUNT(*) FROM attributes WHERE type = 'domain' AND timestamp >= '30d'
```

Most tables are counted with restSearch's `count` format. Events are counted
by asking for one event without its attributes and taking the number of
matches restSearch found:

```
POST /events/restSearch
{"returnFormat": "json", "limit": 1, "page": 1, "metadata": 1, "query": {…}}
```

### Discovery

- `SHOW TABLES` lists the tables the user may query.
- `DESCRIBE table` (or `DESC`) lists the table's fields, each with its type,
  the operators it takes, its level (what it is matched against: the
  record itself, its event, its attributes, …) and what it means; the names
  `ORDER BY` takes; and the limits in effect. It reads the table's
  `queryDescribe`, as `GET /events/queryDescribe` for `DESCRIBE events`, and
  adds the sentences.
- `WHOAMI` answers the user's email, role and organisation.

The rules behind each field, table by table, are in
[Complex queries in restSearch](restsearch-complex-query.md).

### Client statements

`USE database` and `SHOW DATABASES` switch between MISP servers and accounts
in mispql, where a database is one MISP and one API key. MISP parses them, so
a mispql script can be checked whole by `/mispql/explain`: `USE` comes back
with its `database`, and the statements after it come back compiled but not
checked (`"validated": false`), since they may be meant for another MISP,
which checks them itself. `/mispql/run` and the console refuse them
(`client_statement`).

## Tables

Each table is one kind of MISP record, searched through one restSearch
endpoint. What a table can be searched by is listed by `DESCRIBE`, and each
field is described in
[Complex queries in restSearch](restsearch-complex-query.md); this section
gives what each table returns and how it behaves.

For each table:

- **Default columns**: the columns of `FORMAT table` without a column list.
- **ORDER BY**: the names it sorts by.
- **Field names as columns**: the condition names that also work as columns,
  and the column each one reads.

### attributes

Attributes, each with its event (`Event`, with the creator organisation under
`Event.Orgc`) and its tags. Event fields (`eventinfo`, `org`, `published`,
`event_timestamp`, …) are conditions on the attribute's event. `tags` matches
a tag on the attribute or on its event; negated, neither carries it.
[Fields](restsearch-complex-query.md#attributes).

- **Endpoint**: `POST /attributes/restSearch`
- **Default columns**: `id`, `event_id`, `category`, `type`, `value`, `to_ids`,
  `timestamp`, `Tag`
- **ORDER BY**: `id`, `event_id`, `object_id`, `type`, `category`, `value`,
  `distribution`, `timestamp`, `object_relation`, `publish_timestamp`
- **Field names as columns**: `eventinfo` → `Event.info`, `org` →
  `Event.Orgc.name`, `tags` → `Tag`, `event_timestamp` → `Event.timestamp`,
  `publish_timestamp` → `Event.publish_timestamp`, `threat_level_id` →
  `Event.threat_level_id`

```sql
SELECT id, value, Event.info FROM attributes
WHERE eventinfo LIKE '%phishing%' AND type IN ('url', 'domain') AND to_ids = TRUE
LIMIT 50 FORMAT table
```

### events

Events. Event fields are conditions on the event itself. Attribute fields
(`type`, `value`, `category`, …) and object fields (`object_name`,
`object_template_uuid`) select an event holding at least one matching
attribute or object that the user can see; they cannot be negated, so "events
without a `btc` attribute" cannot be asked.

`tags` selects an event carrying the tag, or holding an attribute that does.
Negated (`!=`, `NOT IN`, `NOT LIKE`), it leaves out the events tagged with it
and removes the matching attributes and event reports from the events
returned; it is allowed only where every enclosing condition is an `AND`.
[Fields](restsearch-complex-query.md#events).

- **Endpoint**: `POST /events/restSearch`
- **Default columns**: `id`, `date`, `info`, `Orgc.name`, `threat_level_id`,
  `analysis`, `published`, `attribute_count`, `Tag`
- **ORDER BY**: `id`, `event_id`, `eventinfo`, `analysis`, `threat_level_id`,
  `distribution`, `timestamp`, `event_timestamp`, `publish_timestamp`
- **Field names as columns**: `event_id` → `id`, `eventinfo` → `info`, `org`
  → `Orgc.name`, `event_timestamp` → `timestamp`, `tags` → `Tag`

```sql
SELECT id, info, Orgc.name, attribute_count FROM events
WHERE value = '198.51.100.23' AND published = TRUE
ORDER BY event_id DESC LIMIT 20 FORMAT table
```

### objects

Objects, each with the attributes of it the user can see. Object and event
fields can be negated freely; attribute fields select an object holding a
matching attribute and cannot be negated, and `tags` works as on events.
Objects cannot be sorted. [Fields](restsearch-complex-query.md#objects).

- **Endpoint**: `POST /objects/restSearch`
- **Default columns**: `id`, `event_id`, `name`, `meta-category`, `comment`,
  `timestamp`
- **ORDER BY**: none
- **Field names as columns**: `object_id` → `id`, `object_name` → `name`,
  `object_template_uuid` → `template_uuid`, `orgc_id` → `Event.orgc_id`

```sql
SELECT id, event_id, name, comment FROM objects
WHERE object_name IN ('domain-ip', 'url') AND event_timestamp >= '7d'
  AND value LIKE '%.example.com'
LIMIT 50 FORMAT table
```

### galaxy_clusters

Galaxy clusters, with their galaxy. Text fields compare without regard to
case. `galaxy_name`, `galaxy_namespace` and `galaxy_uuid` are conditions on
the cluster's galaxy; `org` is the creator organisation, by name or uuid, and
`'MISP'` selects the clusters the MISP project maintains.

`meta.<key>` matches the cluster's own meta values under that key, such as
`meta.synonyms` or `meta.country`. A key with characters other than letters,
digits and `_` goes in backticks. A negated condition selects the clusters
with no such value, including those without the key.
[Fields](restsearch-complex-query.md#galaxy-clusters).

- **Endpoint**: `POST /galaxy_clusters/restSearch`
- **Default columns**: `id`, `value`, `Galaxy.name`, `Orgc.name`,
  `distribution`, `default`
- **ORDER BY**: `id`, `version`, `type`, `value`, `distribution`, `orgc_id`,
  `org_id`, `tag_name`, `galaxy_id`
- **Field names as columns**: `org` → `Orgc.name`, `galaxy_uuid` →
  `Galaxy.uuid`, `galaxy_name` → `Galaxy.name`, `galaxy_namespace` →
  `Galaxy.namespace`

```sql
SELECT id, value, Galaxy.name FROM galaxy_clusters
WHERE galaxy_name = 'Threat Actor' AND org = 'MISP' AND meta.synonyms LIKE '%bear%'
ORDER BY value LIMIT 50 FORMAT table
```

### event_reports

Event reports, searched as children of their event: event fields use the
same names as on the other tables. `tags` matches a tag on the report or on
its event. Deleted reports are left out unless the conditions name `deleted`.
A condition on `content` reads the Markdown of every report the user can see.
[Fields](restsearch-complex-query.md#event-reports).

- **Endpoint**: `POST /event_reports/restSearch`
- **Default columns**: `id`, `event_id`, `name`, `Event.info`, `distribution`,
  `timestamp`, `Tag`
- **ORDER BY**: `id`, `event_id`, `name`, `timestamp`, `distribution`
- **Field names as columns**: `eventinfo` → `Event.info`, `org` →
  `Event.Orgc.name`, `org_id` → `Event.org_id`, `orgc_id` → `Event.orgc_id`,
  `date` → `Event.date`, `tags` → `Tag`

```sql
SELECT * FROM event_reports
WHERE tags = 'tlp:clear' AND published = TRUE AND date >= '30d'
ORDER BY timestamp DESC LIMIT 20 FORMAT table
```

### notes, opinions, relationships

Analyst data, one table per type. The user sees the records their
organisation holds and those shared with them. The record they are attached
to is matched by its address only (`object_type`, `object_uuid`,
`object_sha256`), whether or not the user can see it. `created` and
`modified` are datetimes in UTC.
[Fields](restsearch-complex-query.md#analyst-data).

| | notes | opinions | relationships |
|---|---|---|---|
| Endpoint | `POST /analyst_data/restSearch/Note` | `POST /analyst_data/restSearch/Opinion` | `POST /analyst_data/restSearch/Relationship` |
| Default columns | `id`, `object_type`, `object_uuid`, `note`, `authors`, `created` | `id`, `object_type`, `object_uuid`, `opinion`, `comment`, `authors` | `id`, `object_type`, `object_uuid`, `relationship_type`, `related_object_type`, `related_object_uuid` |
| ORDER BY | `id`, `created`, `modified`, `distribution` | `id`, `created`, `modified`, `distribution`, `opinion` | `id`, `created`, `modified`, `distribution`, `relationship_type` |
| Field names as columns | `org` → `Orgc.name` | `org` → `Orgc.name` | `org` → `Orgc.name` |

```sql
SELECT * FROM opinions WHERE opinion < 50 AND created >= '2026-11-01'
ORDER BY opinion LIMIT 20 FORMAT table
```

### collections

Collections, each with its elements. An element field (`element_type`,
`element_uuid`, `element_sha256`, `element_description`) matches when any
element of the collection does; negated, it selects the collections with no
such element, the empty ones included. Elements are matched by their address
and description, whether or not the user can see what they point at. `name`,
`type` and the descriptions compare without regard to case.
[Fields](restsearch-complex-query.md#collections).

- **Endpoint**: `POST /collections/restSearch`
- **Default columns**: `id`, `name`, `type`, `Orgc.name`, `distribution`,
  `element_count`, `modified`
- **ORDER BY**: `id`, `name`, `type`, `created`, `modified`, `distribution`
- **Field names as columns**: `org` → `Orgc.name`

```sql
SELECT * FROM collections WHERE type = 'campaign' AND element_type = 'Event'
ORDER BY modified DESC LIMIT 20 FORMAT table
```

### tags

Every tag on the instance, as MISP's tag index shows them, with how many
events the user can see carry each one (`count`) and how many attributes do
(`attribute_count`); those counts cannot be searched or sorted on. `name`
compares without regard to case. `numerical_value` searches the tag's own
value, even where the user's settings override it.
[Fields](restsearch-complex-query.md#tags).

- **Endpoint**: `POST /tags/restSearch`
- **Default columns**: `id`, `name`, `numerical_value`, `hide_tag`,
  `is_galaxy`, `count`, `attribute_count`
- **ORDER BY**: `id`, `name`, `numerical_value`

```sql
SELECT * FROM tags
WHERE is_galaxy = TRUE AND hide_tag = FALSE AND name LIKE 'misp-galaxy:mitre-attack-pattern=%'
ORDER BY name LIMIT 20 FORMAT table
```

### organisations

Every organisation, local and external, as MISP's organisation index shows
them, with its number of users. Text fields compare without regard to case.
When the instance hides the organisation index from the user's role, this
table answers HTTP 403, as the index does.
[Fields](restsearch-complex-query.md#organisations).

- **Endpoint**: `POST /organisations/restSearch`
- **Default columns**: `id`, `name`, `type`, `nationality`, `sector`, `local`,
  `user_count`
- **ORDER BY**: `id`, `name`, `date_created`, `date_modified`

```sql
SELECT id, name, nationality, sector FROM organisations
WHERE local = FALSE AND sector IN ('Financial', 'Banking')
ORDER BY name LIMIT 100 FORMAT table
```

## Limits

restSearch limits how large a set of conditions may be, before it reads the
database. These are the defaults; an administrator can change them (see
[Complex queries in restSearch](restsearch-complex-query.md#limits)), and
`DESCRIBE` shows the ones in effect.

| Limit | Default | Of |
|---|---|---|
| `max_depth` | 5 | nesting of `AND`, `OR` and `NOT` |
| `max_nodes` | 50 | conditions, plus the `AND`, `OR` and `NOT` joining them |
| `max_list` | 100 | values in one `IN` or `NOT IN` |
| `max_value_length` | 1024 | characters in one value |

MispQL has two limits of its own, checked before anything else and the same in
mispql: at most 1,048,576 characters in what is sent at once (a script for
`explain`, a statement for `run`), and at most 64 parentheses and `NOT` inside
one another. Past any limit, the statement is refused with `limit_exceeded`,
placed on the text.

The role's restSearch limit also applies: when it ends a search before the
statement's `LIMIT` does, `/mispql/run` adds a warning.

## Large events and performance

An event can hold a million attributes. For a column list, `FORMAT table` and
`FORMAT flat` on events, MISP reads the events without their attributes,
objects and reports, which flattening would leave out anyway, so a large event
costs no more than a small one. `SELECT *` without a `FORMAT` returns whole
events, which `/mispql/run` holds in memory to answer them; for events that
may be large, use a column list, or `FORMAT json`, which MISP sends as it
produces it. MISP's other formats also read whole events: keep a `LIMIT` on
those.

Conditions are cheapest when one of them is selective. An `OR` whose branches
share no index, a negated `tags`, or an attribute field matching a large share
of the attributes, such as a common `category`, is best combined with an
`AND` on `event_id`, a timestamp or another narrow condition. See
[Performance](restsearch-complex-query.md#performance) for how each kind of
condition is evaluated.
