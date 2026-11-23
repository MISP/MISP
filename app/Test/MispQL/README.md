# MispQL 1.0 conformance cases

Exported from mispql 1.x's tests. Every offset (`start`, `end`) counts Unicode code
points of the statement text; `fragment` is the text between them. Compare the JSON as
decoded data, not as text.

- `VERSION`: the language version.
- `compile/<case>.mql`: a statement, or a script of several. Some hold characters an
  editor may change unseen (no-break spaces, combining accents): edit them with care.
- `compile/<case>.json`: `statements`, one plan per statement, in order: `kind`
  (`search`, `count`, `describe`, `show_tables`, `show_databases`, `use`, `whoami`),
  the statement's `start` and `end`, the plan's fields, and `spans`: the text each path
  of the request body comes from (`<unknown>` names the field of a condition).
- `errors.json`: statements refused before anything is sent. `code`, `start` and `end`
  are binding; `mispql_message` is mispql's wording, which quotes the input where MISP's
  messages do not. The first error of the script is the one recorded: every statement is
  parsed before any is compiled. Not exported, as each case is a megabyte: a text longer
  than 1048576 code points is refused before the lexer runs (`limit_exceeded`, from
  offset 1048576 to the end of the text).
- `server_errors/<case>.json`: a statement, the `body` it compiles to, MISP's 400 `reply`
  to that body, and `located`: the text each error path of the reply points at.
- `locate.json`: an error `path` and the text it points at, through the longest prefix
  of the path that the plan knows; `null` where none is known (mispql then points at the
  whole statement).
- `rows/<case>.json`: what happens to MISP's rows. The keys present are the steps the
  case checks:
  - `reply`, MISP's answer, gives `rows`: its `response` holds the rows under the table's
    row key, or is a list of objects each holding one row under the row key, whose other
    keys join the row unless the row has them already;
  - `rows` flattened give `flat`: nested objects become dotted keys (an empty one leaves
    none), a list under a `Tag` key, at any depth, the names of its tags; other lists are
    kept when not empty and holding no object or list, and are left out otherwise;
  - `flat` gives the header `columns`, the `cells` and the `warnings`. The columns wanted
    are the statement's column list or, for `FORMAT table` without one, the table's
    default columns; each is spelled as the rows first spell it, matched without regard
    to case. For `FORMAT flat` without a column list, the header is every key of `flat`
    in the order first seen. `cells` holds, per row, the value under each header column
    (matched without regard to case) or null. `warnings` come with a column list only,
    when there are rows: `no row has a column <name>` for each column no row has.
- `source` names the mispql test a case comes from.
