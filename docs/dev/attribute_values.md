# Attribute values

How MISP stores attribute values from 3.0 on, and what that means for code
that reads, writes or searches them. Attributes and proposals no longer hold
their value as text: they point at a row of `attribute_values`, a dictionary
with one row per distinct value.

The short version:

- Save attributes and proposals with their text, as before. `beforeSave` turns
  it into ids; ids sent in are thrown away.
- Read them as before. `afterFind` puts `value1`, `value2` and `value` back and
  removes the ids, so nothing outside the instance ever sees an id.
- Put value conditions in a find on the attribute or proposal model, in the
  plain forms below. `beforeFind` turns them into conditions on the ids.
- There is no `value1`/`value2` column to put in raw SQL any more. If code needs
  SQL on values, it goes through the `AttributeValue` helpers.
- Before you commit, run `python3 tests/value_oracle/lint_value_columns.py --strict`.

---

## 1. The tables

### The dictionary

```sql
attribute_values (
  id    BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  value TEXT    -- utf8mb4, in a case- and accent-insensitive collation
  hash  VARBINARY(32) UNIQUE,  -- SHA-256 over the exact bytes
  KEY value (value(128)),
  FULLTEXT KEY value_search (value)
)
```

- **One row per exact byte string.** `hash` alone decides uniqueness; the
  `value` column's collation equates strings that differ in case, so it could
  not. Every hit on `hash` is compared with the full value, and a mismatch (a
  hash collision) throws.
- **Rows are never changed.** They are added by saves and deleted only through
  `/values/delete` (section 10). Nothing garbage-collects them: a value
  stays after its last attribute is gone.
- **Values are at most 65,535 bytes**, what a `TEXT` column holds and what
  attribute validation already allowed. A longer value is refused before any SQL
  runs.
- **The collation is chosen when the table is created**: `utf8mb4_uca1400_ai_ci`
  on MariaDB 10.10 and later, `utf8mb4_unicode_520_ci` on older MariaDB,
  `utf8mb4_0900_ai_ci` on MySQL 8 (untested). Never `utf8mb4_unicode_ci`,
  which weighs every 4-byte character the same.
- **PostgreSQL** has `value text`, `hash bytea`, an expression index on
  `lower(left(value, 128))` for case-insensitive lookups and a `pg_trgm` GIN
  index for `value_search` (see `docs/CONFIG.postgresql.md`).

### Attributes and proposals

`attributes` and `shadow_attributes` have `value1_id` and `value2_id`
(`BIGINT UNSIGNED`, nullable) in place of `value1` and `value2`.

- `value1_id` is always set, even for an empty value (the dictionary holds
  `''`).
- `value2_id` is NULL exactly when the second part is empty: every
  non-composite attribute, and a composite stored as `x|`.

Attribute indexes on the ids:

```
idx_attr_vid_combo (value1_id, value2_id)
idx_vid1_source    (event_id, value1_id, deleted, disable_correlation, type, id)
idx_vid1_target    (value1_id, event_id, deleted, disable_correlation, type, id)
idx_vid2_source    (event_id, value2_id, deleted, disable_correlation, type, id)
idx_vid2_target    (value2_id, event_id, deleted, disable_correlation, type, id)
```

The `_source` / `_target` pairs make every correlation lookup covering. Proposals
have one plain index per id column.

### Derived and keyed tables

| Table | Holds |
|---|---|
| `value_ip_ranges` | The IP facet: `(value_id UNIQUE, ip_start, ip_end, prefix)` for every value that parses as an IP address or CIDR block (section 9) |
| `default_correlations`, `no_acl_correlations` | `value_id` is the value's **group**: the lowest dictionary id among the values the collation holds equal |
| `over_correlating_values` | `(value_id UNIQUE, occurrence)` |
| `attr_value_counts` | `(value_id UNIQUE, cnt_v1, cnt_v2)`, the On Demand top list; a cache |

Gone: `correlation_values`, `shadow_attribute_correlations`, the text key of
`over_correlating_values`, and the `value` virtual field of both models.

---

## 2. Case, accents and exact bytes

Two questions are answered differently, on purpose:

- **"Is this the same value?"** for searching and correlating: the dictionary's
  collation decides. `EVIL.com` finds `evil.com`. On MariaDB and MySQL accents,
  a no-break space and trailing spaces are folded too. PostgreSQL folds case
  only.
- **"Is this a duplicate?"**: exact bytes. An event can hold `evil.com` and
  `EVIL.com` as two attributes.

| Folded (collation) | Exact (bytes) |
|---|---|
| `value`, `value1`, `value2` filters, in every scope | Duplicate attribute check (`valueIsUnique`, the `breakOnDuplicate` upsert) |
| Correlation, all engines | A proposal's match with an older one (`findOldProposal`) |
| Correlation exclusions (exact ones by value group; wildcards case only) | `/values/view?value=` |
| Over-correlation blocks and their occurrence counts | `TrendingAttributesWidget` (counts spellings apart; `TrendingWidget` counts them together) |
| Proposal searches | |
| `/values/search` in `exact` mode | |

`value_search` is a separate case: case-insensitive, but it compares accents
(section 7).

A **value group** is the set of stored values the collation holds equal. Its key
is the lowest id in it: `AttributeValue::groupIds()` for ids,
`ValueConditionRewriter::groupId()` for a term. Correlation rows, the top
correlations and over-correlations are keyed by group, so a case variant
stored later joins the group it belongs to without anything being rewritten.

---

## 3. Writing

Save through the model with the text, as in 2.x. Do not set `value1_id` or
`value2_id`: `beforeSave` discards whatever is there and derives them.

- `MispAttribute::beforeSave` and `ShadowAttribute::beforeSave` call
  `AttributeValue::assignIds()`. It interns `value1` (also when empty) and a
  non-empty `value2`.
- A save with a field list keeps its ids: `assignIds()` interns only the value
  columns on the list, and `AttributeValue::withIdFields()` adds their id
  columns to it. A `fieldList => ['timestamp']` save costs no dictionary query.
- Both loggers record the text, never the ids.

### Interning inside a transaction

Every `save()` of these two models is atomic, so the intern in `beforeSave`
always runs inside a transaction: the save's own, or the caller's. Two things
follow:

- **A new value's dictionary row stays locked until the save commits.** That
  includes `afterSave` (correlation, pubsub, workflows). A concurrent save of the
  same new value waits that long.
- **A deadlock inside a transaction fails that save.** It is not retried,
  because the database has already rolled the transaction back. Outside a
  transaction, `internMany()` retries a deadlock up to five times.

### Bulk saves: prime first

A loop of saves would intern its values one save at a time, inside each save's
transaction. A path that saves many attributes interns them all up front,
outside any transaction, and the saves then find their ids without a query:

```php
$primed = $this->Attribute->primeValues($attributes);
try {
    foreach ($attributes as $attribute) {
        // ... $this->Attribute->save($attribute) ...
    }
} finally {
    $this->Attribute->releaseValues($primed);
}
```

- For very large inputs, `primedChunks($rows)` primes and releases one chunk at
  a time (`PRIME_CHUNK`, 1,000 rows).
- Proposals have `ShadowAttribute::primeValues()`.
- Inside a transaction, `prime()` only looks values up and adds nothing: a primed
  id is never one that a rollback could take back.

The bulk paths in the tree prime already: `Event::_add`, `saveAttributes`,
`editAttributeBulk`, `MispObject::captureObject`, feed ingestion,
`AttributesController::editSelected`, IP normalisation and the event template
instantiator. A new one should prime as well.

---

## 4. Reading

### What a row looks like

`MispAttribute::afterFind` and `ShadowAttribute::afterFind` call
`AttributeValue::attachFound()`. It reads the dictionary once per 1,000 distinct
ids and then sets `value1`, `value2` (`''` when `value2_id` is NULL) and `value`
(`value1`, or `value1|value2`) on each row. The ids are removed. Keys are placed
where 2.x put the columns and the virtual field, so API output is byte-identical
to 2.x.

### Associations

Cake calls an associated model's `afterFind` once per row, which would mean one
dictionary query per attribute of an event. Instead, an association row keeps
its ids, and `AppModel::find` fills every such row in one batch when the find
that read them returns. Two consequences:

- Inside that find, a container model's own `afterFind` and its behaviours see
  association rows that still hold ids and no text.
- Association field lists are not translated (no attribute `beforeFind` runs
  for them). A call site that lists fields names `value1_id` and `value2_id`,
  and passes the find option `valueKeys` with the text keys it wants
  (`['value']`, or all three). `Event::fetchEvent` is the example.

### Field lists and ordering

On a primary find (`callbacks => true`), `ValueFieldTranslator` handles:

- **Field lists**: `value`, `value1` and `value2` are read as the ids, and only
  the keys the list named are filled in.
- **Ordering**: `order => 'value'` (or `Alias.value`) sorts by the dictionary
  text, through two left joins on the primary key. The order follows the
  dictionary collation (UCA 14 on current MariaDB), which places punctuation
  differently from 2.x. The cost is one primary-key probe per row the find
  filters, which is heavy on an unfiltered find.
- **The paginator**: `hasField('value', true)` answers yes, so `sort:value` is
  kept.

### Finds that skip callbacks

- **`callbacks => false`** returns ids and no text. If such a find needs the
  text, call `AttributeValue::attachValues($rows, $alias)` on its result.
- **`callbacks => 'before'`** rewrites conditions (section 5) but does not
  hydrate.
- **`valueText => false`** (find option) keeps the ids on purpose, so that a
  caller can fill many finds in one go with `attachNested()`. That caller is then
  responsible for removing the ids. `MispAttribute::relatedAttributesOf()` is
  the pattern.

---

## 5. Conditions: the rewriter

`ValueConditionRewriter` turns conditions on `value`, `value1` and `value2` into
conditions on the ids, with the meaning they had on the 2.x text columns.

### Where it runs

- **Attribute and proposal finds**: `MispAttribute::beforeFind` and
  `ShadowAttribute::beforeFind`, with `callbacks` `true` or `'before'`.
- **Subqueries built by `AppModel::subQueryGenerator`**, through the
  `subQueryConditions()` hook.
- **Everywhere else, the caller runs it**: `buildStatement()` subqueries, or an
  `Attribute` alias hand-joined into another model's find. Pass the conditions
  through `AttributeValue::rewriteConditions($conditions, 'Attribute')` first.

Conditions that already name ids pass through untouched. So rewriting once,
ahead of a count and its pages, makes the dictionary lookup happen once per
search, not once per statement. `fetchAttributes` and the restSearch page loop
do this.

### What it understands

- **Keys**: `Alias.value`, `Alias.value1`, `Alias.value2` and the bare names.
- **Operators**: `=` (scalar or list), `IN`, `!=` / `<>`, `NOT IN`, `LIKE`,
  `NOT LIKE`, under any `AND` / `OR` / `NOT` / `XOR` nesting.
- **Terms**: strings and numbers. `= null`, `= []`, `!= null` keep their Cake
  meaning.
- **An empty `value2`**: wherever 2.x compared an empty `value2`, the
  rewriter adds `value2_id IS NULL`, and it gets three-valued logic right under
  `NOT`.
- **`value`**: it matches `value1` alone when `value2` is empty, and
  `value1|value2` otherwise. A term with pipes is read once per pipe, and a
  `LIKE` separator can be a literal `|`, a `_` or part of a `%`.

### How terms become ids

- **Equality**: the term's case variants are read from the dictionary
  (`resolveCi`, one statement for every term of the find), and the condition
  becomes a literal id list.
- **`LIKE`**: the pattern is read from the dictionary (`resolveLike`) into a
  literal list of up to 50,000 ids (`ValueConditionRewriter::OVERFLOW`).
  - **Overflow**: above 50,000 matches, the condition becomes
    `valueN_id IN (SELECT id FROM attribute_values WHERE value LIKE …)`.
  - **Bounded finds**: if the top level of the conditions ties the find to at
    most 100 `event_id`, `object_id` or `id` values, an unanchored pattern
    (`%x`) is checked per row instead. Reading the whole dictionary first would
    cost more than the find. `object_id = 0` does not count: it means every
    attribute outside an object.
  - A caller that knows its find is small can declare it with
    `rewriteConditions($conditions, $alias, true)`. Every proposal find does.
- **Many terms**: `AttributeValue::batchRewriter($alias, $terms)` resolves a
  batch of terms in one statement and keeps them for every `rewrite()` that
  follows.

### What it refuses

A condition that names a value column in any other form cannot be carried over:

- a function around the column (`LOWER(Attribute.value1)`, `CONCAT(…)`);
- a raw string condition that mentions a value column;
- another operator (`REGEXP`, `BETWEEN`, `>`);
- a term that is a bool or a nested or keyed array.

With `debug > 0` the rewriter throws `ValueConditionException`. With `debug = 0`
it logs a warning and leaves the condition as it is, and the database then
rejects the missing column. Either way it is a bug in the caller. Most such
conditions are unnecessary anyway: the collation already ignores case, so
`LOWER()` buys nothing.

User input that can reach a value condition unnormalised (`/events/index`'s
`searchvalue`, the sighting `values` list) is cast to strings, or filtered, at
the call site.

---

## 6. Searching from SQL you build yourself

When a feature needs value conditions the rewriter cannot express, build them
with the `AttributeValue` helpers. Each one returns a condition on
`<alias>.value1_id` / `value2_id`, already in the form the planner handles well:

| Helper | Matches |
|---|---|
| `resolveCi($terms)` | `[term => ids]`: every case variant of each term |
| `idsOf($values)` | `[value => id]`: exact bytes, adds nothing |
| `resolveLike($pattern, $limit)` | `['ids' => …, 'overflow' => bool]`, an empty list on overflow |
| `likeCondition($field, $pattern, $not)` | a `LIKE` on one id column, literal list or overflow subquery |
| `searchCondition($texts, $alias, $not, $bounded)` | `value_search` |
| `cidrCondition($ranges, $alias, $not)` | `value_cidr` |
| `fetchValues($ids)` | `[id => text]` |

Never join `attribute_values` on `value = ?` from code that knows the term:
resolve the term to ids first, then filter the attribute table on the ids.

---

## 7. The restSearch value filters

| Filter | Meaning |
|---|---|
| `value`, `value1`, `value2` | Unchanged from 2.x: equality and `LIKE` in the dictionary collation |
| `value_search` | Substring search. MySQL/MariaDB: the text must start at the beginning of a word (letters, digits, `_`), case-insensitive, accent-sensitive; the `FULLTEXT` index finds candidates, and `LIKE` + `REGEXP` decide. PostgreSQL: the text anywhere in the value (`ILIKE`, through `pg_trgm`). The text is literal: `%` and `_` are not wildcards |
| `value_cidr` | Addresses and blocks overlapping the given ones: inside them or holding them, in any spelling (`/32`, `/128`, IPv4-mapped IPv6, uncompressed IPv6). A term that is not an address or block is a 400 |

All three combine with `OR`, `AND` and `NOT` as other filters do, in the
attribute, event and object scopes. In the event and object scopes they go
through `add_value_filter_subquery()`, which takes a per-term condition builder.

**The `FULLTEXT` index must be built without stopwords.** InnoDB's default list
holds `com`, `www`, `the` and others, and an index built with it cannot find
them. The migration rebuilds the table with `innodb_ft_enable_stopword = 0`.
Any later rebuild in a default session (`OPTIMIZE TABLE`, `ALTER TABLE … FORCE`)
brings the stopwords back. `value_search` notices this and falls back to a
slower check for those words, with a warning that says how to rebuild. Do not
drop and re-add the index instead: on a table filled row by row, that can leave
it matching nothing.

---

## 8. Correlation

All three engines correlate on the ids.

- **Default and No ACL.**
  - **On save**: `afterSaveCorrelation` resolves the attribute's values once and
    looks targets up by id.
  - **A recorrelation** primes one rewriter per chunk of
    `MISP.correlation_chunk_size` attributes (`Correlation::$valueRewriter`).
  - **Rows**: keyed by the value group. The text shown is resolved when read
    (`Correlation::displayValueQuery()`): the other attribute's own spelling,
    full length, so nothing is cut at 191 characters any more.
- **On Demand** (MySQL and MariaDB only). Four passes (value1↔value1,
  value1↔value2, value2↔value1, value2↔value2). Each starts from the event's
  distinct value ids, looks their holders up once, and joins the event's
  attributes back last. It matches no CIDR blocks.
- **Exclusions**: one matcher, `Correlation::isExcludedValue()`, read from
  `correlation_exclusions`.
  - `%x%`, `%x` and `x%` match contains, ends-with and starts-with, ignoring
    case.
  - Anything else matches its value group and every stored spelling of it.
  - Saves check against the live group, so a spelling stored after the matcher
    was read is still excluded.
- **Over-correlation**: `OverCorrelatingValue::isBlocked()` reads every stored
  spelling of every blocked value once per process. Read paths filter with
  `blockedGroupsCondition()`.
- **CIDR**: through the IP facet (section 9). An address correlates with the
  blocks holding it and with its own other spellings; a block correlates with
  the single addresses inside it; two blocks never correlate.
  - **Holders**: `ip-src` and `ip-dst` value1 only (`Correlation::CIDR_TYPES`).
  - **Members**: the four IP types (`IP_TYPES`).
  - CIDR and ssdeep matches take the same filters as exact ones: deleted, disabled,
    same event, correlation rules.

---

## 9. The IP facet

`value_ip_ranges` holds a row for every dictionary value that
`ValueFacetTool::ipRange()` accepts:

- **What parses**: an IPv4 or IPv6 address, optionally with a prefix. Text over
  49 characters is never read.
- **Byte form**: ranges are stored as 16 bytes. IPv4 is mapped
  (`::ffff:a.b.c.d`), so an IPv4 `/n` is stored with prefix `96 + n`, and a
  single address of either family has prefix 128. Host bits under the mask are
  cleared.
- **When rows are written**: `internMany()` writes the rows of values it adds.
  The backfill does not, so `cake AttributeValue rebuildFacets` builds them
  afterwards. It is rerunnable and leaves correct rows alone.
- **How lookups run**:
  - **Address in blocks**: probe the address masked at every prefix length
    (`containingStarts()`, `containing()`).
  - **Members of a block**: `ip_start BETWEEN start AND end`.
  - Either way the read is index-only. Never write it as `ip_start <= :ip`, which
    reads every row below the address.

The facet is derived. It is never used to rebuild a value, and it can be
rebuilt at any time.

---

## 10. `/values` endpoints

| Endpoint | Does |
|---|---|
| `GET /values/view/<id>`, `/values/view/sha256:<hex>`, `/values/view?value=…` | The value and the attributes that hold it which the user can see, paged (`page`, `limit` ≤ 1000). The text address matches byte for byte. Missing, unheld and invisible values are the same 404. A site admin also gets a value nothing holds (`attribute_count` 0), so its id can be found for deletion |
| `POST /values/search` `{"value", "mode": "search"\|"like"\|"exact"}` | Values with at least one visible holder, matched by `value_search`, a `LIKE` pattern, or case-folded equality. More than 50,000 candidates is a 400. Rate-limited with the role's restSearch budget |
| `POST /values/delete/<id>` | Site admins. Deletes a value nothing refers to, with its facet and count rows. If attributes, proposals (deleted ones included), over-correlations or correlation rows still refer to it, it refuses and lists them. Logs the id, never the text |

Deleting a value is for erasure requests. It does not reach audit logs that
recorded the text, backups, or copies synced or exported earlier.

---

## 11. Checklist: adding a feature that queries values

1. **Use a find on `Attribute` / `ShadowAttribute`** with conditions on `value`,
   `value1` or `value2` in the forms of section 5. Let `beforeFind` rewrite them.
2. **Not going through that model's `beforeFind`?** (A `buildStatement`
   subquery, a hand-joined alias, `callbacks => false`.) Call
   `AttributeValue::rewriteConditions()` yourself, or build the condition with a
   section 6 helper.
3. **Many terms**: one `batchRewriter()` or one `rewriteConditions()` ahead of
   the loop, not one lookup per term.
4. **Exact or folded?** Decide, and write it down. Folded is the default
   (section 2); exact is `idsOf()`.
5. **Field lists**: primary finds can keep naming `value`. Association field
   lists name `value1_id` / `value2_id` and pass `valueKeys`. A
   `callbacks => false` read must attach the text itself.
6. **Never emit an id**: not in API output, exports, sync, pubsub, workflows or
   logs. Never accept one from a request.
7. **Writes**: save with the text. Prime bulk paths (section 3).
8. **Size it at 10^6 attributes in one event** and at an instance-wide
   dictionary (section 12).
9. **Run the lint and the tests** (section 14).

---

## 12. Performance rules

- **Never put `valueN_id IN (subquery)` under an `OR`.** The planner cannot
  merge it and falls back to a scan. Resolve to literal lists. The one exception
  is the overflow form: a subquery that reads only the dictionary, or only the
  facet.
- **`value1_id IN (list) OR value2_id IN (list)` uses an index merge up to a
  point.** Above `eq_range_index_dive_limit` (200) MariaDB estimates each list
  from index statistics. `value2_id` is mostly NULL, which inflates the estimate,
  and long lists flip to a full scan. On a 3 M-attribute instance the flip came
  between 20,000 and 30,000 ids; an instance with fewer composite attributes
  flips earlier. Measure a new long-list shape with `ANALYZE`, not wall time.
- **Chunk literal lists at 500 when they drive a per-row subquery.** MariaDB
  turns an `IN` list of 1,000 or more literals into a join
  (`in_predicate_conversion_threshold`). That can turn a correlated `EXISTS`
  into a pass over the whole table. `MispAttribute::visibleValueIds()` chunks
  for this reason.
- **An unanchored pattern (`%x`) reads the whole dictionary** unless the find
  is bounded. For broad substring search, `value_search` is the tool.
- **Hydration is cheap**: one primary-key read per 1,000 distinct ids. A loop
  that hydrates one row at a time is not.
- **Bound per event, not per instance.** Prefer a plan that scales with the
  event (event-scoped, covering `_source` index) over one that materialises
  something instance-wide.

---

## 13. Commands

```bash
app/Console/cake AttributeValue backfill           # set the ids from the text columns; resumable
app/Console/cake AttributeValue verify             # every row's ids give back its text; hashes match; changes nothing
app/Console/cake AttributeValue rebuildFacets      # bring value_ip_ranges in line with the dictionary
app/Console/cake AttributeValue remapCorrelations  # key existing correlations by value group; resumable
```

`backfill`, `verify` and `remapCorrelations` serve the upgrade from the text
columns (`docs/UPGRADE.md`). After the text columns are dropped, `backfill` and
`verify` report that there is nothing to read. `rebuildFacets` stays useful at
any time.

---

## 14. Tests and tools

- **Lint**: `python3 tests/value_oracle/lint_value_columns.py --strict`. It
  reports every string in `app/` that uses a value column in SQL and is not
  legal by a rule (a condition the rewriter carries, a translated field or
  order, an interned save field list) or allowlisted. CI runs it.
  `--show-allowed` explains each exemption.
- **Unit tests** (framework-free, part of `app/Test`): `AttributeValueTest`,
  `ValueConditionRewriterTest`, `ValueFieldTranslatorTest`, `ValueFacetToolTest`,
  `AttributeValuesMigrationTest`.
- **Database tests**: `app/Test/*DbTest.php`. They need a MySQL/MariaDB
  instance with data, and run only with `ATTRIBUTE_VALUE_DB_TESTS=1`, one file
  per run:

  ```bash
  ATTRIBUTE_VALUE_DB_TESTS=1 ./app/Vendor/bin/phpunit app/Test/AttributeValueFilterDbTest.php
  ```

  - **How they clean up**: each test runs in a transaction that is rolled back.
    Tests whose code commits (correlation top lists, `FULLTEXT` fixtures) delete
    their own rows by id afterwards.
  - **Strict conditions**: they set `AttributeValue::$strictConditions = true`.
  - **Engines**: `AttributeValueEngineDbTest` also runs on PostgreSQL; the rest
    skip there.
  - **A new database test**: follow the existing ones. Never insert explicit
    ids, and put divergent text through `AttributeValueTextSupport`.

---

## 15. Where things are

| Path | What |
|---|---|
| `app/Model/AttributeValue.php` | The dictionary: intern, resolve, hydrate, helpers |
| `app/Lib/Tools/ValueConditionRewriter.php` | Conditions → ids |
| `app/Lib/Tools/ValueFieldTranslator.php` | Field lists and order → ids |
| `app/Lib/Tools/ValueFacetTool.php` | IP facet |
| `app/Lib/Tools/AttributeValueBackfillTool.php`, `CorrelationRemapTool.php` | Upgrade tools |
| `app/Console/Command/AttributeValueShell.php` | `cake AttributeValue …` |
| `app/Controller/ValuesController.php` | `/values/view`, `/values/search`, `/values/delete` |
| `app/Model/Behavior/OnDemandCorrelationBehavior.php` | On Demand passes |
| `app/Model/Correlation.php`, `OverCorrelatingValue.php` | Group keys, display, exclusions, CIDR |
| `app/Lib/Migration/Migrations/` | The schema changes: `create_attribute_values`, `create_value_ip_ranges`, `attribute_value_ids`, `value_keyed_correlation_counts`, `value_group_correlations`, `drop_shadow_attribute_correlations`, `drop_attribute_value_text`, `value_search_without_stopwords` |
| `tests/value_oracle/` | The lint and the 2.x comparison suites |
