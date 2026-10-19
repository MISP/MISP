# Upgrading MISP

!!! note
    As time goes by this space will be populated with certain upgrade specific tasks that might at the time of this writing still be in the [MISP-book](https://www.circl.lu/doc/misp/)

!!! warning
    If you are a MISP developer reading this.<br />
    Always aim to avoid having to write anything about a specific upgrade procedure. We strive to make our upgrades as seamless as possible and no extra steps should be needed, alas, extreme circumstances sometimes need those extreme measures.<br />
    We have been warned.

## Schema monitoring after the migration ledger

!!! warning
    If you monitor your instances through the schema diagnostic (`/servers/dbSchemaDiagnostic`, the payload fleet checks poll), your alert rule needs changing. Do it together with the upgrade, not after.

MISP now records schema changes in a `schema_migrations` ledger, one row per
migration, instead of advancing the `db_version` counter. `db_version` is frozen
at 159 permanently. The consequence for monitoring:

- **`actual_db_version` vs `expected_db_version` no longer detects anything.**
  Both are 159 on every instance from now on, including one that has unapplied
  or failed migrations. The comparison is not wrong; it is constant.
- **Alert on `migrations_pending > 0` instead.** This is the direct replacement.
  `migrations_pending_ids` names the migrations the instance is behind on, so
  the alert body can say which.
- **Alert on `migrations_failed > 0` as well.** This is new: a failed migration
  now halts the update run, everything behind it stays pending, and the failure
  is recorded (`migrations_failed_ids`). The previous system could not report
  this state at all — a later update would advance the version past the failure
  and the instance looked healthy.
- `update_locked`, `remaining_lock_time` and `update_fail_number_reached` keep
  their meaning.
- `diagnostic`, `diagnostic_index` and `checked_table_column` are always empty
  from 3.0 on. The column-by-column comparison with `db_schema.json` is gone: it
  mostly reported harmless differences between database server releases.

The diagnostics page shows the same figures, and so does
`Console/cake Admin schemaDiagnostics`. The full description of the fields and
of what a halted instance looks like is in
[docs/dev/database-migrations.md](dev/database-migrations.md), section 11.

## Attribute values move to a value table (MISP 3.0)

!!! warning
    The upgrade runs offline, from the command line, in one command. Read the steps before you start.

MISP 3.0 stores each distinct attribute value once, in `attribute_values`.
Attributes and proposals point at it instead of holding their value as text.
The API, exports, sync and pubsub output do not change. The developer reference
is [docs/dev/attribute_values.md](dev/attribute_values.md).

### Steps

Run the commands from `app/` as the web server user
(`sudo -u www-data Console/cake …`).

1. **Update the code**, then run the upgrade from the command line before
   anyone logs in: `Console/cake Admin runUpgrade`. It takes the instance
   offline, stops the background workers, applies every pending update and
   converts the attribute values: it fills the value table
   (`Console/cake AttributeValue backfill`), builds the IP index used by CIDR
   correlation and the `value_cidr` filter (`rebuildFacets`), and checks that
   every attribute and proposal gives back its exact text from the value table
   before the last migration drops the old text columns. Then it starts the
   background workers again and brings the instance back. It shows its
   progress as it goes.
   If anything fails, it stops and leaves the instance offline; fix what it
   names and run it again, and it carries on where it stopped.
   Run it inside `screen` or `tmux`: on a large instance it runs for hours,
   and a closed SSH session stops it halfway.
   After an interruption (Ctrl-C, a lost session, a killed process) the
   database server may still be running the statement the run was on. Look for
   an `ALTER TABLE` or `CREATE INDEX` in `SHOW PROCESSLIST` (MySQL, MariaDB)
   or `pg_stat_activity` (PostgreSQL), and either wait for it to finish or end
   it (`KILL <id>`, `SELECT pg_cancel_backend(<pid>)`) so that the table
   starts over; then run `runUpgrade` again. A run that finds such a statement
   on the table it is about to change stops and names it.
   `Console/cake AttributeValue verify` runs the same check on its own and
   changes nothing.
2. **Restart the web server** once the upgrade has finished:
   `sudo systemctl restart apache2` with mod_php, or restart PHP-FPM
   (`sudo systemctl restart php8.2-fpm`, named after your PHP version). This
   clears the PHP caches that still hold the old database layout; until then,
   pages can fail and some changes are not saved.
3. **Let the correlations fill in.** The upgrade recreates the correlation
   tables empty instead of converting them, and its last step queues a full
   recorrelation: the background workers start it once they are back, and the
   correlations appear while the instance is already live. Without background
   jobs it only prints the command; run `Console/cake Admin
   jobGenerateCorrelation` once the instance is back. On a large instance
   either takes hours.
4. **Regenerate the lists the conversion emptied**, once the recorrelation
   has finished:
   - **Top correlations**: `Console/cake Event generateTopCorrelations`, or the
     button on the top correlations page.
   - **Over-correlation counts**: the button on the over-correlating values
     page.
5. **Optional cleanup**: Redis no longer uses `misp:cidr_cache_list` or
   `misp:correlation_exclusions`, so both keys can be deleted.

### How long it takes and what it needs

Plan the window and the disk before you go offline. The figures come from
MariaDB 10.11 on a laptop (SSD, 2 GB InnoDB buffer pool), measured up to 8
million attributes and extrapolated beyond that; a server with more memory and
faster disks does better. Run the upgrade on a copy of your database first if
the window matters.

- **Rebuilding `attributes`** is the step that runs longest. It copies every
  row into a new table while the table cannot be written to. Once the table no
  longer fits in the buffer pool the time is linear: about 21,000 rows per
  second (11 to 13 MB/s of table and index data), which is 6 minutes for 8
  million attributes, about 1.3 to 1.5 hours for 100 million and 6.5 to 8
  hours for 500 million.
- **Filling the value table** (`AttributeValue backfill`) is the other long
  step: about 8,000 attributes per second, measured once at 2 million. That is
  about 3 hours for 100 million attributes if it stays linear, and it may be
  worse, because the value table's unique index grows with it.
- **A whole upgrade from 2.5** with 2 million attributes took 509 seconds
  (backfill 242 s, the schema changes before `attributes` 137 s, `attributes`
  106 s). Count on five hours or more at 100 million attributes.
- **Free disk: about 3.5 times the size of the `attributes` table, indexes
  included.** The new table is built beside the old one, and on MariaDB the
  sort files for its new indexes take about as much again, in the temporary
  directory (`tmpdir`), which may be another filesystem. At 100 million
  attributes that is about 180 GB: roughly 85 GB in the data directory and
  roughly 95 GB in `tmpdir`. MySQL 8.4 writes no sort files to `tmpdir`, so it
  needs about half of that. The upgrade checks the free space of each
  filesystem before it starts a table and stops with the amount it needs;
  `Console/cake Admin migrationApply --dry-run` only prints the SQL and
  skips this check.
- **Memory.** An optional speed-up on MariaDB and MySQL: set
  `innodb_sort_buffer_size = 16M` (a startup setting, so restart the database)
  for the run. It made the `attributes` rebuild about 15 % faster at 4
  million attributes. The server allocates that buffer for every index it
  builds at once, 22 on `attributes`, so allow about 4.5 times the buffer size
  for each of them (about 1.6 GB more at 16 MB). Do not go much higher on a
  small machine: 64 MB used more than 5 GB and the operating system killed the
  database. Take the setting out again afterwards.
- **While it runs**, each table's start, size and the disk it needs are printed,
  together with how to watch the statement: `SHOW FULL PROCESSLIST` and its
  `Progress` column on MariaDB, `performance_schema.events_stages_current` on
  MySQL.

**Galera and other synchronous clusters.** Run the upgrade on one node. On
Galera, a schema change replicates in total order isolation: while the
`attributes` rebuild runs, every node of the cluster is blocked for writes, not
only the one you run it on. Plan the window for the whole cluster, and do not
switch the rebuild to rolling schema upgrade unless you have a way to keep the
nodes' schemas equal.

**Back up first.** A rebuild is not a transaction on any engine: it either ends
with the new table or can be run again, but a full disk or a killed server can
leave you restoring from the backup.

### Requirements

- **MariaDB 10.11 or later** (collation `utf8mb4_uca1400_ai_ci`), or
  **MySQL 8.4 or later** (collation `utf8mb4_unicode_520_ci`). A new
  installation loads `INSTALL/MARIADB.sql` or `INSTALL/MYSQL.sql`
  respectively.
- **PostgreSQL 16 or later**, with the `pg_trgm` extension
  ([docs/CONFIG.postgresql.md](CONFIG.postgresql.md)). `runUpgrade` checks for
  it before it takes the instance offline and stops with what to do if it is
  missing and the database user cannot create it. The On Demand
  correlation engine is MySQL/MariaDB only.

### What behaves differently

**Values and duplicates**

- **Case variants are no longer duplicates.** An event can now hold `evil.com`
  and `EVIL.com` as two attributes; 2.x refused the second. If such an event
  syncs to a 2.x instance, the 2.x side refuses the second spelling of a
  standalone attribute and logs it as dropped, on every sync.
- **Proposals are validated like attributes.** A value of control characters
  only is refused, and an over-long value is a validation error instead of a
  server error.
- **Proposal searches** ignore case and accents, as attribute searches always
  did.

**Searching**

- **New restSearch filters.** `value_search` is an indexed substring search. On
  MySQL/MariaDB it matches from the start of a word; on PostgreSQL, anywhere.
  `value_cidr` finds addresses and blocks overlapping the given ones. The
  `value` filter keeps its meaning.
- **Sorting by value** follows the value table's collation, which orders some
  punctuation differently from 2.x.
- **New endpoints**: `/values/view`, `/values/search`, and `/values/delete` for
  site admins (see below).

**Correlation**

- **Correlations show the other attribute's own spelling, in full.** 2.x showed
  one stored spelling, cut at 191 characters.
- **Correlation exclusions ignore case.** Exact ones also ignore accents and
  no-break spaces. An exclusion `0` now applies. Purging correlations by an
  exclusion deletes exactly what the exclusion matches; 2.x deleted every value
  that started or ended with its text.
- **CIDR correlation**:
  - An address correlates with the blocks holding it, and with its other
    spellings (`/32`, `/128`, IPv4-mapped IPv6); a block correlates with the
    single addresses inside it.
  - IPv4 addresses are no longer inside IPv6 blocks such as `::/0`.
  - CIDR and ssdeep matches now skip deleted, correlation-disabled and same-event
    attributes, as exact matches do.
  - Saves now store `/32` and `/128` as the plain address, and refuse a CIDR
    block on an `ip-src|port` / `ip-dst|port` attribute.
- **Rows a 2.x instance stored keep 2.x behaviour until a recorrelation.**
  Correlations 2.x stored for a case variant of an excluded value, and CIDR or
  ssdeep rows with deleted, disabled or same-event targets, stay until the
  instance is recorrelated.
- **On Demand** matches no CIDR blocks. It now applies wildcard exclusions and
  the primary-only rule for composite types as the other engines do.
- **Proposal correlation is gone**: the "Recorrelate proposals" action,
  `cake Admin jobGenerateShadowAttributeCorrelation`, and the
  `shadow_attribute_correlations` table. It had been out of use since 2022.
- **Over-correlation**:
  - Entries are kept per value, case variants together, shown as stored, and
    counted exactly.
  - An entry for a value the instance does not hold is removed by the upgrade;
    block such a value again afterwards if you still want it.
- **Dashboard**: the two trending widgets differ on purpose.
  `TrendingAttributesWidget` counts case variants apart; `TrendingWidget` counts
  them together.

**Analyst data and collections**

- **Notes, opinions, relationships and collection elements can point at a
  value**, addressed by the SHA-256 of its text (`object_sha256`,
  `related_object_sha256`, `element_sha256`, type `AttributeValue`). On those
  rows `object_uuid`, `related_object_uuid` or `element_uuid` is `null`: API
  clients that assume a uuid there need to cope with it. Developer reference:
  [docs/dev/value_targets.md](dev/value_targets.md).
- **2.x peers never receive these rows.** A collection a 2.x instance sends back
  replaces the other elements as before, but never removes the value elements.

**Indexes**

- The final migration drops every index on the old text columns, custom ones
  included. The value table's indexes replace them.
- The `cake Admin` `OnDemandCorrelationTuning` index pack is gone, and
  `runDBScript highPerformance` only tells you that those indexes are now part
  of the schema, which the upgrade applies. `runDBScript indexLogs` is
  unchanged.

**Erasure**

- **A value outlives its attributes.** Deleting or sanitising an attribute leaves
  its text in the value table. When nothing refers to the value any more, a
  site admin removes it with `/values/delete/<id>` (find the id with
  `/values/view?value=…`).
- **What that does not reach**: audit logs that recorded the text, backups, and
  copies synced or exported earlier.

**Custom code and maintenance**

- **Custom SQL**: anything reading `attributes.value1` / `value2`,
  `shadow_attributes.value1` / `value2` or `correlation_values` directly must
  change. Finds through the models keep working.
- **Rebuilding `attribute_values`**: the `value_search` index is built without
  InnoDB's stopword list. If you rebuild the table (`OPTIMIZE TABLE`,
  `ALTER TABLE … FORCE`), do it in a session with
  `SET SESSION innodb_ft_enable_stopword = 0;`, or searches for words such as
  `com` and `www` fall back to a slower path. MISP logs a warning when it
  detects this.
