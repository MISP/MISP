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
    The conversion needs a few commands after the update, and the instance should be offline while they run. Read the steps before you start.

MISP 3.0 stores each distinct attribute value once, in `attribute_values`.
Attributes and proposals point at it instead of holding their value as text.
The API, exports, sync and pubsub output do not change. The developer reference
is [docs/dev/attribute_values.md](dev/attribute_values.md).

### Steps

Run the commands from `app/` as the web server user
(`sudo -u www-data Console/cake …`).

1. **Update, then apply the migrations**: `Console/cake Admin runUpdates`, or
   log in. They create the value table and the new id columns. The last one,
   which drops the old text columns, waits until the next steps are done.
   `Console/cake Admin migrationStatus` shows it as deferred, and its message
   names the step it is waiting for.
2. **Take the instance offline**: `Console/cake Admin live 0`. Until steps 3–5
   finish, searches and correlation miss the attributes not converted yet, and
   existing correlations do not show their values correctly.
3. **Fill the value table**: `Console/cake AttributeValue backfill`. It shows its
   progress and can be stopped and started again; it carries on where it
   stopped.
4. **Build the IP index** used by CIDR correlation and the `value_cidr` filter:
   `Console/cake AttributeValue rebuildFacets`.
5. **Re-key the existing correlations**:
   `Console/cake AttributeValue remapCorrelations`. Also resumable.
6. **Apply the last migration**: `Console/cake Admin runUpdates`. It checks that
   every attribute and proposal gives back its exact text from the value table
   before it drops anything. `Console/cake AttributeValue verify` runs the same
   check on its own and changes nothing.
7. **Restart the background workers**: `Console/cake Admin restartWorkers`. A
   worker that was running during the update still knows the tables as they
   were before it, and fails on the columns the update dropped.
8. **Bring the instance back**: `Console/cake Admin live 1`.
9. **Regenerate the lists the conversion emptied**:
   - **Top correlations**: `Console/cake Event generateTopCorrelations`, or the
     button on the top correlations page.
   - **Over-correlation counts**: the button on the over-correlating values
     page.
10. **Optional cleanup**: Redis no longer uses `misp:cidr_cache_list` or
    `misp:correlation_exclusions`, so both keys can be deleted.

Make sure the database has room for the value table before you start: it is
built while the old text columns still exist.

### Requirements

- **MariaDB 10.10 or later** is recommended (collation `utf8mb4_uca1400_ai_ci`).
  Older MariaDB uses `utf8mb4_unicode_520_ci`. MySQL 8 has not been tested.
- **PostgreSQL 16 or later**, with the `pg_trgm` extension
  ([docs/CONFIG.postgresql.md](CONFIG.postgresql.md)). The On Demand
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
- The `cake Admin` `OnDemandCorrelationTuning` index pack is gone, and the
  `highPerformance` pack no longer creates text indexes.

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
