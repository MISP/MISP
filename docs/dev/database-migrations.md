# Database migrations

How to change MISP's database schema. This is the developer reference for the
migration system under `app/Lib/Migration/`: where a migration lives, how it is
written, how it is checked before it runs, and the two rules that are not
negotiable.

The short version:

```bash
Console/cake Admin migrationCreate my_change --description "What it is for"
# edit app/Lib/Migration/Migrations/Migration_<id>_my_change.php
Console/cake Admin migrationApply --dry-run --id <id>     # read both engines
sudo -u www-data Console/cake Admin migrationApply        # or just log in
```

---

## 1. The two rules

**Nothing new goes into `AppModel::DB_CHANGES`.** The historic corpus is frozen
at **159** and lives in `app/Lib/Migration/LegacyMigrationsTrait.php`, which is
read, never edited. `AppModel::assertLegacyCorpusFrozen()` enforces it at runtime
and `LegacyCorpusFreezeTest` enforces it in CI, so an added case fails the build
rather than shipping. Every schema change from now on is a migration.

**A migration writes no raw SQL.** It declares what it wants against a
flavour-agnostic builder, and the builder renders that for each engine. Raw SQL
in a migration is raw MySQL, and it silently does nothing useful anywhere else.
`rawSql()` exists for the cases that genuinely have no portable spelling — see
§6 — and it makes you write out every engine by hand.

## 2. Why the counter was not enough

The old system tracked one integer, `db_version`, and applied everything above
it. That answers *how far did we get*, which is not the same question as *did
this particular change run*. Two branches numbering their updates independently,
or a branch merged after an instance had already moved past its numbers, and an
update is skipped forever with nothing to show for it.

Migrations are tracked by identity instead, one row per migration in the
`schema_migrations` ledger. An unapplied migration stays pending no matter what
else has happened around it, and it cannot be skipped by arriving late.

`db_version` still exists and is still 159. It will not move again.

## 3. Anatomy

One class per file, under `app/Lib/Migration/Migrations/`:

```
file:  app/Lib/Migration/Migrations/Migration_20260901_120000_probe_shares.php
class: Migration_20260901_120000_probe_shares
id:    20260901_120000_probe_shares
```

**Identity is the file name and nothing else.** The id is the class name minus
the `Migration_` prefix, and CakePHP requires the class name and file name to
agree, so the three are one fact spelled once. There is deliberately no `$id`
property: a declared id is free to disagree with its file, and a migration that
disagrees with itself applies twice under two different keys.

The prefix exists because a PHP class name cannot begin with a digit. The
timestamp is fixed-width because that is what makes sorting ids as strings sort
them chronologically, which is how pending migrations are ordered.

`migrationCreate` derives the id from the current time and the slug you give it;
slugs are `[A-Za-z0-9_]+` because the slug ends up inside a class name.

A migration has three parts, all optional:

```php
class Migration_20260901_120000_probe_shares extends AbstractMigration
{
    public $description = 'One line, shown by migrationStatus';
    public $requiresLogout = false;

    public function beforeUp() { /* PHP data work the DDL depends on */ return true; }

    public function up(SchemaBuilder $schema) { /* DDL */ }

    public function afterUp() { /* PHP data work */ return true; }
}
```

`up()` declares schema. `afterUp()` runs once every statement `up()` declared has
landed, and is where the work that needs models rather than SQL goes — seeding
rows, regenerating correlations, backfilling a column. Returning `false` from it
marks the migration **failed**, exactly as a broken statement does: a migration
is one unit, and a seeding step that could not finish must not be recorded as
done.

`beforeUp()` runs first, for the data work the DDL cannot proceed without:
merging the rows a unique index about to be added would refuse, filling in the
nulls a `NOT NULL` would trip over. Same contract as `afterUp()` — returning
`false` or throwing marks the migration failed and halts the run — with the
difference that nothing has been issued yet, so a failure there leaves the
schema exactly as it was. Anything that can wait until the DDL has landed
belongs in `afterUp()`.

`requiresLogout` carries the meaning the old `DB_CHANGES` value had. Set it if
the change touches a table the session data is built from.

## 4. The schema DSL

Table-scoped, chainable:

```php
$schema->table('event_templates')
    ->addColumn('exposed', 'boolean', [
        'null' => false, 'default' => 0, 'after' => 'misp_default',
    ])
    ->addIndex('exposed');
```

| Method | Notes |
|---|---|
| `addColumn($name, $type, $options)` | `after`, `first` place it on MySQL; type `primary_key` adds an auto-increment id that is the table's key |
| `changeColumn($name, $type, $options)` | `null` and `default` are **required** |
| `renameColumn($from, $to, $type, $options)` | type restated; same requirement |
| `dropColumn($name)` | |
| `addIndex($columns, $options)` | `unique`, `name`, `length`, `fulltext` |
| `dropIndex($columnsOrName)` | The column set, or the index's own name |
| `dropPrimaryKey()` | Drops the constraint, keeps the columns. Add a unique index over the old key column first |

Schema-scoped: `createTable()`, `dropTable()`, `renameTable()`, `rawSql()`.

```php
$schema->createTable('collection_shares', [
    'id'            => ['type' => 'primary_key'],
    'collection_id' => ['type' => 'integer', 'null' => false],
    'uuid'          => ['type' => 'string', 'length' => 40, 'null' => false],
], [
    'indexes' => ['collection_id' => [], 'uuid' => ['unique' => true]],
    'engine'  => 'InnoDB',
    'charset' => 'utf8mb4',
]);
```

Order is declaration order across the whole builder, so a migration that adds a
column, creates a table and then indexes the column gets exactly that sequence.

**`changeColumn` is stricter than the rest.** MySQL's `MODIFY` restates the whole
definition, so anything you leave out is silently dropped — a `MODIFY` that omits
`NOT NULL` makes the column nullable. Both `null` and `default` are therefore
required rather than defaulted, because guessing either one is a data-loss bug
wearing a convenience feature's clothes.

**Hints that one engine cannot express are dropped, and reported.** `after` is
cosmetic ordering PostgreSQL has no equivalent for, so it goes quietly. `charset`,
`collate`, `comment`, `unsigned` and a table's `ENGINE` go the same way, for
free — CakePHP's Postgres driver simply declares no such parameters. An index
**prefix length** is different in kind: dropping it changes what the index
indexes, so it is logged rather than vanishing. `--dry-run` prints all of these.

**Data changes go through models, in `beforeUp()` and `afterUp()`, never as
DML.** A
`save()`/`updateAll()` is portable by construction where a hand-written `INSERT`
is not, and the entire historic corpus contains 34 data statements, so nothing is
lost by declining to abstract them.

**Call `$Model->schema(true)` in `afterUp()` for any table the migration
altered.** CakePHP caches a table's description and `Model::save()` filters
fields against it, so without that a write to a column added moments earlier is
silently dropped. The migration runner turns the datasource's schema cache off
before `afterUp()`, which handles the common case, but a model already
initialised earlier in the process keeps its own copy.

## 5. Check before you run

```bash
Console/cake Admin migrationApply --dry-run --id 20260901_120000_probe_shares
```

This prints the SQL for **every** engine and executes nothing. It is the only
practical way to see the PostgreSQL rendering, since a MISP host has no
`pdo_pgsql` and cannot connect to PostgreSQL at all — the grammar is rendered
through a connectionless datasource specifically so this works.

Read the PostgreSQL half. It is the half nothing else will exercise for you. The
dry run also prints:

- dropped hints, as SQL comments under the flavour that dropped them;
- `No schema changes.` for a data-only migration;
- a note when the migration carries a `beforeUp()` or an `afterUp()`, because
  otherwise "no schema changes" reads as "does nothing";
- a hard error for a `rawSql()` that does not cover every flavour.

With no `--id`, it renders every pending migration.

## 6. `rawSql`, and when to reach for it

Some things have no portable spelling: a `FULLTEXT` index, an `enum`, a statement
gated on a MySQL version. `rawSql()` takes one statement per engine:

```php
$schema->rawSql([
    'mysql' => "ALTER TABLE `attributes` ADD FULLTEXT INDEX `value_ft` (`value1`);",
    'pgsql' => "CREATE INDEX idx_attributes_value_ft ON attributes USING gin(to_tsvector('simple', value1));",
]);
```

A `rawSql()` missing the flavour being rendered is a **hard error**, not a skip.
A migration that quietly does nothing on one engine leaves that engine's schema
behind the code that expects it, which is the failure this whole subsystem exists
to end.

An explicit empty list is not a missing flavour. `'pgsql' => []` says, in so many
words, that PostgreSQL has nothing to run at this point — the spelling for a MySQL
storage option (`ROW_FORMAT`, an `ENGINE` change) that the other engine has no
counterpart to, or the mirror image — and it renders as no statement at all.

Reach for it when the DSL genuinely cannot express the change — not when
expressing it is inconvenient. Every `rawSql()` is a place a future engine has to
be added by hand.

## 7. Running, failing, retrying

```bash
Console/cake Admin migrationStatus                # applied / failed / pending / orphaned
Console/cake Admin migrationApply                 # all pending, in id order
Console/cake Admin migrationApply --id <id>       # one
```

Applying is also what `runUpdates()` does, so an ordinary login or
`Console/cake Admin runUpdates` picks migrations up alongside the legacy corpus —
legacy first in numeric order, then migrations in id order.

`migrationApply` must run as the web server's user (`www-data`, `httpd`,
`apache`, `wwwrun`, `www`, or whoever `MISP.osuser` names). Applying writes cache
files and, through `afterUp()`, whatever else a model touches; doing that as root
or as a developer leaves files the web server cannot read, and the instance
breaks later for reasons that no longer point back here. `--dry-run`,
`migrationStatus` and `migrationCreate` are not gated.

**A failure halts the run.** Everything after the failed migration stays pending
and untried, and the failed one is retried first on the next run. This is the
contract, not an optimisation: a three-step change — add a column, backfill it,
drop the old one — must not run its third step when its first one failed. The
command names what it did not attempt and exits non-zero.

The update lock is still released after a halt, so a stuck instance retries on
the next run rather than sitting out the lock's TTL. But `update_fail_number`
accumulates and no later success resets it, so a migration that keeps failing
will lock the instance out after four attempts through the existing backstop.

**A migration is not transactional.** MySQL DDL commits implicitly, so a
migration whose third statement fails leaves the first two applied and the ledger
row marked failed. Write migrations that can be re-run. For DDL, `up()` can ask
the live schema through `$this->inspector()` — `hasTable()`, `hasColumn()`,
`hasIndex()`, `primaryKey()` — and declare only what is still missing, so the
retry skips what already landed:

```php
public function up(SchemaBuilder $schema)
{
    if ($this->inspector()->hasColumn('bruteforces', 'id')) {
        return;
    }
    $schema->table('bruteforces')->addColumn('id', 'primary_key', ['first' => true]);
}
```

A one-statement migration needs none of that. `beforeUp()` and `afterUp()` are
yours to guard the same way, through the models they write with.

`migrationApply --id` on a migration already recorded as applied does nothing and
exits 0 — `apply` means "make sure this is applied". To genuinely re-run one,
delete its `schema_migrations` row first, and be sure its `afterUp()` can take it.

## 8. `db_schema.json`, and why you do not touch it

`db_schema.json` at the repo root is the **canonical expected schema** —
`Console/cake Admin schemaDiagnostics` compares a live database against it — and
it is **not** maintained migration by migration. Before a release it is
regenerated wholesale from a freshly built, clean MISP database:

```bash
# on a clean build, not on your working instance
Console/cake Admin dumpCurrentDatabaseSchema
```

So as a migration author you do nothing here. Between that regeneration and the
next one, `schemaDiagnostics` will report your change as a difference on every
instance that has applied it. That is expected and it clears itself at the next
release.

**The one rule: regenerate only from a clean build.**
`dumpCurrentDatabaseSchema` rewrites the file from whatever database it is
pointed at, and a development instance accumulates drift — replayed updates,
abandoned experiments, columns from branches that never shipped. Regenerating
there does not fix a diff, it promotes that box's history to canonical and
teaches every instance in the fleet to expect it.

Two things worth knowing about the file:

- **Its `db_version` field is permanently 159.** It is written from
  `admin_settings`, which no longer moves. The ledger, not that number, is what
  records a migration.
- **`schema_migrations` will appear in it** from the first regeneration after a
  clean build has applied a migration, because `Server::getActualDBSchema()`
  enumerates every table in `information_schema` rather than a fixed list. Once
  it is in the expected schema, an instance that has not yet run its updates
  reports one critical line — ``Table `schema_migrations` does not exist`` —
  rather than nothing. That is correct signal, not noise: such an instance really
  does have schema work outstanding. But it is new, so expect it.

`INSTALL/MYSQL.sql` is a different file with a different lifecycle. It is
generated, like `INSTALL/POSTGRESQL.sql`, from a reference database that has
applied everything, and it needs nothing from a migration: a fresh install
loads it, finds the migration recorded in the seeded ledger, and runs nothing.
It is regenerated before a release; §10 applies.

## 9. The ledger

`schema_migrations`, one row per migration: `id` (the auto-increment integer
every table keys on), `migration_id` (the migration's id, unique — what every
read and write goes by), `applied_at`, `duration_ms`, `status` (`applied` /
`failed`), `error`.

It is created on first write, not by a migration — a migration system whose
ledger is a migration has nowhere to record that it ran. For the same reason it
reshapes itself: a ledger from before it had an integer `id` (the migration id
sat in a varchar column named `id`) is altered in place on the next write, rows
kept, and reads take either shape in the meantime. It is read fresh on every
call and never cached, because the interesting callers are polling it while
another process applies migrations. Asking what is pending never creates it.

It may hold ids with no file behind them, if a migration was reverted out of the
tree after running somewhere. `migrationStatus` reports those under **Recorded
but no longer on disk**; nothing else cares.

`schema_migrations` is absent from `db_schema.json` on purpose, and causes no
`schemaDiagnostics` noise: the diagnostic iterates the *expected* schema, so a
table it does not know about yields no diff.

## 10. Checklist: regenerating the install baselines

Two baselines, one generator, one reference. `INSTALL/MYSQL.sql` and
`INSTALL/POSTGRESQL.sql` are both rendered by `dumpInstallBaseline` from a
MySQL/MariaDB database that has applied everything — the frozen legacy corpus
to 159 and every migration on disk — so a fresh install on either engine
starts at the current schema, with `db_version` 159 and every migration
recorded in `schema_migrations`, and runs no legacy update and no migration.
Existing instances are untouched by this: they climb the legacy corpus to 159
and then apply the migrations, exactly as before.

Regenerate both, from the same reference, once a migration has landed since
the last time — at the latest before a release. A baseline that lags the
migrations is not wrong, merely wasteful: a fresh install applies what is
missing. A baseline dumped from a reference that applied migrations **without**
recording them would be wrong — every fresh install would re-run them, and a
data step is author-guarded, not automatically idempotent — which is why the
ledger is a seed table and the reference is always a database that recorded
what it applied.

### 1. Build the reference

Never a working instance: whatever drift it has accumulated becomes canonical.
Build it from the previous release's baseline, so that the legacy corpus and
the migrations are what produced it:

```bash
mysql -e 'CREATE DATABASE misp_ref'
git show v2.5.45:INSTALL/MYSQL.sql | mysql misp_ref   # the last hand-maintained baseline, db_version 126
Console/cake Admin runUpdates                         # against misp_ref: legacy to 159, then every migration
Console/cake Admin migrationStatus                    # everything applied, nothing pending or failed
```

The generator refuses a reference that is not at the frozen `db_version`.
`runUpdates` works on the instance's default connection, so on a development
box point it at the reference from a probe shell for the duration rather than
editing `database.php`. **Legacy update 150 rewrites the `encoding` of every
connection in `app/Config/database.php` to a MySQL spelling** and leaves the
original as `database.php.bak-update-150`; a box whose default connection is
PostgreSQL has to restore that backup afterwards.

### 2. Render

```bash
Console/cake Admin dumpInstallBaseline --engine mysql --database misp_ref --output INSTALL/MYSQL.sql
Console/cake Admin dumpInstallBaseline --engine pgsql --database misp_ref --output INSTALL/POSTGRESQL.sql
Console/cake Admin dumpCurrentDatabaseSchema          # db_schema.json, from the same reference
```

`--database` names the reference on the connected server; the connected user
needs `SELECT` on it, and the connection has to be MySQL — the reference is
read through `information_schema`, which is what carries the column widths and
index prefixes the baseline needs. The notes on stderr list everything that is
not the reference's shape and are the review list, not noise:

- prefix-length indexes on text columns, rendered as hash indexes on
  PostgreSQL (equality lookups only) or with the prefix dropped where the
  index is unique;
- the PostgreSQL-only indexes a migration created through `rawSql()` on that
  engine alone (`BaselineGenerator::PGSQL_ONLY_INDEXES`), added because a
  fresh install seeds that migration as applied and would never create them;
- a default dropped from a key column, an index name PostgreSQL would
  truncate, any hint the grammar could not express.

The ledger is seeded automatically: `schema_migrations` is a seed table, so
whatever the reference recorded as applied is carried across. So are the
default dashboards a legacy update seeds. `admin_settings` is restricted to
`db_version`, `default_role` and `fix_login` (the install's own epoch).

### 3. Verify the round trip, on both engines

Load each file into an empty database, then compare what the driver reads back
with the reference:

```bash
Console/cake Admin verifyInstallBaseline --connection <loaded> --database misp_ref   # 0 findings
Console/cake Admin migrationStatus     # against the loaded database: all applied, nothing pending
Console/cake User init                 # the first admin, as an installer would
```

`<loaded>` is a connection in `database.php` pointing at the loaded database.
For PostgreSQL that can be a scratch schema in an existing database: `'schema'
=> 'baseline_check'` in the connection, and the file loaded with `SET
search_path TO baseline_check;` inserted after `BEGIN;`. The comparison names
every column, key and index that differs, in both directions, and knows which
deviations are the rendering being right — hash indexes, PostgreSQL-only
indexes, boolean defaults. Anything pending in `migrationStatus` means the
reference was not up to date.

### 4. What CI checks

The fresh-install job loads `INSTALL/MYSQL.sql`, runs `runUpdates` and asserts
that it had nothing to do: `db_version` 159, no pending migration. A second
step loads the previous release's `MYSQL.sql` out of git history into another
database, runs `runUpdates` there — the legacy corpus and then every
migration, the path every existing instance takes — and compares the result
with the fresh install through `verifyInstallBaseline`. That comparison is the
drift guard: the two ways in have to produce the same schema. Bump the tag the
legacy step pins when a release moves the baseline.

### Both files

- Keep the literal comment `Default values for initial installation` verbatim
  and once — `tools/misp-wipe/misp-wipe.sh` locates the seed block by matching
  it, drops the `admin_settings` lines, and replays the rest after a wipe.
  `admin_settings` is rendered one single-line statement per row for that
  filter's sake; ledger rows are `INSERT IGNORE` / `ON CONFLICT DO NOTHING`,
  so a replay is harmless. `misp-wipe.sql` does not truncate
  `schema_migrations`, and should not start to — a wipe clears data, not
  schema.
- Do not edit the generated DDL by hand. A column added to `MYSQL.sql` by hand
  is a column PostgreSQL never gets; a migration is what carries both engines,
  and the next regeneration carries it into both baselines.

## 11. Monitoring: what to alert on

Fleet monitoring has always watched one thing on the schema diagnostic: whether
`actual_db_version` differs from `expected_db_version`. **That comparison is
dead.** `db_version` is frozen at 159, so the two are the same number on every
instance, up to date or not — an instance with five migrations unapplied and one
failed reports exactly the version pair a healthy one does. Nothing breaks
loudly; the alert simply stops meaning anything. Move it.

The diagnostic is served as JSON over the API and carries the ledger's answer:

```bash
curl -s -H "Authorization: $AUTHKEY" -H "Accept: application/json" \
     https://misp.example/servers/dbSchemaDiagnostic
```

| Field | Type | Alert on |
|---|---|---|
| `migrations_pending` | int | `> 0` — migrations on disk the ledger does not record as applied. **The replacement for the version mismatch.** |
| `migrations_pending_ids` | list | The ids, in the order the next run applies them. Put them in the alert body: "which boxes are missing `M20260901_120000_x`" is answerable, "which boxes are below 159" no longer is. |
| `migrations_failed` | int | `> 0` — the ledger records a failure. **New signal**: the old scheme could not express it, because a later success used to advance `db_version` past the failure and reset the counter. Escalate on it. |
| `migrations_failed_ids` | list | The failed ids. A failed migration is still pending — it is retried first on the next run — so each one is in both lists. |
| `migrations_applied` | int | Drift between peers on the same release: two instances on the same code should agree. |
| `update_locked`, `remaining_lock_time`, `update_fail_number_reached` | as before | Unchanged, still meaningful. |

The fields are present on every engine, and they are present whether or not the
`schema_migrations` table exists yet — an instance that has never applied a
migration reports `migrations_applied = 0` and, if there are migrations on disk,
`migrations_pending` counting them.

**What a stuck instance looks like.** Because a failure halts the run (§7), a
blocked instance shows `migrations_failed = 1` alongside a `migrations_pending`
that counts the failed one *and* everything queued behind it. `actual_db_version`
and `expected_db_version` are both 159 while it does. That combination is the
state to page on, and it is the state the version pair can no longer show.

The same figures are on the diagnostics page in the UI — under *Schema status*
in the classic theme, in the *Database status* card in Overmind, with the pending
ids listed — and at the top of the CLI diagnostic:

```bash
Console/cake Admin schemaDiagnostics        # '# Migrations' block first: applied / failed / pending, with ids
Console/cake Admin migrationStatus --json   # the full ledger view, with each failure's recorded error
```

**Rollout.** Change the monitoring rule when the code that carries the ledger is
deployed, not after. Between the two, an instance behind on migrations is
invisible to a monitor still keyed on the version pair. The old rule can stay in
place alongside the new one — it will simply never fire again.

## 12. Where things are

| Path | What |
|---|---|
| `app/Lib/Migration/Migrations/` | The migrations |
| `app/Lib/Migration/Migration.stub` | Scaffold template. Not `.php`, and not in `Migrations/`, so it is neither discovered nor linted |
| `app/Lib/Migration/AbstractMigration.php` | The contract, and the id rules |
| `app/Lib/Migration/SchemaBuilder.php` | The DSL |
| `app/Lib/Migration/Grammar/` | Per-engine rendering, and the connectionless datasources `--dry-run` uses |
| `app/Lib/Migration/MigrationManager.php` | Discovery, the ledger, applying |
| `app/Lib/Migration/MigrationRunner.php` | Statement execution, logging, progress — shared with the legacy path |
| `app/Lib/Migration/LegacyMigrationsTrait.php` | The frozen corpus. Read, never edit |
