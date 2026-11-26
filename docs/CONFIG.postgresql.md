# Running MISP on PostgreSQL

MISP can be installed on PostgreSQL as an alternative to MySQL / MariaDB.
This is a **fresh-install** path: an existing MySQL instance is not migrated
by anything described here.

Support status, honestly: the schema, the upgrade system and the application's
SQL are engine-neutral, and an instance boots, upgrades, creates users and
events, correlates and publishes on PostgreSQL 16. What has not been done is
performance work at scale, and CI does not yet run the test suite against
PostgreSQL. Treat it accordingly.

## What is different from a MySQL install

Only the database steps. Everything else in the platform install guide —
packages, PHP, Redis, workers, the web server — is the same.

- The database is created by loading `INSTALL/POSTGRESQL.sql`, which is a
  complete schema at the frozen legacy `db_version` (159) plus the seed rows a
  fresh instance starts with. The legacy update corpus is MySQL-only and is
  never replayed on PostgreSQL; the ledger-tracked migrations under
  `app/Lib/Migration/Migrations/` carry both engines forward from that point.
- `app/Config/database.php` uses the `Database/PostgresObserverExtended`
  datasource. It is the only PostgreSQL datasource MISP ships, and it does for
  PostgreSQL what `MysqlObserverExtended` does for MySQL.
- The On Demand correlation engine and the search benchmark are MySQL-only and
  refuse to run. The Default engine is what a PostgreSQL instance uses.

## Requirements

- PostgreSQL 13 or later. Developed and verified against 16.
- The `pdo_pgsql` PHP extension (`php-pgsql` on Debian/Ubuntu, `php-pgsql` on
  RHEL), for the CLI, php-fpm and Apache alike.
- A database created with **UTF8** encoding. MISP does not set encoding per
  table or column on PostgreSQL; the database does.

## Install

1. Create the role and the database:

   ```sql
   CREATE ROLE misp LOGIN PASSWORD 'change me';
   CREATE DATABASE misp OWNER misp ENCODING 'UTF8';
   ```

   The owner of the database owns its `public` schema, which is what MISP
   needs to create and alter tables there.

2. Load the baseline:

   ```bash
   psql -h 127.0.0.1 -U misp -d misp -v ON_ERROR_STOP=1 -f /var/www/MISP/INSTALL/POSTGRESQL.sql
   ```

   The file is one transaction, so a failed load leaves an empty database
   rather than half of one.

3. Configure the connection in `app/Config/database.php`:

   ```php
   public $default = [
       'datasource' => 'Database/PostgresObserverExtended',
       'persistent' => false,
       'host' => '127.0.0.1',
       'login' => 'misp',
       'port' => 5432,
       'password' => 'change me',
       'database' => 'misp',
       'schema' => 'public',
       'prefix' => '',
       'encoding' => 'utf8',
       'flags' => [
           PDO::ATTR_STRINGIFY_FETCHES => true
       ]
   ];
   ```

   `schema` is the namespace the tables live in and must match where the
   baseline was loaded; `public` unless you changed it. Keep
   `ATTR_STRINGIFY_FETCHES` on — MISP expects it on every engine.

4. Bring the database up to date and create the first user, exactly as on
   MySQL:

   ```bash
   sudo -u www-data /var/www/MISP/app/Console/cake Admin runUpdates
   sudo -u www-data /var/www/MISP/app/Console/cake User init
   ```

   On a freshly loaded baseline `runUpdates` finds nothing to do unless a
   migration newer than the baseline has landed in the tree, in which case it
   applies it and records it in `schema_migrations`.
   `Console/cake Admin migrationStatus` shows the ledger.

## Knowing what changed

A few things are deliberately not what MySQL has. None of them need action;
they are listed so nobody discovers them the hard way.

- **Flags are boolean.** Every `tinyint(1)` column is `boolean` on PostgreSQL.
  The application still sees `"1"` and `"0"` — the datasource sees to that —
  but hand-written SQL against those columns must say `TRUE` / `FALSE`, not
  `1` / `0`.
- **Text comparison is exact.** MySQL's case-insensitive collations do not
  carry over; PostgreSQL compares text as-is.
- **Some indexes are hash indexes.** MySQL indexes the first 255 characters of
  `attributes.value1`, `events.info` and seven similar text columns. PostgreSQL
  has no prefix indexes, and a full-column btree would reject values longer
  than about 2.7 KB, which MISP stores routinely. Those columns carry a hash
  index instead: equality lookups, which is how they are queried, at the cost
  of no ordered scans.
- **No FULLTEXT.** MySQL-only. Nothing in MISP requires it.
- **`schemaDiagnostics` declines.** The expected-schema file it compares
  against is a MySQL dump, so on PostgreSQL the diagnostic reports that it is
  not available rather than a meaningless diff. `Admin verifyInstallBaseline`
  is the PostgreSQL-side check against a reference database.

## For developers

- `INSTALL/POSTGRESQL.sql` is generated, not hand-edited. The regeneration
  procedure is in `docs/dev/database-migrations.md`.
- A migration is written once, against the schema DSL, and
  `Console/cake Admin migrationApply --dry-run` prints its rendering for both
  engines — including the one your host cannot connect to. Read the
  PostgreSQL half; nothing else will.
- The archived guides under `docs/archive/` and `INSTALL/old/` describe an
  older, abandoned PostgreSQL path and the files they load no longer exist.
