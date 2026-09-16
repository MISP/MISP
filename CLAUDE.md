# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MISP (Malware Information Sharing Platform) is an open-source threat intelligence sharing platform built on CakePHP 2.x. It enables organizations to share, store, and correlate indicators of compromise (IOCs) and threat intelligence.

Primary languages and projects: Rust (RustMISP, draugnet, warninglists), Python (PyMISP, MISP tooling), PHP/CakePHP (MISP core), JavaScript/HTML/CSS (MISP UI, Galaxy Editor). When asked to run tests, always confirm which project's tests to run before executing.

## Build and Development Commands

### PHP Dependencies
```bash
cd app && composer install
```

### Running Tests

**PHP Tests:**
```bash
# Lint PHP files
./app/Vendor/bin/parallel-lint --exclude app/Lib/cakephp/ --exclude app/Vendor/ -e php,ctp app/

# Run PHPUnit tests
./app/Vendor/bin/phpunit app/Test/
```

**Python Tests (PyMISP):**
```bash
cd PyMISP
poetry install -E fileobjects -E openioc -E virustotal -E docs -E pdfexport -E email
poetry run pytest tests/test_mispevent.py
poetry run pytest tests/testlive_comprehensive.py  # Requires running MISP instance
```

**Integration Tests:**
```bash
# Requires running MISP instance with AUTH key
cd tests
./curl_tests_GH.sh $AUTH_KEY $HOSTNAME
python3 testlive_comprehensive_local.py -v
python3 testlive_security.py -v
python3 testlive_sync.py -v
```

### Code Style Checks
```bash
cd app
make check-style      # PHP CodeSniffer (CakePHP standard)
make check-cpd        # PHP Copy/Paste Detector
```

### CLI Commands (CakePHP Console)
```bash
# User management
app/Console/cake User init                    # Initialize first admin user
app/Console/cake User add                     # Add new user
app/Console/cake Password resetPassword       # Reset password

# Server configuration
app/Console/cake Admin setSetting KEY VALUE   # Set configuration value
app/Console/cake Admin runUpdates             # Apply all outstanding DB updates
app/Console/cake Admin schemaDiagnostics      # Check database schema
app/Console/cake Admin live 1                 # Enable/disable MISP

# Database migrations (see docs/dev/database-migrations.md)
app/Console/cake Admin migrationStatus        # Applied / pending / failed
app/Console/cake Admin migrationApply --dry-run   # Print the SQL, per engine
app/Console/cake Admin migrationApply         # Apply pending migrations
app/Console/cake Admin migrationCreate slug   # Scaffold a new migration

# Event operations
app/Console/cake Event publish                # Publish events
app/Console/cake Event reindex                # Reindex correlations

# Background workers
app/Console/cake StartWorker                  # Start background workers
```

## Architecture Overview

### CakePHP 2.x Structure
- **Models** (`app/Model/`): Data access layer with behaviors. Core models: `Event`, `Attribute`, `Object`, `User`, `Org`, `SharingGroup`
- **Controllers** (`app/Controller/`): Request handling. `AppController` (71KB) provides auth, ACL, API handling base
- **Views** (`app/View/`): Template files (`.ctp`), organized by controller with `Elements/` for reusable components
- **Components** (`app/Controller/Component/`): Reusable controller logic - `RestSearchComponent`, `CRUDComponent`, `RestResponseComponent`
- **Behaviors** (`app/Model/Behavior/`): Reusable model logic - `AuditLogBehavior`, `CorrelationBehavior`

### Key Directories
- `app/Lib/Tools/`: Utility classes (57+ tools) - `AttachmentTool`, `CurlClient`, `BackgroundJobsTool`
- `app/Plugin/`: Auth plugins (LDAP, OIDC, AAD, Shibboleth), caching, logging
- `app/Console/Command/`: CLI shells for administration
- `app/files/`: Data storage (samples, taxonomies, galaxies, warninglists)
- `PyMISP/`: Python client library

### Request Flow
1. Apache/mod_rewrite → `app/webroot/index.php`
2. CakePHP Router (`app/Config/routes.php`) → Controller
3. `AppController::beforeFilter()` - Auth, ACL, session
4. Controller action uses Models with Behaviors
5. Response via `RestResponseComponent` for API calls

### Configuration Files
- `app/Config/database.php` - Database connection
- `app/Config/config.php` - MISP settings
- `app/Config/core.php` - CakePHP core settings
- `app/Config/bootstrap.php` - Plugin loading

## Coding Standards

- **Line length**: 80 characters max
- **Naming**: `ClassName`, `someVariable`, `someFunction`
- **PHP files**: Title case (`AttachmentTool.php`)
- **Python files**: Lowercase with underscores (`load_warninglists.py`)
- **JavaScript files**: Lowercase with dashes (`bootstrap-colorpicker.js`)

## Commit Message Format

Use gitchangelog prefixes for automatic changelog generation:
```
new: [category] Description (#ISSUE)   # New features
fix: [category] Description (#ISSUE)   # Bug fixes
chg: [category] Description (#ISSUE)   # Refactoring/changes
```

Example: `fix: [api] Correct attribute validation (#3120)`

## Git Workflow

- **`develop`** — the default target for ordinary work. Smaller changes (bug
  fixes, cleanups, small improvements) are committed here directly.
- **`2.5`** — current stable. Receives `develop` through a merge at release
  time. Take direct commits on `2.5` **only** for an urgent hotfix outside the
  release cycle.
- **Feature branches** — for larger changes such as full-fledged new features.
  Branch from `develop`, prefix with `fix-*` or `feature-*`, and fold back into
  `develop` once ready to ship. External contributions often branch from
  somewhere else; expect that on incoming PRs.

A release is cut by merging `develop` into `2.5`, and **`develop`'s CI/CD is
the go/no-go** for that merge. Right after a release `develop` and `2.5` are
identical — that is expected, not a sign of drift.

When in doubt about where a change belongs, it belongs on `develop`.

## Requirements

- PHP 8.1+ (8.2 recommended, <9.0)
- MySQL/MariaDB with UTF-8MB4
- Redis (caching, background jobs)
- Python 3.10+ (workers, PyMISP)

Required PHP extensions: json, mbstring, xml, dom, simplexml, pcre, curl
Recommended: gd, redis, openssl, apcu, ssdeep, bcmath

## MISP Development

When working with CakePHP (MISP), always verify query result structures before assuming array shapes. CakePHP find() returns vary by type (first/all/list) and version.

### Database schema changes — migrations, never `DB_CHANGES`

Any change to the database schema is a **migration** under `app/Lib/Migration/Migrations/`. Never add a case to `AppModel::DB_CHANGES` or to `LegacyMigrationsTrait`: that corpus is frozen at `db_version` 159, the freeze is enforced at runtime and by `LegacyCorpusFreezeTest`, and an added case fails the build.

`docs/dev/database-migrations.md` is the full reference. The load-bearing parts:

1. Scaffold with `app/Console/cake Admin migrationCreate <slug>` — never hand-name the file. A migration's id *is* its file name (class name minus the `Migration_` prefix), so the two cannot be allowed to disagree.
2. Declare DDL in `up(SchemaBuilder $schema)` against the flavour-agnostic DSL, not as raw SQL. Raw SQL in a migration is raw MySQL.
3. Data work goes in `afterUp()`, through models (`save()`/`updateAll()`), never as hand-written DML — and call `$Model->schema(true)` on any table the migration just altered, or writes to a new column are silently dropped.
4. Always read `app/Console/cake Admin migrationApply --dry-run --id <id>` before applying. It renders **both** engines; the PostgreSQL half is the one nothing else will check, since a MISP host cannot connect to PostgreSQL at all.
5. `rawSql()` is the escape hatch for things with no portable spelling (FULLTEXT, enum, version-gated statements). It requires a statement for every engine — a missing one is a hard error, not a skip.
6. **Do not touch `db_schema.json`.** It is regenerated wholesale from a clean build before a release, not maintained per migration, so `schemaDiagnostics` reporting your change as a difference in the meantime is expected. Never run `dumpCurrentDatabaseSchema` against a working development instance and commit the result — it promotes that box's accumulated drift to canonical.
7. Regenerating `INSTALL/MYSQL.sql` now also has to seed `schema_migrations` with the ids already baked into the dump, or fresh installs re-run every migration. Checklist in the doc's final section.

### Dashboard v2 — widget render kinds

When adding a new widget render kind (any new value for `public $render` on a class under `app/Lib/Dashboard/`, or a new template under `app/View/Elements/dashboard/Widgets/`), you must also add a matching glyph to `app/webroot/js/dashboard/gallery/render-thumbs.mjs`. The Add Widget gallery uses these glyphs as fallback thumbnails for any widget that doesn't declare `$thumbnail`, so a new render kind without a glyph ships as a generic block in every gallery card that uses it. Steps:
1. Add a `thumb<Name>()` builder following the existing pattern (single-color SVG, 80×45 viewBox, `currentColor` strokes/fills).
2. Register it in the `REGISTRY` object at the bottom of the file under the exact `$render` string.
3. The glyph should visually evoke the widget's output shape, not its data domain — a bar chart is bars regardless of whether it's counting events or orgs.

## Debugging

When fixing bugs, always verify the root cause by comparing git blame/diff of the specific change before proposing a fix. Do not conclude old and new code are equivalent without tracing actual execution paths.

## CI/CD

For CI/CD workflow debugging, always check: database connection strings (localhost vs 127.0.0.1), file permissions for web server user traversal, cache directory ownership, and ensure test output isn't polluted by warnings/deprecation notices.
