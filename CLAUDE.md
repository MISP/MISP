# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MISP (Malware Information Sharing Platform) is an open-source threat intelligence sharing platform built on CakePHP 2.x. It enables organizations to share, store, and correlate indicators of compromise (IOCs) and threat intelligence.

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
app/Console/cake Admin runUpdates             # Run database migrations
app/Console/cake Admin schemaDiagnostics      # Check database schema
app/Console/cake Admin live 1                 # Enable/disable MISP

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

- **Main branch**: `2.5` (current stable), `2.4` (legacy stable until April 2025)
- **Development**: `develop` (main dev), `2.4-develop` (legacy dev)
- **Feature branches**: Branch from `2.5`, prefix with `fix-*` or `feature-*`

## Requirements

- PHP 8.1+ (8.2 recommended, <9.0)
- MySQL/MariaDB with UTF-8MB4
- Redis (caching, background jobs)
- Python 3.10+ (workers, PyMISP)

Required PHP extensions: json, mbstring, xml, dom, simplexml, pcre, curl
Recommended: gd, redis, openssl, apcu, ssdeep, bcmath
