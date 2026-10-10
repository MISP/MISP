# Testing MISP

MISP has three test layers. A behaviour is tested in the **highest-numbered
layer that can assert it, and no higher** — correlation strategies need model
internals, so they belong in layer 2, not layer 3; export formats are pure
transforms, so they belong in layer 1 even though the API also exercises them.

| Layer | May use | May NOT use | Answers |
|---|---|---|---|
| 1. Unit (PHP) | pure PHP, on-disk fixtures | DB, Redis, HTTP, network | "is this function correct for this input?" |
| 2. Integration (PHP) | DB, Redis, model internals | HTTP, auth stack | "do these components agree with each other?" |
| 3. Live (Python) | the full HTTP stack | — | "does the deployed system behave?" |

## Running the suites

```bash
# layer 1 - fast, no services required
cd app && composer install
./Vendor/bin/phpunit -c phpunit.xml

# layer 1 with coverage
./Vendor/bin/phpunit -c phpunit.xml --coverage-clover ../clover.xml

# layer 2 - needs a configured instance and database; its own config,
# because the unit stubs and the real CakePHP classes cannot share a process
cd app && sudo -u www-data ./Vendor/bin/phpunit -c phpunit-integration.xml

# layer 3 - needs a running, configured MISP instance
cd tests
export HOST=127.0.0.1 AUTH=<api key> PYTHONPATH=$PWD
python testlive_comprehensive_local.py -v
```

## Measuring coverage

The unit suite is measured by PHPUnit directly. The live suite drives MISP
over HTTP, so PHPUnit cannot attribute it; instead pcov is hooked into every
request and CLI call:

```bash
# 1. point php.ini (BOTH the web SAPI and CLI) at the collector
pcov.enabled=1
pcov.directory=/var/www/MISP/app
auto_prepend_file=/var/www/MISP/build/coverage/covcollect.php

# 2. arm collection only after the instance is set up, so install work
#    (schema import, runUpdates, updateJSON) is not counted as coverage
mkdir -p /cov && chmod 777 /cov && touch /cov/ENABLED

# 3. run the live suite, then merge and report
python3 build/coverage/merge_coverage.py /cov merged.json /var/www/MISP/app/
python3 build/coverage/report.py clover.xml merged.json
```

`report.py` intersects both suites with the same statement map, so unit, live
and union are directly comparable. Note that a line counted as covered was
*executed*, not necessarily *asserted*: an export that ran once for one
attribute type scores as covered regardless of whether it is correct for the
other forty.

Baseline on `ff132f4d`: **unit 1.77 %, live 18.46 %, union 19.67 %** of
117,925 statements.

## Environment preconditions

Each of these produced a confusing failure rather than a clear error message,
so check them first:

- **The `zip` binary must be installed** — not just `libzip-dev` or `ext-zip`.
  MISP shells out to `zip` when building attachment archives, and its absence
  surfaces as `proc_open(): posix_spawn() failed: No such file or directory`
  in an unrelated-looking part of the API.
- **`app/files/scripts/*` submodules must be initialised** (`misp-stix`,
  `cti-python-stix2`, `python-stix`, `python-cybox`, `mixbox`, `python-maec`),
  or the STIX paths fail the same way.
- **PyMISP needs its own `pymisp/data/misp-objects` submodule** plus
  `pip install ".[fileobjects]"`. Without it, object-building tests raise
  `NewAttributeError: The type of the attribute is required. Is the object
  template missing?`, which reads like a MISP bug and is not one.
- **`MISP.baseurl` must match the port the tests actually reach.** A mismatch
  makes `testlive_security.py` follow a redirect to a dead port and fail at
  `setUpClass` with a connection error.
- **`MISP.host_org_id` can only be set after `cake User init`** has created
  the organisation; setting it earlier is rejected with "Invalid organisation".
- **`Security.allow_self_registration` must be true** for
  `testlive_security.py`, which registers users.
- **PyMISP's `fast_mode`** gates `load_default_feeds()` and the galaxy /
  taxonomy / warninglist updates. With it on, `test_feeds` fails with an
  `UnboundLocalError` because the feed it looks for was never loaded.

## Never invoke a shell bare

`cake <Shell>` with no subcommand can run that shell's DEFAULT action.
**`cake Live` with no argument takes the instance OFFLINE.** Doing that once
while probing the console set `MISP.live=false` mid-run, and every
PyMISP-based suite afterwards failed to connect with an error that pointed at
PyMISP rather than at the cause.

`testlive_console.py` therefore probes each shell with an *invalid*
subcommand, which forces the option parser to print usage and exit, and
excludes `Live` and `Password` outright. A bare `cake` with no shell name is
safe - it only lists the available commands.

## Test isolation

`testlive_security.py` mutates global server settings and only restores them
on a clean exit. **Interrupting it leaves `Security.auth` set to
`ShibbAuth.ApacheShibb` in `app/Config/config.php`**, after which the login
page renders with no form and every later run fails at `setUpClass` — a
failure that looks nothing like its cause.

If that happens, remove the `'auth' => array('ShibbAuth.ApacheShibb')` entry
from `app/Config/config.php` and clear `app/tmp/cache/persistent/`.

Any live test that changes a server setting must record the previous value and
restore it in `tearDownClass`, and register an `atexit` handler so an
interrupted run still restores it.
