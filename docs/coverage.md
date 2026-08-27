# Code coverage

`.github/workflows/coverage.yml` measures how much of MISP the existing test
suites actually execute, and fails if that number goes backwards.

## Why two measurements

MISP is tested from two directions, and neither one alone is the answer:

* **`app/Test/`** runs under PHPUnit, which measures its own coverage.
* **`tests/testlive_*.py`, `PyMISP/tests/testlive_comprehensive.py` and
  `tests/curl_tests_GH.sh`** drive a running instance over HTTP. PHPUnit is
  not in that process and cannot attribute a single line of it.

The live suites are where most of MISP's controllers and models are actually
exercised, so a report that ignored them would understate coverage badly and
point refactoring effort at the wrong places.

`build/coverage/covcollect.php` closes the gap. It is hooked in as
`auto_prepend_file` for **both** the Apache and CLI SAPIs, starts pcov on
every request and console invocation, and writes one JSON capture per process
on shutdown. `build/coverage/merge_coverage.py` merges the captures;
`build/coverage/report.py` intersects them with PHPUnit's clover report - which
supplies the denominator, i.e. every executable statement in the tree - and
prints unit, live, union and overlap, plus a per-subsystem breakdown.

Collection only starts once `$MISP_COV_DIR/ENABLED` exists, which is how
instance setup (`runUpdates`, `updateJSON`, the schema import) is kept out of
the numbers: it is not test coverage.

## The ratchet

The job fails when the union of the two suites covers fewer than
`MIN_UNION_LINES` distinct statements.

It gates on **lines, not on a percentage**, because the percentage has a
denominator nobody controls per-PR: merging a large feature adds untested
statements and drops the percentage without any test having stopped working.
A gate that a legitimate merge turns red is a gate people learn to lower.
Covered lines fall only when the tests stop executing code.

Raise `MIN_UNION_LINES` as tests land. The percentage is still reported.

## Running it locally

Against an instance you already have configured (adjust the paths):

```bash
# 1. PHPUnit, with coverage, needs pcov or xdebug
cd app && ./Vendor/bin/phpunit -c phpunit.xml --coverage-clover ../clover.xml

# 2. instrument the live suite - in php.ini for BOTH the web SAPI and CLI
#    pcov.enabled=1
#    pcov.directory=/var/www/MISP/app
#    auto_prepend_file=/var/www/MISP/build/coverage/covcollect.php
mkdir -p /tmp/cov && chmod 777 /tmp/cov
cat > build/coverage/covconfig.php <<'EOF'
<?php
return ['cov_dir' => '/tmp/cov', 'app_root' => '/var/www/MISP/app/'];
EOF
touch /tmp/cov/ENABLED          # from here on, everything is recorded

# 3. run the live suites, then merge and report
python3 build/coverage/merge_coverage.py /tmp/cov merged.json /var/www/MISP/app/
python3 build/coverage/report.py clover.xml merged.json --min-union-lines 15000
```

`covconfig.php` is gitignored: it holds machine-specific absolute paths. It
exists because Apache is started before the workflow step that exports
`MISP_COV_DIR`, so mod_php never sees those variables and would otherwise fall
back to defaults that match nothing.

`build/coverage/test_report.py` covers the reporter itself - in particular
that the union counts a line once however many suites covered it. Run it with
`python3 -m pytest build/coverage/test_report.py`.
