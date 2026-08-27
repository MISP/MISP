#!/usr/bin/env bash
# Run the live (Python) test suite against a configured MISP instance.
#
# Individual suite failures do not abort the run: the goal is to exercise as
# much of the application as possible and then report coverage. Suite results
# are printed, and each suite is grouped in the log, so a regression is still
# visible. The gate for this workflow is the coverage ratchet, not these
# suites - .github/workflows/main.yml is where they gate.
set -uo pipefail

WORKSPACE="${GITHUB_WORKSPACE:-$(pwd)}"
HOST="${HOST:-127.0.0.1}"
AUTH="${AUTH:-$(cat "$WORKSPACE/key.txt")}"

cd "$WORKSPACE"

python3 -m virtualenv -p python3 ./venv
# shellcheck disable=SC1091
. ./venv/bin/activate
pip install -q -r requirements.txt
pip install -q pytest lxml ./PyMISP

# Only now does the interpreter exist, so this is where MISP can be pointed
# at it - setting it during install is rejected as "Binary file not
# executable". Several suites (and the enrichment/export paths they touch)
# shell out to it.
sudo -u www-data app/Console/cake Admin setSetting "MISP.python_bin" "${WORKSPACE}/venv/bin/python"

cat > PyMISP/tests/keys.py <<KEYS
url = "http://${HOST}"
key = "${AUTH}"
KEYS
cp PyMISP/tests/keys.py tests/keys.py
cp PyMISP/tests/keys.py PyMISP/keys.py

export HOST AUTH
export PYTHONPATH="${WORKSPACE}/tests"
export MISP_ROOT="${WORKSPACE}"

status=0

# main.yml checks this repository out as a workflow step; doing it here keeps
# the dependency in one place. Its binary samples are what PyMISP's attachment
# and file-object tests read - without them those tests skip, and the code
# paths behind them go unmeasured.
if [ ! -d PyMISP/tests/viper-test-files ]; then
    git clone --depth 1 https://github.com/viper-framework/viper-test-files.git \
        PyMISP/tests/viper-test-files || true
fi

# PyMISP's suite runs FIRST, exactly as main.yml orders it, and the order is
# load-bearing: PyMISP's setUpClass and tests/testlive_comprehensive_local.py's
# both create an organisation literally named 'Test Org'. PyMISP's tears its
# own down; the local one does not. So PyMISP first leaves a clean table for
# the local suite, while local first makes add_organisation return
#   {'errors': ...}  -> cls.test_org is a dict -> AttributeError at
#   testlive_comprehensive.py:96 (user.org_id = cls.test_org.id)
# and every one of its tests errors in setUpClass in about seven seconds,
# contributing no coverage at all.
echo "::group::PyMISP testlive_comprehensive"
( cd PyMISP && python -m pytest -q --no-header tests/testlive_comprehensive.py ) || status=1
echo "::endgroup::"

# The first three are the suites main.yml runs. The remaining four live in
# tests/ but no workflow currently runs them; they are included because this
# job's purpose is to measure how much of MISP the existing tests reach.
for suite in testlive_comprehensive_local testlive_sync testlive_security \
             testlive_event_addtag testlive_event_mass_actions \
             testlive_event_templates testlive_collection_sync; do
    echo "::group::${suite}"
    ( cd tests && python "${suite}.py" -v ) || status=1
    echo "::endgroup::"
done

deactivate
echo "live suite finished (aggregate status ${status}); coverage captures: $(ls "${MISP_COV_DIR:-/cov}"/*.json 2>/dev/null | wc -l)"
exit 0
