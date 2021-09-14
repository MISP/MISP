help:
	@echo "Please use \`make <target>' where <target> is one of"
	@echo "  test [suite=api]       to run tests. use suite=[unit|api] optional argument to specify test suite."
	@echo "  check-style            to check CakePHP coding style."
	@echo "  check-style-ci         to check CakePHP coding style with output report for CI."
	@echo "  check-cpd              to run PHP Copy/Paste Detector."
	@echo "  check-cpd-ci           to run PHP Copy/Paste Detector with output report for CI."
	@echo "  check-js               to check Javascript coding style."
	@echo "  check-all-ci           to run all checks with output report for CI."

.PHONY: check-style check-style-ci
.PHONY: check-cpd check-cpd-ci
.PHONY: check-js check-js-ci
.PHONY: check-all-ci
.PHONY: test

# Both these command exit non-0 when any violations occur
# We want to ignore that so we can get all the results in jenkins
.IGNORE: check-style-ci check-cpd-ci

check-style:
	phpcs --standard=CakePHP --extensions=php,ctp -p ./

check-style-ci:
	phpcs --standard=CakePHP \
		--extensions=php,ctp -p --report=checkstyle \
		--report-file=build/checkstyle.xml ./

check-cpd:
	phpcpd --min-lines 3 --min-tokens 50 --names *.php ./

check-cpd-ci:
	phpcpd --min-lines 3 --min-tokens 50 \
		--names *.php --log-pmd build/pmd.xml ./

check-js:
	#jshint webroot/js --config app/Config/jshint.json

check-all-ci: check-style-ci check-cpd-ci check-js

test: $(suite="api")
	Vendor/bin/codecept build
	Vendor/bin/codecept run $(suite)