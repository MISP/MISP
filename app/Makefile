
.PHONY: check-style check-style-ci
.PHONY: check-cpd check-cpd-ci
.PHONY: check-js check-js-ci
.PHONY: check-all-ci

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
