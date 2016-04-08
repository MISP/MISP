
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

frontend-deps:
	# Twitter Bootstrap 3.x stuff
	wget -qO- https://github.com/twbs/bootstrap/releases/download/v3.3.6/bootstrap-3.3.6-dist.zip | bsdtar --strip-components 1 -C webroot/ -xvf-
	# bootstrap-colorpicker
	wget -qO- https://github.com/mjolnic/bootstrap-colorpicker/archive/2.3.0.tar.gz | tar -C webroot/ --strip-components 2 -xzv bootstrap-colorpicker-2.3.0/dist/
	# bootstrap-timepicker
	wget -qO- https://github.com/jdewit/bootstrap-timepicker/releases/download/v0.5.2/bootstrap-timepicker.tar.gz | tar -C webroot/ --strip-components 1 --exclude="*.json" --exclude="*.md" --exclude="*.less" -xzv
	# bootstrap-datepicker
	wget -qO- https://github.com/eternicode/bootstrap-datepicker/releases/download/v1.6.0/bootstrap-datepicker-1.6.0-dist.zip | tar -C webroot/ -xvf-
	# jQuery stuff
	wget -q -O webroot/js/jquery.min.js https://code.jquery.com/jquery-2.2.3.min.js
	wget -q -O webroot/js/jquery-ui.min.js https://code.jquery.com/ui/1.11.4/jquery-ui.min.js
	wget -q -O webroot/css/jquery-ui.css https://code.jquery.com/ui/1.11.4/themes/flick/jquery-ui.css
	# D3js
	wget -q -O webroot/js/d3.v3.min.js https://d3js.org/d3.v3.min.js
