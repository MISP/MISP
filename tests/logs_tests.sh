#!/usr/bin/env bash
ERROR_MESSAGE="Errors found in logs !"
# exit 0 of grep = match found, so we need to exit 1 on this use-case.
grep -HE -f tests/logs_fail_regexes.txt `pwd`/app/tmp/logs/* && echo $ERROR_MESSAGE && exit 1
grep -HE -f tests/logs_fail_regexes.txt /var/log/apache2/*.log && echo $ERROR_MESSAGE && exit 1
zgrep -HE -f tests/logs_fail_regexes.txt /tmp/logs.json.gz && echo $ERROR_MESSAGE && exit 1
# exit cleanly because grep found nothing, and did exit 1.
exit 0