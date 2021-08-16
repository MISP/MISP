#!/usr/bin/env bash

set -e
set -x

AUTH="$1"
HOST="$2"

# Check if user is logged
curl -i -H "Authorization: $AUTH" -H "Accept: application/json" -X GET http://${HOST}/servers/getVersion
curl -i -H "Accept: application/json" -H "content-type: application/json" -H "Authorization: $AUTH" --data "@event.json" -X POST http://${HOST}/events > /dev/null
curl -H "Authorization: $AUTH"  -X GET http://${HOST}/events/csv/download/1/ignore:1 | sed -e 's/^M//g' | cut -d, -f2 --complement | sort > 1.csv
cat 1.csv
cut -d, -f2 --complement event.csv | sort > compare.csv
diff compare.csv 1.csv
# Test alert email generating
sudo -E su $USER -c '../app/Console/cake Event testEventNotificationEmail 1 1' > /dev/null
# Delete created event
curl -i -H "Accept: application/json" -H "content-type: application/json" -H "Authorization: $AUTH" -X POST http://${HOST}/events/delete/1
