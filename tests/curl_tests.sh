#!/bin/bash

set -e
set -x

AUTH="$1"

curl -i -H "Accept: application/json" -H "content-type: application/json" -H "Authorization: $AUTH" --data "@event.json" -X POST http://misp.local/events
curl -H "Authorization: $AUTH"  -X GET http://misp.local/events/csv/download/1 | sed -e 's/^M//g' | cut -d, -f2 --complement > 1.csv
cat 1.csv
cut -d, -f2 --complement event.csv > compare.csv
diff compare.csv 1.csv
curl -H "Authorization: $AUTH"  -X GET http://misp.local/events/json/download/false/false/false/false/false/1d > 1.json
cat 1.json
diff event.json 1.json
