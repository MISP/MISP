#!/usr/bin/env bash
set -e
set -o xtrace

# Check if dependencies for zmq are properly installed
python ./../app/files/scripts/mispzmq/mispzmqtest.py

# Check if all attachments handlers dependencies are correctly installed
python ./../app/files/scripts/generate_file_objects.py -c | python3 -c 'import sys, json; data = json.load(sys.stdin); print(data); sys.exit(0 if len([i for i in data.values() if i is not False]) == 0 else 1)'

# Try to extract data from file
python ./../app/files/scripts/generate_file_objects.py -p /bin/ls | python3 -c 'import sys, json; data = json.load(sys.stdin); sys.exit(0 if "objects" in data else 1)'

# Test converting stix1 to MISP format
curl -sS --compressed https://stixproject.github.io/documentation/idioms/c2-indicator/indicator-for-c2-ip-address.xml > ./../app/files/scripts/tmp/test-stix1.xml
python ./../app/files/scripts/stix2misp.py test-stix1.xml 1 1 ./../app/files/scripts/synonymsToTagNames.json | python3 -c 'import sys, json; data = json.load(sys.stdin); print(data); sys.exit(0 if data["success"] == 1 else 1)'
rm -f ./../app/files/scripts/tmp/{test-stix1.xml,test-stix1.xml.json}

# Test converting STIX2 to MISP format
curl -sS --compressed https://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/master/examples/indicator-for-c2-ip-address.json > ./../app/files/scripts/tmp/test-stix2.json
python ./../app/files/scripts/stix2/stix2misp.py -i ./../app/files/scripts/tmp/test-stix2.json --distribution 1 | python3 -c 'import sys, json; data = json.load(sys.stdin); print(data); sys.exit(0 if data["success"] == 1 else 1)'
python3 -c 'import sys, json; json.load(sys.stdin)' < ./../app/files/scripts/tmp/test-stix2.json.out
rm -f ./../app/files/scripts/tmp/{test-stix2.json,test-stix2.json.stix2}

# Test converting MISP to STIX2
cp event.json /tmp/
python ./../app/files/scripts/stix2/misp2stix2.py -i /tmp/event.json | python3 -c 'import sys, json; data = json.load(sys.stdin); print(data); sys.exit(0 if data["success"] == 1 else 1)'
python3 -c 'import sys, json; json.load(sys.stdin)' < /tmp/event.json.out
rm -f /tmp/{event.json,event.json.out}
