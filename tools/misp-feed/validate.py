import os
import sys
import json
import jsonschema

script_path = os.path.dirname(os.path.realpath(__file__))
default_feed_path = script_path + '/../../app/files/feed-metadata/defaults.json'
schema_path = script_path + '/../../app/files/feed-metadata/schema.json'

with open(default_feed_path) as feed_file:
    feedlist = json.load(feed_file)

with open(schema_path) as schema_file:
    schema = json.load(schema_file)

jsonschema.validate(instance=feedlist, schema=schema)

valid = True

for feed in feedlist:
    for json_field in ("rules", "settings"):
        if len(feed['Feed'][json_field]) == 0:
            continue
        try:
            json.loads(feed['Feed'][json_field])
        except ValueError:
            valid = False
            print("Invalid JSON for field `{}` for feed `{}`".format(json_field, feed['Feed']['name']))

if not valid:
    sys.exit(1)
