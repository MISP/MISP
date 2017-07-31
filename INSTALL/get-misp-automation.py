#!/usr/bin/env python

'''
Example file on how to get the exported IDS data from MISP

Add your API key, set the MISP host and define the output file.
'''

import urllib2

MISP_HOST="http:/"
API_KEY=""
EXPORT_DATA="events/nids/suricata/download"
OUTPUT_FILE="misp-suricata"

URL="%s/%s" % (MISP_HOST, EXPORT_DATA)
request = urllib2.Request(URL)
f = open(OUTPUT_FILE,'w')
request.add_header('Authorization', API_KEY)
data = urllib2.urlopen(request).read()
f.write(data)
f.close()
