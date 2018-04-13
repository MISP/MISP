#!/usr/bin/env python

'''
Example file on how to get the exported IDS data from MISP

Add your API key and SSL client certificate file,
set the MISP host and define the output file.
'''

import urllib2, httplib

MISP_HOST="http:/"
API_KEY=""
CERT_FILE="/path/to/file.pem"
EXPORT_DATA="events/nids/suricata/download"
OUTPUT_FILE="misp-suricata"

class HTTPSClientAuthHandler(urllib2.HTTPSHandler):
    def __init__(self, key, cert):
        urllib2.HTTPSHandler.__init__(self)
        self.key = key
        self.cert = cert

    def https_open(self, req):
        # Rather than pass in a reference to a connection class, we pass in
        # a reference to a function which, for all intents and purposes,
        # will behave as a constructor
        return self.do_open(self.getConnection, req)

    def getConnection(self, host, timeout=300):
        return httplib.HTTPSConnection(host, key_file=self.key, cert_file=self.cert)

URL="%s/%s" % (MISP_HOST, EXPORT_DATA)
opener = urllib2.build_opener(HTTPSClientAuthHandler(CERT_FILE, CERT_FILE))
opener.addheaders = [('Authorization', API_KEY)]
data = opener.open(URL).read()
f = open(OUTPUT_FILE,'w')
f.write(data)
f.close()
