#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
from simplejson.decoder import JSONDecodeError

from pymisp import PyMISP
from keys import url, key


misp = PyMISP(url, key, True, 'json')

try:
    event = misp.new_event(0, 1, 0, "This is a test")
    print(event)
    print(json.dumps(event, indent=2))
except JSONDecodeError as e:
    print(e.doc)
    exit(0)
