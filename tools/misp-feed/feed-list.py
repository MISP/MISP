#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Export default feed list in Markdown format
#
# This tool is part of the MISP core project and released under the GNU Affero
# General Public License v3.0
#
# Copyright (C) 2017 Alexandre Dulaunoy

import json


default_feed = '../../app/files/feed-metadata/defaults.json'

with open(default_feed) as feed_file:
    feedlist = json.load(feed_file)


for feed in feedlist:
    output = "- [{}]({}) - {} - feed format: {}".format(feed['Feed']['name'], feed['Feed']['url'],feed['Feed']['provider'],feed['Feed']['source_format'])
    print (output)
