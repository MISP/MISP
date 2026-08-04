#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Export default feed list in Markdown format
#
# This tool is part of the MISP core project and released under the GNU Affero
# General Public License v3.0
#
# Copyright (C) 2017-2023 Alexandre Dulaunoy
# Copyright (C) 2023 Christophe Vandeplas

import json
import requests

default_feed = '../../app/files/feed-metadata/defaults.json'
misp_website_path = '../../../misp-website/content/feeds.md'
verify_certificate = False

with open(default_feed) as feed_file:
    feedlist = json.load(feed_file)


print("Checking feed availability.")
items = []
for feed in feedlist:
    output = "- [{}]({}) - {} - feed format: {}".format(feed['Feed']['name'], feed['Feed']['url'],feed['Feed']['provider'],feed['Feed']['source_format'])
    items.append(output)
    # try to download the feed
    headers = {"Range": "bytes=0-0"}
    res = requests.get(feed['Feed']['url'], headers=headers, verify=verify_certificate)
    if (res.status_code >= 200 and res.status_code < 300)\
            or res.status_code == 403:
        continue
    else:
        print(f'- Feed {feed["Feed"]["name"]} - returns {res.status_code}')


items = sorted(items, key=lambda s: s.casefold())

print("Updating misp-website feed.md file.")
start_header_seen = False
inserted = False
with open(misp_website_path, 'r') as f:
    data_new = []
    for line in f:
        if start_header_seen and line.startswith('- ') and not inserted:  # first item
            # add new content
            for item in items:
                data_new.append(item)
            inserted = True
        elif start_header_seen and line.startswith('- '):  # continue skipping
            continue
        else:
            data_new.append(line.strip())
        if inserted and line.startswith("#"):
            start_header_seen = False
        if line.startswith("## Default feeds"):
            start_header_seen = True


with open(misp_website_path, 'w') as f:
    f.write('\n'.join(data_new))
