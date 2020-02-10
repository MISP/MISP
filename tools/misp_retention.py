#!/usr/bin/env python3
#
# This script requires the MISP retention taxonomy is installed and enabled
# See https://github.com/MISP/misp-taxonomies/tree/master/retention/retention

from pymisp import ExpandedPyMISP, MISPEvent
from datetime import datetime
from dateutil.relativedelta import relativedelta
import re
from keys import misp_url, misp_key

# pip install pymisp python-dateutil


class misphelper(object):
    """Helper class around a MISP object."""
    taxonomyId = None
    expiredTag = "retention:expired"

    def __init__(self):
        self.misp = ExpandedPyMISP(url=misp_url,
                           key=misp_key,
                           ssl=True)
        self.taxonomyId = self.searchTaxonomy()

    def searchTaxonomy(self):
        res = self.misp.taxonomies()

        for tax in res:
            if (tax["Taxonomy"]["namespace"] == "retention" and tax["Taxonomy"]["enabled"]):
                return tax["Taxonomy"]["id"]

        raise Exception("Could not find the 'retention' Taxonomy in MISP. Please enable this first!")

    def processEvent(self, event):
        mevent = MISPEvent()
        mevent.from_dict(Event=event)
        changed = False

        for attr in mevent.attributes:
            if (attr["type"] == "ip-dst" or attr["type"] == "ip-src") and attr["to_ids"]:
                print("Removing IDS flag in event '{}' on attr '{}'".format(mevent.id, attr["value"]))
                changed = True
                attr["to_ids"] = False

        self.misp.tag(mevent, self.expiredTag, True)
        if changed:
            res = self.misp.update_event(mevent.id, mevent)

    def findEventsAfterRetention(self, events, retention):
        for event in events:
            ts = datetime.strptime(event["Event"]["date"], "%Y-%m-%d")
            now = datetime.utcnow()

            if retention[1] == "d":
                delta = relativedelta(days=int(retention[0]))
            elif retention[1] == "w":
                delta = relativedelta(weeks=int(retention[0]))
            elif retention[1] == "m":
                delta = relativedelta(months=int(retention[0]))
            elif retention[1] == "y":
                delta = relativedelta(years=int(retention[0]))

            if ts < (now - delta):
                self.processEvent(event["Event"])

    def queryRetentionTags(self):
        res = self.misp.get_taxonomy(self.taxonomyId)

        for tag in res['entries']:
            m = re.match(r"^retention:([0-9]+)([d,w,m,y])$", tag["tag"])
            if m:
                tagSearch = self.misp.build_complex_query(and_parameters = tag["tag"], not_parameters = self.expiredTag)
                events = self.misp.search(published=True, tags=tagSearch)
                self.findEventsAfterRetention(events, (m.group(1), m.group(2)))

            else:
                # set expiredTag to hidden if it was accidentally enabled by "enable all"
                if tag["tag"] == self.expiredTag:
                    if tag["existing_tag"]["Tag"]["hide_tag"] is False:
                        self.misp.edit_tag(tag["existing_tag"]["Tag"]["id"], hide_tag=True)
                else:
                    raise Exception("Could not parse retention time/unit from tag: '{}'.".format(tag["tag"]))


if __name__ == "__main__":
    misp = misphelper()
    misp.queryRetentionTags()
