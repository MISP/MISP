#!/usr/bin/env python3
"""Golden-snapshot contract for restSearch.

`AppController::restSearch` (app/Controller/AppController.php:1523) is one
generic seam serving every controller, which makes it the highest-leverage
thing to pin: a single suite covers the response contract of the whole REST
surface. It is also precisely what a reviewer would otherwise verify by
clicking around, which is the manual step this replaces.

The fixture is deterministic - a fixed set of attribute types and values - so
the only variation between runs is the volatile identity data that
lib/snapshots.py aliases away.

    HOST=127.0.0.1 AUTH=<key> python3 testlive_restsearch_contract.py -v
    UPDATE_SNAPSHOTS=1 ... to re-record after an intended change
"""
import os
import sys
import unittest
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib.misp_live import MispApi  # noqa: E402
from lib import snapshots  # noqa: E402

# Formats needing an external toolchain or extra request parameters. Excluded
# from the matrix so that every OTHER format is genuinely required to work.
UNAVAILABLE = {
    "stix": "python STIX bridge",
    "stix2": "python STIX bridge",
    "stix-xml": "python STIX bridge",
    "yara": "needs a configured rule store",
    "yara-json": "needs a configured rule store",
    "opendata": "needs a 'setup' filter naming the dataset",
}

FORMATS = [
    "json", "xml", "csv", "text", "openioc", "snort", "suricata",
    "rpz", "netfilter", "hashes", "hosts", "bro",
    "attack-sightings", "context-markdown", "count", "cache", "kunai",
]

# `attack` and `context` are deliberately absent. Both embed the resolved
# galaxy corpus in the response, so their golden files are ~5 MB each - 99%
# of the bytes this suite would add to the repository, for two of nineteen
# formats. `attack-sightings` and `context-markdown` exercise the same two
# code paths at a fraction of the size.

# Behaviour recorded as-is because it is wrong; see ADR 0002. The value names
# the specification test that asserts what SHOULD happen.
KNOWN_DEFECTS = {
    "text": "returnFormat=text emits no values, while json/csv/netfilter "
            "return them for the identical query. See "
            "testlive_export_formats.test_text_format_lists_values_one_per_line",
}

# Defects that apply only to the event scope.
#
# CacheExport had the identical bug and was fixed upstream in e06cb68844; it is
# deliberately NOT listed here. An annotation naming a fixed defect is worse
# than none, because it teaches the reader to distrust the others.
KNOWN_DEFECTS_EVENT_SCOPE = {
    "netfilter": "NetfilterExport.php:39 binds $attribute in the loop but then "
                 "reads $data['Attribute']['type'] - the LIST - so every iteration "
                 "raises 'Undefined array key type' and no rules are emitted. "
                 "Fix proposed upstream: MISP/MISP#10965.",
}


class TestRestSearchContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.api = MispApi()
        cls.event_uuid = str(uuid.uuid4())
        cls.event_id = cls._create_event()

    @classmethod
    def _create_event(cls):
        payload = {"Event": {
            "info": "restSearch contract fixture",
            "uuid": cls.event_uuid,
            "distribution": 0, "analysis": 0, "threat_level_id": 1,
            "Attribute": [
                {"category": "Network activity", "type": "ip-dst", "value": "8.8.8.8", "to_ids": True},
                {"category": "Network activity", "type": "ip-src", "value": "1.1.1.1", "to_ids": True},
                {"category": "Network activity", "type": "domain", "value": "example.com", "to_ids": True},
                {"category": "Network activity", "type": "url", "value": "http://example.com/x", "to_ids": True},
                {"category": "Payload delivery", "type": "md5",
                 "value": "d41d8cd98f00b204e9800998ecf8427e", "to_ids": True},
                {"category": "Payload delivery", "type": "sha256", "value": "a" * 64, "to_ids": True},
                {"category": "Payload delivery", "type": "filename", "value": "evil.exe", "to_ids": True},
                {"category": "Other", "type": "comment", "value": "a comment", "to_ids": False},
            ],
        }}
        response = cls.api.json("POST", "/events/add", json=payload)
        if isinstance(response, dict) and "Event" in response:
            event = response["Event"]
            # Auto-increment ids differ every run and leak into text formats
            # that no regex can safely normalise; record them so the snapshot
            # harness can alias them by exact value.
            cls.volatile = [event.get("id"), event.get("uuid")]
            cls.volatile += [a.get("id") for a in event.get("Attribute", [])]
            cls.volatile += [a.get("uuid") for a in event.get("Attribute", [])]
            return event.get("id")
        cls.volatile = []
        return None

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.event_id:
            cls.api.post(f"/events/delete/{cls.event_id}", json_body={})

    def setUp(self) -> None:
        if not self.event_id:
            self.skipTest("could not create the fixture event")

    def _fetch(self, scope: str, body: dict) -> str:
        response = self.api.post(f"/{scope}/restSearch", json_body=body)
        self.assertLess(response.status_code, 500,
                        f"{scope}/restSearch 5xx for {body}: {response.text[:200]}")
        return response.text

    def _check(self, name: str, raw: str, defect: str | None = None) -> None:
        normalised = snapshots.normalise_response(raw, getattr(self, "volatile", []))
        ok, message = snapshots.compare(name, normalised, known_defect=defect)
        self.assertTrue(ok, message)

    def test_event_scope_formats(self) -> None:
        """Pin the event-scoped response of every available return format."""
        for fmt in FORMATS:
            if fmt in UNAVAILABLE:
                continue
            with self.subTest(returnFormat=fmt):
                raw = self._fetch("events", {"returnFormat": fmt, "eventid": self.event_id})
                defect = KNOWN_DEFECTS.get(fmt) or KNOWN_DEFECTS_EVENT_SCOPE.get(fmt)
                self._check(f"restsearch_events_{fmt}", raw, defect)

    def test_attribute_scope_formats(self) -> None:
        """The attribute scope takes different branches through the same seam."""
        for fmt in ["json", "csv", "text", "hashes", "snort", "suricata", "netfilter", "count"]:
            with self.subTest(returnFormat=fmt):
                raw = self._fetch("attributes", {"returnFormat": fmt, "eventid": self.event_id})
                self._check(f"restsearch_attributes_{fmt}", raw, KNOWN_DEFECTS.get(fmt))

    def test_filters_shape_the_result(self) -> None:
        """Filters are where restSearch does most of its work."""
        cases = {
            "type_single": {"type": "ip-dst"},
            "type_list": {"type": ["ip-dst", "domain"]},
            "category": {"category": "Payload delivery"},
            "to_ids_true": {"to_ids": 1},
            "to_ids_false": {"to_ids": 0},
            "value_exact": {"value": "8.8.8.8"},
            "limit_two": {"limit": 2, "page": 1},
        }
        for name, extra in cases.items():
            with self.subTest(filter=name):
                body = {"returnFormat": "json", "eventid": self.event_id}
                body.update(extra)
                self._check(f"restsearch_filter_{name}", self._fetch("attributes", body))

    def test_unknown_return_format_is_rejected_cleanly(self) -> None:
        response = self.api.post("/events/restSearch",
                                 json_body={"returnFormat": "not-a-format", "eventid": self.event_id})
        self.assertLess(response.status_code, 500,
                        "an unknown returnFormat must be a client error, not a server error")


if __name__ == "__main__":
    unittest.main(verbosity=2)
