#!/usr/bin/env python3
"""
Integration tests for the /event_templates REST surface (PRD §9).

Hits a running MISP instance over HTTP — configure via either the env
vars HOST + AUTH (matches the other testlive_*.py scripts) or a local
tests/keys.py file exposing `url` and `key`. Uses raw `requests` calls
rather than PyMISP because event templates aren't yet modelled in the
client library.

Every test creates templates it owns and cleans them up in tearDown;
the suite is safe to run against an instance that already has other
templates installed.

Commit 4 of the Phase 1.6 plan covers the REST CRUD + use endpoints:
index, add, view, edit, delete, duplicate, validate_definition,
instantiate. Commits 5 and 6 extend the same file with import/export
round-trip and object-template-dependency tracking coverage.
"""
from __future__ import annotations

import json
import os
import sys
import unittest
import uuid
from typing import Any, Dict, List, Optional

import requests
import urllib3  # type: ignore

# Config: env vars HOST+AUTH take precedence (matches other testlive_*
# scripts); fall back to a local tests/keys.py only when neither is set.
_host = os.environ.get("HOST")
_auth = os.environ.get("AUTH")
if _host and _auth:
    URL = "http://" + _host
    KEY = _auth
else:
    try:
        sys.path.insert(0, os.path.dirname(__file__))
        from keys import url as _KEYS_URL, key as _KEYS_KEY  # type: ignore
        URL = _KEYS_URL
        KEY = _KEYS_KEY
    except Exception:
        URL = "http://" + (_host or "localhost:5007")
        KEY = _auth or ""

urllib3.disable_warnings()


def _headers() -> Dict[str, str]:
    return {
        "Authorization": KEY,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def _minimal_definition(
    name: str = "Integration template",
    info_template: Optional[str] = None,
) -> Dict[str, Any]:
    """A structurally- and semantically-valid definition with no
    DB-backed element types (no attribute_field, no object_field),
    keeping the semantic validator off the MispAttribute and
    ObjectTemplate DB paths. The test templates focus on envelope
    CRUD + instantiation — deeper element coverage belongs to
    commits 5 and 6."""
    event_defaults: Dict[str, Any] = {"distribution": 0}
    if info_template is not None:
        event_defaults["info_template"] = info_template
    return {
        "schema_version": 1,
        "uuid": str(uuid.uuid4()),
        "name": name,
        "description": None,
        "event_defaults": event_defaults,
        "structure": [
            {"type": "tag_field", "id": "tags_campaign", "label": "Campaign tags"},
        ],
    }


class EventTemplatesRestTests(unittest.TestCase):
    """REST CRUD + use (instantiate) + validate_definition."""

    # Templates and events created during each test, cleaned up in tearDown.
    _templates: List[int]
    _events: List[int]

    def setUp(self) -> None:
        if not KEY:
            self.skipTest("AUTH env var / keys.py not configured.")
        self._templates = []
        self._events = []

    def tearDown(self) -> None:
        for tid in self._templates:
            try:
                requests.post(
                    f"{URL}/event_templates/delete/{tid}",
                    headers=_headers(),
                    timeout=10,
                )
            except requests.RequestException:
                pass
        for eid in self._events:
            try:
                requests.post(
                    f"{URL}/events/delete/{eid}",
                    headers=_headers(),
                    timeout=10,
                )
            except requests.RequestException:
                pass

    # ---- helpers ----------------------------------------------------

    def _add(self, name: Optional[str] = None, **extra: Any) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "name": name or f"tpl-{uuid.uuid4().hex[:8]}",
            "distribution": 0,
            "active": 1,
            "definition": _minimal_definition(),
        }
        payload.update(extra)
        r = requests.post(
            f"{URL}/event_templates/add",
            headers=_headers(),
            data=json.dumps(payload),
            timeout=10,
        )
        self.assertEqual(
            r.status_code, 200,
            f"/event_templates/add returned {r.status_code}: {r.text[:200]}",
        )
        body = r.json()
        self.assertIn("EventTemplate", body, f"unexpected /add response: {body}")
        tid = int(body["EventTemplate"]["id"])
        self._templates.append(tid)
        return body

    # ---- tests ------------------------------------------------------

    def test_index_returns_list(self) -> None:
        # Seed a template so the index has at least one known row.
        created = self._add()
        created_id = int(created["EventTemplate"]["id"])

        r = requests.get(
            f"{URL}/event_templates/index",
            headers=_headers(),
            timeout=10,
        )
        self.assertEqual(r.status_code, 200)
        rows = r.json()
        self.assertIsInstance(rows, list)
        ids = [int(row["EventTemplate"]["id"]) for row in rows]
        self.assertIn(created_id, ids)

    def test_add_view_delete_roundtrip(self) -> None:
        created = self._add(name="rt-template")
        tid = int(created["EventTemplate"]["id"])

        r = requests.get(
            f"{URL}/event_templates/view/{tid}",
            headers=_headers(),
            timeout=10,
        )
        self.assertEqual(r.status_code, 200)
        view = r.json()
        self.assertEqual(view["EventTemplate"]["name"], "rt-template")
        self.assertEqual(int(view["EventTemplate"]["version"]), 1)

        r = requests.post(
            f"{URL}/event_templates/delete/{tid}",
            headers=_headers(),
            timeout=10,
        )
        self.assertEqual(r.status_code, 200)
        self._templates.remove(tid)  # tearDown doesn't need to re-delete

        r = requests.get(
            f"{URL}/event_templates/view/{tid}",
            headers=_headers(),
            timeout=10,
        )
        self.assertEqual(r.status_code, 404)

    def test_add_rejects_invalid_definition(self) -> None:
        # Malformed definition: missing schema_version.
        bad_def = _minimal_definition()
        del bad_def["schema_version"]
        payload = {"name": "bad", "distribution": 0, "definition": bad_def}
        r = requests.post(
            f"{URL}/event_templates/add",
            headers=_headers(),
            data=json.dumps(payload),
            timeout=10,
        )
        # MISP's saveFailResponse hard-codes 403 for validation failures.
        self.assertIn(r.status_code, (400, 403, 405))
        body = r.json()
        # The server returns MISP's standard saveFailResponse envelope,
        # with the model's validation errors nested under "errors".
        self.assertFalse(body.get("saved", True), body)
        flat = json.dumps(body)
        self.assertIn("schema_version", flat)

    def test_edit_bumps_version(self) -> None:
        created = self._add(name="to-edit")
        tid = int(created["EventTemplate"]["id"])

        new_def = _minimal_definition(name="edited")
        r = requests.post(
            f"{URL}/event_templates/edit/{tid}",
            headers=_headers(),
            data=json.dumps({"definition": new_def}),
            timeout=10,
        )
        self.assertEqual(r.status_code, 200, r.text[:200])
        body = r.json()
        self.assertEqual(
            int(body["EventTemplate"]["version"]), 2,
            "edit should bump version from 1 to 2",
        )
        self.assertEqual(body["EventTemplate"]["definition"]["name"], "edited")

    def test_duplicate_produces_distinct_row_with_new_uuid(self) -> None:
        created = self._add(name="to-duplicate")
        tid = int(created["EventTemplate"]["id"])
        src_uuid = created["EventTemplate"]["uuid"]

        r = requests.post(
            f"{URL}/event_templates/duplicate/{tid}",
            headers=_headers(),
            timeout=10,
        )
        self.assertEqual(r.status_code, 200, r.text[:200])
        body = r.json()
        new_tid = int(body["EventTemplate"]["id"])
        self._templates.append(new_tid)
        self.assertNotEqual(new_tid, tid)
        self.assertNotEqual(body["EventTemplate"]["uuid"], src_uuid)
        # Default name on duplicate is "<original> (copy)".
        self.assertIn("(copy)", body["EventTemplate"]["name"])
        # Row uuid and JSON-internal uuid stay aligned per the
        # duplicate() implementation in EventTemplatesController.
        self.assertEqual(
            body["EventTemplate"]["uuid"],
            body["EventTemplate"]["definition"]["uuid"],
        )

    def test_validate_definition_happy_and_sad(self) -> None:
        r = requests.post(
            f"{URL}/event_templates/validate_definition",
            headers=_headers(),
            data=json.dumps(_minimal_definition()),
            timeout=10,
        )
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertTrue(body.get("valid"), body)
        self.assertEqual(body.get("errors"), [])

        bad = _minimal_definition()
        del bad["schema_version"]
        r = requests.post(
            f"{URL}/event_templates/validate_definition",
            headers=_headers(),
            data=json.dumps(bad),
            timeout=10,
        )
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertFalse(body.get("valid"), body)
        self.assertTrue(
            any("schema_version" in e for e in body.get("errors", [])),
            body,
        )

    def test_instantiate_creates_event(self) -> None:
        created = self._add(name="inst-template")
        tid = int(created["EventTemplate"]["id"])

        r = requests.post(
            f"{URL}/event_templates/instantiate/{tid}",
            headers=_headers(),
            data=json.dumps({"values": {}}),
            timeout=15,
        )
        self.assertEqual(r.status_code, 200, r.text[:200])
        body = r.json()
        self.assertIn("event_id", body, body)
        self.assertIn("event_uuid", body, body)
        eid = int(body["event_id"])
        self._events.append(eid)

        # Verify the event actually exists.
        r = requests.get(
            f"{URL}/events/view/{eid}",
            headers=_headers(),
            timeout=10,
        )
        self.assertEqual(r.status_code, 200)
        evt = r.json()
        self.assertEqual(int(evt["Event"]["id"]), eid)

    def test_instantiate_rejects_file_field_input(self) -> None:
        # PRD §5.2 F2.11: templates may declare file_field elements, but
        # user input for them is rejected in v1. The instantiator must
        # surface that as a structured saveFailResponse.
        def_with_file = _minimal_definition(name="file-template")
        def_with_file["structure"] = [
            {"type": "file_field", "id": "samples", "label": "Samples"},
        ]
        created = self._add(name="file-tpl", definition=def_with_file)
        tid = int(created["EventTemplate"]["id"])

        r = requests.post(
            f"{URL}/event_templates/instantiate/{tid}",
            headers=_headers(),
            data=json.dumps({"values": {"samples": ["anything"]}}),
            timeout=10,
        )
        # MISP's saveFailResponse hard-codes 403 for validation failures;
        # accept the neighbouring 4xx codes too for robustness.
        self.assertIn(r.status_code, (400, 403, 405, 422))
        flat = r.text
        self.assertIn("file_field", flat)
        self.assertIn("not yet supported", flat)


class EventTemplatesObjectDependencyTrackingTests(unittest.TestCase):
    """Verifies the `event_template_object_dependencies` sidecar stays in
    sync with the parent template's object_field references across save,
    edit, and delete (PRD §6.2).

    Save and edit coverage reads the sidecar back through the /view REST
    response — our controller contains EventTemplateObjectDependency
    there. The delete-cascade assertion requires a direct DB read
    (no REST endpoint exposes rows for a template that no longer
    exists); that test is skipped when DB credentials are not provided
    via env vars.
    """

    # Two real, installed object templates on a default MISP instance.
    # We use stable uuids and pinned_versions so the semantic validator
    # is happy on every supported MISP. If these uuids are ever removed
    # from misp-object upstream this will need updating.
    EMAIL_OT = {
        "uuid": "a0c666e0-fc65-4be8-b48f-3423d788b552",
        "name": "email",
        "pinned_version": 1,
    }
    FILE_OT = {
        "uuid": "688c46fb-5edb-40a3-8273-1af7923e2215",
        "name": "file",
        "pinned_version": 1,
    }

    _templates: List[int]

    def setUp(self) -> None:
        if not KEY:
            self.skipTest("AUTH env var / keys.py not configured.")
        self._templates = []

    def tearDown(self) -> None:
        for tid in self._templates:
            try:
                requests.post(
                    f"{URL}/event_templates/delete/{tid}",
                    headers=_headers(),
                    timeout=10,
                )
            except requests.RequestException:
                pass

    # ---- helpers ---------------------------------------------------

    def _definition_with_object_fields(
        self, object_templates: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        structure: List[Dict[str, Any]] = []
        for idx, ot in enumerate(object_templates):
            structure.append({
                "type": "object_field",
                "id": f"obj_{idx}",
                "label": f"Object {idx}",
                "object_template": ot,
                "relations": [],
            })
        return {
            "schema_version": 1,
            "uuid": str(uuid.uuid4()),
            "name": "dep-tracking",
            "event_defaults": {"distribution": 0},
            "structure": structure,
        }

    def _add(self, definition: Dict[str, Any]) -> int:
        r = requests.post(
            f"{URL}/event_templates/add",
            headers=_headers(),
            data=json.dumps({
                "name": "dep-" + uuid.uuid4().hex[:8],
                "distribution": 0,
                "active": 1,
                "definition": definition,
            }),
            timeout=10,
        )
        self.assertEqual(r.status_code, 200, r.text[:200])
        tid = int(r.json()["EventTemplate"]["id"])
        self._templates.append(tid)
        return tid

    def _dep_uuids(self, tid: int) -> List[str]:
        r = requests.get(
            f"{URL}/event_templates/view/{tid}",
            headers=_headers(),
            timeout=10,
        )
        self.assertEqual(r.status_code, 200, r.text[:200])
        deps = r.json().get("EventTemplateObjectDependency", []) or []
        return sorted(d["object_template_uuid"] for d in deps)

    def _dep_count_in_db(self, tid: int) -> int:
        import subprocess
        pw = os.environ.get("DB_PASS")
        if not pw:
            self.skipTest("DB_PASS env var not set; cannot verify cascade.")
        user = os.environ.get("DB_USER", "misp")
        db = os.environ.get("DB_NAME", "misp")
        host = os.environ.get("DB_HOST", "localhost")
        proc = subprocess.run(
            [
                "mysql", f"-h{host}", f"-u{user}", f"-p{pw}", db,
                "-N", "-B", "-e",
                "SELECT COUNT(*) FROM event_template_object_dependencies "
                f"WHERE event_template_id = {int(tid)}",
            ],
            capture_output=True, text=True, timeout=10,
        )
        if proc.returncode != 0:
            self.skipTest(f"mysql CLI unavailable or auth failed: {proc.stderr[:200]}")
        return int(proc.stdout.strip())

    # ---- tests -----------------------------------------------------

    def test_dependencies_written_on_save(self) -> None:
        definition = self._definition_with_object_fields([
            self.EMAIL_OT, self.FILE_OT,
        ])
        tid = self._add(definition)
        deps = self._dep_uuids(tid)
        self.assertEqual(
            deps,
            sorted([self.EMAIL_OT["uuid"], self.FILE_OT["uuid"]]),
            "save must write one dep row per distinct object_template uuid",
        )

    def test_dependencies_deduplicated_across_multiple_fields(self) -> None:
        # Two object_fields referencing the same object template — the
        # sidecar keeps one row (extractObjectDependencies dedupes by
        # uuid and keeps the highest pinned_version).
        definition = self._definition_with_object_fields([
            self.EMAIL_OT, self.EMAIL_OT,
        ])
        tid = self._add(definition)
        self.assertEqual(self._dep_uuids(tid), [self.EMAIL_OT["uuid"]])

    def test_dependencies_updated_on_edit_remove(self) -> None:
        definition = self._definition_with_object_fields([
            self.EMAIL_OT, self.FILE_OT,
        ])
        tid = self._add(definition)
        self.assertEqual(len(self._dep_uuids(tid)), 2)

        # Edit down to one object_field.
        new_def = self._definition_with_object_fields([self.FILE_OT])
        new_def["uuid"] = definition["uuid"]  # keep internal JSON uuid stable
        r = requests.post(
            f"{URL}/event_templates/edit/{tid}",
            headers=_headers(),
            data=json.dumps({"definition": new_def}),
            timeout=10,
        )
        self.assertEqual(r.status_code, 200, r.text[:200])
        self.assertEqual(self._dep_uuids(tid), [self.FILE_OT["uuid"]])

    def test_dependencies_updated_on_edit_add(self) -> None:
        definition = self._definition_with_object_fields([self.EMAIL_OT])
        tid = self._add(definition)
        self.assertEqual(self._dep_uuids(tid), [self.EMAIL_OT["uuid"]])

        new_def = self._definition_with_object_fields([
            self.EMAIL_OT, self.FILE_OT,
        ])
        new_def["uuid"] = definition["uuid"]
        r = requests.post(
            f"{URL}/event_templates/edit/{tid}",
            headers=_headers(),
            data=json.dumps({"definition": new_def}),
            timeout=10,
        )
        self.assertEqual(r.status_code, 200, r.text[:200])
        self.assertEqual(
            self._dep_uuids(tid),
            sorted([self.EMAIL_OT["uuid"], self.FILE_OT["uuid"]]),
        )

    def test_dependencies_cascade_deleted_with_template(self) -> None:
        definition = self._definition_with_object_fields([
            self.EMAIL_OT, self.FILE_OT,
        ])
        tid = self._add(definition)
        self.assertEqual(self._dep_count_in_db(tid), 2)

        r = requests.post(
            f"{URL}/event_templates/delete/{tid}",
            headers=_headers(),
            timeout=10,
        )
        self.assertEqual(r.status_code, 200)
        self._templates.remove(tid)  # tearDown needn't re-delete

        self.assertEqual(
            self._dep_count_in_db(tid), 0,
            "dependent=>true should cascade-delete the sidecar rows",
        )


class EventTemplatesImportExportTests(unittest.TestCase):
    """Export → Import round-trip, all three collision modes."""

    _templates: List[int]

    def setUp(self) -> None:
        if not KEY:
            self.skipTest("AUTH env var / keys.py not configured.")
        self._templates = []

    def tearDown(self) -> None:
        for tid in self._templates:
            try:
                requests.post(
                    f"{URL}/event_templates/delete/{tid}",
                    headers=_headers(),
                    timeout=10,
                )
            except requests.RequestException:
                pass

    # ---- helpers ---------------------------------------------------

    def _add(self, name: str) -> Dict[str, Any]:
        r = requests.post(
            f"{URL}/event_templates/add",
            headers=_headers(),
            data=json.dumps({
                "name": name,
                "distribution": 0,
                "active": 1,
                "definition": _minimal_definition(name=name),
            }),
            timeout=10,
        )
        self.assertEqual(r.status_code, 200, r.text[:200])
        body = r.json()
        self._templates.append(int(body["EventTemplate"]["id"]))
        return body

    def _export(self, tid: int) -> Dict[str, Any]:
        r = requests.get(
            f"{URL}/event_templates/export/{tid}",
            headers=_headers(),
            timeout=10,
        )
        self.assertEqual(r.status_code, 200, r.text[:200])
        return r.json()

    def _import(
        self,
        payload: Dict[str, Any],
        mode: str = "fail",
    ) -> requests.Response:
        return requests.post(
            f"{URL}/event_templates/import?mode={mode}",
            headers=_headers(),
            data=json.dumps(payload),
            timeout=10,
        )

    # ---- tests -----------------------------------------------------

    def test_export_returns_self_contained_document(self) -> None:
        created = self._add("for-export")
        tid = int(created["EventTemplate"]["id"])
        doc = self._export(tid)

        self.assertIn("_meta", doc, doc)
        self.assertEqual(doc["_meta"]["event_template_schema_version"], 1)
        self.assertIn("misp_version", doc["_meta"])
        self.assertIn("template", doc, doc)
        tpl = doc["template"]
        self.assertEqual(tpl["uuid"], created["EventTemplate"]["uuid"])
        self.assertEqual(tpl["name"], "for-export")
        self.assertIsInstance(tpl["definition"], dict)
        # Ownership columns must not leak into the export payload — the
        # importer gives ownership to the importing user.
        self.assertNotIn("org_id", tpl)
        self.assertNotIn("creator_user_id", tpl)

    def test_import_fail_mode_creates_new_row(self) -> None:
        tpl_uuid = str(uuid.uuid4())
        doc = self._build_doc(tpl_uuid, name="fresh-import")

        r = self._import(doc, mode="fail")
        self.assertEqual(r.status_code, 200, r.text[:200])
        body = r.json()
        self.assertEqual(body["event_template_uuid"], tpl_uuid)
        self._templates.append(int(body["event_template_id"]))

    def test_import_fail_mode_rejects_uuid_collision(self) -> None:
        tpl_uuid = str(uuid.uuid4())
        doc = self._build_doc(tpl_uuid, name="first")

        # First import succeeds.
        r = self._import(doc, mode="fail")
        self.assertEqual(r.status_code, 200, r.text[:200])
        self._templates.append(int(r.json()["event_template_id"]))

        # Second import with the same uuid must fail.
        r = self._import(doc, mode="fail")
        self.assertIn(r.status_code, (400, 403, 405, 422))
        body = r.json()
        self.assertFalse(body.get("saved", True), body)
        flat = json.dumps(body)
        self.assertIn("already exists", flat)

    def test_import_overwrite_mode_updates_in_place(self) -> None:
        created = self._add("to-overwrite")
        original_uuid = created["EventTemplate"]["uuid"]
        original_id = int(created["EventTemplate"]["id"])

        doc = self._export(original_id)
        # Mutate the exported template before re-importing so we can
        # prove overwrite updated the row.
        doc["template"]["description"] = "overwritten description"

        r = self._import(doc, mode="overwrite")
        self.assertEqual(r.status_code, 200, r.text[:200])
        body = r.json()
        self.assertEqual(body["event_template_uuid"], original_uuid)
        self.assertEqual(body["event_template_id"], original_id)
        self.assertEqual(body["mode"], "overwrite")

        # Confirm the description landed.
        r = requests.get(
            f"{URL}/event_templates/view/{original_id}",
            headers=_headers(),
            timeout=10,
        )
        self.assertEqual(r.status_code, 200)
        view = r.json()
        self.assertEqual(
            view["EventTemplate"]["description"],
            "overwritten description",
        )

    def test_import_duplicate_as_new_generates_fresh_uuid(self) -> None:
        created = self._add("to-duplicate-via-import")
        original_uuid = created["EventTemplate"]["uuid"]
        original_id = int(created["EventTemplate"]["id"])

        doc = self._export(original_id)
        r = self._import(doc, mode="duplicate_as_new")
        self.assertEqual(r.status_code, 200, r.text[:200])
        body = r.json()
        self.assertEqual(body["mode"], "duplicate_as_new")
        self.assertNotEqual(
            body["event_template_uuid"], original_uuid,
            "duplicate_as_new must produce a fresh uuid",
        )
        self.assertNotEqual(int(body["event_template_id"]), original_id)
        self._templates.append(int(body["event_template_id"]))

    def test_roundtrip_export_delete_import_matches_definition(self) -> None:
        # Headline round-trip: export → wipe → import → compare (PRD §13).
        created = self._add("roundtrip")
        tid = int(created["EventTemplate"]["id"])
        src_definition = created["EventTemplate"]["definition"]

        doc = self._export(tid)

        r = requests.post(
            f"{URL}/event_templates/delete/{tid}",
            headers=_headers(),
            timeout=10,
        )
        self.assertEqual(r.status_code, 200)
        self._templates.remove(tid)

        r = self._import(doc, mode="fail")
        self.assertEqual(r.status_code, 200, r.text[:200])
        body = r.json()
        new_id = int(body["event_template_id"])
        self._templates.append(new_id)

        r = requests.get(
            f"{URL}/event_templates/view/{new_id}",
            headers=_headers(),
            timeout=10,
        )
        self.assertEqual(r.status_code, 200)
        view = r.json()
        self.assertEqual(view["EventTemplate"]["definition"], src_definition)

    # ---- helpers -----------------------------------------------

    @staticmethod
    def _build_doc(tpl_uuid: str, name: str) -> Dict[str, Any]:
        definition = _minimal_definition(name=name)
        definition["uuid"] = tpl_uuid
        return {
            "_meta": {
                "misp_version": "2.5.36",
                "exported_at": "2026-04-23T14:00:00+00:00",
                "event_template_schema_version": 1,
            },
            "template": {
                "uuid": tpl_uuid,
                "name": name,
                "description": None,
                "version": 1,
                "distribution": 0,
                "active": True,
                "definition": definition,
            },
        }


if __name__ == "__main__":
    unittest.main(verbosity=2)
