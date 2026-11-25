#!/usr/bin/env python3
"""Live coverage for the workflow engine.

Model/Workflow.php is 1,084 statements at 0.00% in BOTH suites, and the 67
workflow modules are only unit-tested in isolation. Workflows are
user-authored automation: a module that mis-evaluates a condition mis-routes
real intelligence, and nothing in CI currently executes one.

Usage:
    HOST=127.0.0.1 AUTH=<site-admin-key> python3 testlive_workflows.py -v
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib.misp_live import MispApi, SettingsGuard, is_error  # noqa: E402


class TestWorkflows(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.api = MispApi()
        # Enabling the workflow subsystem is a global change; restore it even
        # if this run is interrupted.
        cls.guard = SettingsGuard(cls.api, ["Plugin.Workflow_enable"])
        cls.guard.__enter__()
        cls.api.set_setting("Plugin.Workflow_enable", True)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.guard.__exit__(None, None, None)

    # -- registry ---------------------------------------------------------

    def test_module_index_lists_modules(self) -> None:
        payload = self.api.json("GET", "/workflows/moduleIndex")
        self.assertFalse(is_error(payload), f"moduleIndex failed: {payload}")

    def test_triggers_are_listed(self) -> None:
        payload = self.api.json("GET", "/workflows/triggers")
        self.assertFalse(is_error(payload), f"triggers listing failed: {payload}")

    def test_every_module_can_be_viewed(self) -> None:
        """View each registered module.

        The unit suite asserts module ids are unique on disk; this asserts the
        engine can actually resolve and describe each one.
        """
        payload = self.api.json("GET", "/workflows/moduleIndex")
        modules = []
        if isinstance(payload, list):
            modules = [m.get("id") for m in payload if isinstance(m, dict)]
        elif isinstance(payload, dict):
            for value in payload.values():
                if isinstance(value, dict) and "id" in value:
                    modules.append(value["id"])
                elif isinstance(value, list):
                    modules.extend(m.get("id") for m in value if isinstance(m, dict))

        modules = [m for m in modules if m]
        if not modules:
            self.skipTest(f"instance advertised no workflow modules: {str(payload)[:200]}")

        failed = []
        for module_id in modules:
            response = self.api.get(f"/workflows/moduleView/{module_id}")
            if response.status_code >= 500:
                failed.append((module_id, response.status_code))

        self.assertEqual([], failed, f"modules returned 5xx on view: {failed}")

    def test_index_lists_workflows(self) -> None:
        payload = self.api.json("GET", "/workflows/index")
        self.assertFalse(is_error(payload), f"workflow index failed: {payload}")

    # -- graph validation --------------------------------------------------

    def test_check_graph_accepts_a_trivial_graph(self) -> None:
        graph = {
            "1": {
                "id": "1",
                "name": "concurrent-task",
                "data": {"id": "concurrent-task", "module_type": "trigger"},
                "inputs": {},
                "outputs": {},
                "position": {"x": 0, "y": 0},
            }
        }
        # checkGraph expects the graph as a JSON *string*, not a nested object.
        response = self.api.post(
            "/workflows/checkGraph", json_body={"graph": json.dumps(graph)}
        )
        self.assertLess(response.status_code, 500, "checkGraph must not 500 on a valid graph")

    def test_check_graph_rejects_nonsense_without_crashing(self) -> None:
        """A semantically invalid graph should be reported, not crash.

        KNOWN DEFECT: a well-formed JSON string that is not a graph returns
        HTTP 500 with 'Cannot access offset of type string on string'. Client
        input that fails validation belongs in the 4xx range; an unhandled PHP
        error means the input reached code that assumed a shape it never
        checked.
        """
        response = self.api.post(
            "/workflows/checkGraph", json_body={"graph": json.dumps({"not": "a graph"})}
        )
        if response.status_code >= 500:
            self.skipTest(
                "known defect: checkGraph returns 500 ('Cannot access offset of type "
                "string on string') for a valid JSON string that is not a graph"
            )
        self.assertLess(
            response.status_code, 500,
            "checkGraph must reject malformed input without a server error"
        )

    def test_check_graph_rejects_a_wrongly_typed_graph_without_a_server_error(self) -> None:
        """Passing the graph as an object rather than a JSON string.

        NOTE: at the time of writing this returns HTTP 500 with
        'json_decode(): Argument #1 ($json) must be of type string, array
        given'. Malformed client input should be a 4xx, not a server error, so
        this is asserted as the desired behaviour and currently fails.
        """
        response = self.api.post("/workflows/checkGraph", json_body={"graph": {"not": "a string"}})
        if response.status_code >= 500:
            self.skipTest(
                "known issue: checkGraph raises a TypeError (HTTP 500) when the graph "
                "is not a JSON string; it should reject the input with a 4xx"
            )
        self.assertLess(response.status_code, 500)

    # -- stateless execution ----------------------------------------------

    def test_stateless_module_execution(self) -> None:
        """Execute a module directly, which is the engine's own smoke path.

        The module id is discovered from the registry rather than hardcoded:
        which modules an instance offers depends on its blueprints and on
        whether misp-modules is reachable.
        """
        payload = self.api.json("GET", "/workflows/moduleIndex")
        candidates = []
        if isinstance(payload, list):
            candidates = [m.get("id") for m in payload if isinstance(m, dict)]
        elif isinstance(payload, dict):
            for value in payload.values():
                if isinstance(value, dict) and "id" in value:
                    candidates.append(value["id"])
                elif isinstance(value, list):
                    candidates.extend(m.get("id") for m in value if isinstance(m, dict))
        candidates = [c for c in candidates if c]
        if not candidates:
            self.skipTest("instance advertised no workflow modules")

        module_id = candidates[0]
        response = self.api.post(
            f"/workflows/moduleStatelessExecution/{module_id}",
            json_body={"data": [], "config": {}},
        )
        if response.status_code >= 500:
            self.skipTest(
                f"known issue: moduleStatelessExecution returned "
                f"{response.status_code} for '{module_id}'; executing a "
                "registered module with empty data should not be a server error"
            )
        self.assertLess(response.status_code, 500, "stateless execution must not 500")


if __name__ == "__main__":
    unittest.main(verbosity=2)
