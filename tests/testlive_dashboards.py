#!/usr/bin/env python3
"""Live coverage for the dashboard controller.

DashboardsController is 875 statements at 0.00% in BOTH suites: nothing in CI
has ever requested a dashboard. The widgets themselves are unit-tested, but
the controller that lists, renders, persists and templates them is untouched.

Usage:
    HOST=127.0.0.1 AUTH=<site-admin-key> python3 testlive_dashboards.py -v

Falls back to tests/keys.py when the env vars are unset.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib.misp_live import MispApi, SettingsGuard, is_error  # noqa: E402


class TestDashboards(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.api = MispApi()
        # The dashboard persists per-user settings; put them back afterwards.
        cls.guard = SettingsGuard(cls.api, [])
        cls.guard.__enter__()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.guard.__exit__(None, None, None)

    # -- listing ----------------------------------------------------------

    def test_index_renders(self) -> None:
        response = self.api.get("/dashboards/index")
        self.assertIn(response.status_code, (200, 302), "dashboard index must respond")

    def test_widgets_lists_available_widgets(self) -> None:
        payload = self.api.json("GET", "/dashboards/widgets")
        self.assertFalse(is_error(payload), f"widget listing failed: {payload}")
        self.assertTrue(
            isinstance(payload, (list, dict)),
            "widget listing must return a structure",
        )

    def test_list_templates(self) -> None:
        payload = self.api.json("GET", "/dashboards/listTemplates")
        self.assertFalse(is_error(payload), f"listTemplates failed: {payload}")

    def test_list_sharing_groups(self) -> None:
        payload = self.api.json("GET", "/dashboards/listSharingGroups")
        self.assertFalse(is_error(payload), f"listSharingGroups failed: {payload}")

    def test_list_galaxy_types(self) -> None:
        payload = self.api.json("GET", "/dashboards/listGalaxyTypes")
        self.assertFalse(is_error(payload), f"listGalaxyTypes failed: {payload}")

    # -- search endpoints -------------------------------------------------

    def test_search_organisations(self) -> None:
        response = self.api.get("/dashboards/searchOrganisations")
        self.assertLess(response.status_code, 500, "searchOrganisations must not 500")

    def test_search_galaxy_clusters(self) -> None:
        response = self.api.get("/dashboards/searchGalaxyClusters")
        self.assertLess(response.status_code, 500, "searchGalaxyClusters must not 500")

    # -- rendering --------------------------------------------------------

    def test_render_each_widget(self) -> None:
        """Render every widget the instance offers.

        This is the part unit tests cannot reach: the controller resolves the
        widget, applies ACL, and renders it against real data.
        """
        payload = self.api.json("GET", "/dashboards/widgets")
        widgets = []
        if isinstance(payload, list):
            widgets = [w.get("alias") or w.get("widget") for w in payload if isinstance(w, dict)]
        elif isinstance(payload, dict):
            for value in payload.values():
                if isinstance(value, dict) and ("alias" in value or "widget" in value):
                    widgets.append(value.get("alias") or value.get("widget"))

        if not widgets:
            self.skipTest(f"instance advertised no widgets: {str(payload)[:200]}")

        # Widgets that need infrastructure a stock instance does not have.
        needs_infrastructure = {"BenchmarkTopListWidget": "needs benchmarking enabled"}

        rendered, failed, skipped = 0, [], []
        for widget in widgets:
            if not widget:
                continue
            response = self.api.post(
                "/dashboards/renderWidget",
                json_body={"widget": widget, "config": {}},
            )
            if response.status_code >= 500:
                if widget in needs_infrastructure:
                    skipped.append(widget)
                else:
                    failed.append((widget, response.status_code))
            else:
                rendered += 1

        self.assertEqual([], failed, f"widgets returned 5xx: {failed}")
        self.assertGreater(rendered, 0, "no widget rendered")
        if skipped:
            print(f"\n  (infrastructure-dependent widgets skipped: {sorted(skipped)})")

    # -- persistence ------------------------------------------------------

    def test_export_returns_a_dashboard_configuration(self) -> None:
        payload = self.api.json("GET", "/dashboards/export")
        self.assertFalse(is_error(payload), f"dashboard export failed: {payload}")

    def test_update_settings_round_trip(self) -> None:
        original = self.api.json("GET", "/dashboards/export")

        response = self.api.post(
            "/dashboards/updateSettings",
            json_body={"value": json.dumps([])},
        )
        self.assertLess(response.status_code, 500, "updateSettings must not 500")

        # Put the user's dashboard back exactly as it was.
        if isinstance(original, (list, dict)):
            self.api.post(
                "/dashboards/updateSettings",
                json_body={"value": json.dumps(original)},
            )

    def test_update_theme_does_not_error(self) -> None:
        response = self.api.post("/dashboards/updateTheme", json_body={"theme": "default"})
        self.assertLess(response.status_code, 500, "updateTheme must not 500")


if __name__ == "__main__":
    unittest.main(verbosity=2)
