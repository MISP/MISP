#!/usr/bin/env python3
"""
AI UX end-to-end test against the fake `ai_connector` module server.

Exercises every MISP-side path of the AI integration over real HTTP without
an LLM: the fake server in tests/ai_fake_module_server.py answers the
contract the real module implements (deterministic summaries, a fixed tag
list). Covered:

  * settings: the Plugin.AI_* settings exist and the dry run leaves the event
    untouched
  * A2 summarise event: a new report is added, the event unpublished
  * A1 summarise report: the AI summary block is put on top, a re-run
    replaces it, the module always receives the original text
  * A3 recommend tags: suggestions classified (existing / present / new /
    galaxy cluster), accept attaches and creates, re-accept skips, unknown
    galaxy names refused, taxonomy exclusivity enforced; a user without the
    tag editor permission cannot create tags; a host-org user without edit
    rights gets local tags
  * ACL: no perm_ai_tools -> 403, AI services off -> 405, unknown event -> 404
  * the reworked workflow action node summarises a report

The test starts the fake server itself on AI_FAKE_PORT (default 6670) and
points the instance at it (Plugin.AI_services_url/port), so MISP must be
able to reach the machine running this script on that port; every setting
it changes is restored afterwards. A1/A2 run synchronously by switching
MISP.background_jobs off for the duration.

Environment:
    HOST, AUTH      instance (host:port) + a site-admin API key
    AI_FAKE_PORT    port for the fake module server (default 6670)

Run:
    HOST=127.0.0.1:5007 AUTH=<key> python3 tests/testlive_ai_ux.py -v
"""

import json
import os
import subprocess
import sys
import time
import unittest
import urllib.request
import uuid
import warnings

import requests

from pymisp import PyMISP, MISPEvent, MISPOrganisation, MISPUser

url = "http://" + os.environ["HOST"]
key = os.environ["AUTH"]
FAKE_PORT = int(os.environ.get("AI_FAKE_PORT", "6670"))
FAKE_URL = f"http://127.0.0.1:{FAKE_PORT}"

AI_HEADING = "# AI summary"
AI_DELINEATOR = "=================="


def check_response(response):
    if isinstance(response, dict) and "errors" in response:
        raise Exception(response["errors"])
    return response


def random():
    return str(uuid.uuid4()).split("-")[0]


def rest(authkey, method, path, data=None):
    """One REST call with a raw key; the caller reads the status code."""
    headers = {"Authorization": authkey, "Accept": "application/json", "Content-Type": "application/json"}
    return requests.request(method, f"{url}/{path}", headers=headers, json=data, timeout=120)


def rest_json(authkey, method, path, data=None, expect=200):
    r = rest(authkey, method, path, data)
    body = r.json()
    if r.status_code != expect:
        raise AssertionError(f"{method} {path}: HTTP {r.status_code}, expected {expect}: {body}")
    return body


def fake_last():
    with urllib.request.urlopen(f"{FAKE_URL}/last", timeout=10) as f:
        return json.load(f)


def count_blocks(content):
    """How many AI summary headings / delineator lines the content holds."""
    lines = content.splitlines()
    headings = sum(1 for line in lines if line.strip().lower() == AI_HEADING.lower())
    delineators = sum(1 for line in lines if line.strip() == AI_DELINEATOR)
    return headings, delineators


class TestAiUx(unittest.TestCase):
    fake = None
    settings_backup = {}
    created_tag_ids = set()
    created_key_ids = []

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)
        cls.admin = PyMISP(url, key)
        cls.admin.global_pythonify = True
        assert cls.admin._current_role.perm_site_admin, "AUTH must be a site admin key"
        if "perm_ai_tools" not in cls.admin._current_role.to_dict():
            raise unittest.SkipTest("perm_ai_tools missing: migration 160 not applied")
        cls.host_org_id = int(cls.admin._current_user.org_id)

        cls.__start_fake()
        cls.__configure_instance()

        # Fixtures: another org owning the event, three roles, three users.
        org = MISPOrganisation()
        org.name = "AI UX org " + random()
        cls.org = check_response(cls.admin.add_organisation(org))

        cls.role_tagger = cls.__add_role("AI UX tagger " + random(), permission=2, perm_tagger=True, perm_tag_editor=False, perm_ai_tools=True)
        cls.role_editor = cls.__add_role("AI UX tag editor " + random(), permission=2, perm_tagger=True, perm_tag_editor=True, perm_ai_tools=True)
        cls.role_reader = cls.__add_role("AI UX reader " + random(), permission=0, perm_tagger=False, perm_tag_editor=False, perm_ai_tools=False)

        # org user: may modify the org's event, may tag, cannot create tags
        cls.org_user, cls.org_key = cls.__add_user(cls.org.id, cls.role_tagger)
        # host-org user: may tag and create tags, but cannot modify the other org's event
        cls.host_user, cls.host_key = cls.__add_user(cls.host_org_id, cls.role_editor)
        # reader: no perm_ai_tools
        cls.reader, cls.reader_key = cls.__add_user(cls.org.id, cls.role_reader)

        # The event: owned by the org user, visible to the community so the
        # host-org user can see it.
        org_connector = PyMISP(url, cls.org_key)
        org_connector.global_pythonify = True
        event = MISPEvent()
        event.info = "AI UX live test " + random()
        event.distribution = 1
        event.threat_level_id = 4
        event.analysis = 0
        event.add_attribute("domain", "ai-ux-" + random() + ".example")
        event.add_attribute("ip-dst", "198.51.100.42")
        cls.event = check_response(org_connector.add_event(event))
        cls.event_id = int(cls.event.id)

    @classmethod
    def tearDownClass(cls):
        try:
            if getattr(cls, "event_id", None):
                cls.admin.delete_event(cls.event_id)
            for tag_id in sorted(cls.created_tag_ids):
                rest(key, "POST", f"tags/delete/{tag_id}")
            # deleting a user leaves its auth keys behind
            for key_id in cls.created_key_ids:
                rest(key, "POST", f"auth_keys/delete/{key_id}")
            for user in ("org_user", "host_user", "reader"):
                if getattr(cls, user, None) is not None:
                    cls.admin.delete_user(getattr(cls, user))
            for role in ("role_tagger", "role_editor", "role_reader"):
                if getattr(cls, role, None) is not None:
                    rest(key, "POST", f"admin/roles/delete/{getattr(cls, role)}")
            if getattr(cls, "org", None) is not None:
                cls.admin.delete_organisation(cls.org)
        finally:
            cls.__restore_instance()
            cls.__stop_fake()

    # ---- fixtures ---------------------------------------------------------

    @classmethod
    def __start_fake(cls):
        script = os.path.join(os.path.dirname(os.path.realpath(__file__)), "ai_fake_module_server.py")
        cls.fake = subprocess.Popen([sys.executable, script, "--port", str(FAKE_PORT)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            try:
                with urllib.request.urlopen(f"{FAKE_URL}/health", timeout=2) as f:
                    if json.load(f).get("ok"):
                        return
            except Exception:
                time.sleep(0.2)
        cls.__stop_fake()
        raise Exception(f"the fake module server did not come up on {FAKE_URL}")

    @classmethod
    def __stop_fake(cls):
        if cls.fake is not None:
            cls.fake.terminate()
            try:
                cls.fake.wait(timeout=10)
            except subprocess.TimeoutExpired:
                cls.fake.kill()
            cls.fake = None

    @classmethod
    def __setting(cls, name, value):
        check_response(cls.admin.set_server_setting(name, value, force=True))

    @classmethod
    def __configure_instance(cls):
        wanted = {
            "Plugin.AI_services_enable": True,
            "Plugin.AI_services_url": "http://127.0.0.1",
            "Plugin.AI_services_port": FAKE_PORT,
            "MISP.background_jobs": False,
        }
        for name, value in wanted.items():
            cls.settings_backup[name] = cls.admin.get_server_setting(name).get("value")
            cls.__setting(name, value)

    @classmethod
    def __restore_instance(cls):
        # A setting that was unset before is put back to the definition's
        # default; the family switch is off by default.
        defaults = {
            "Plugin.AI_services_enable": False,
            "Plugin.AI_services_url": "http://127.0.0.1",
            "Plugin.AI_services_port": 6666,
            "MISP.background_jobs": True,
        }
        for name, original in cls.settings_backup.items():
            try:
                cls.__setting(name, original if original is not None else defaults[name])
            except Exception as exc:  # best effort
                print(f"  (cleanup) could not restore {name}: {exc}")

    @classmethod
    def __add_role(cls, name, permission, **flags):
        data = {"name": name, "permission": permission, "perm_auth": True}
        data.update(flags)
        role = rest_json(key, "POST", "admin/roles/add", data)["Role"]
        for flag, value in flags.items():
            assert bool(role[flag]) == value, f"role {name}: {flag} not applied"
        return int(role["id"])

    @classmethod
    def __add_user(cls, org_id, role_id):
        user = MISPUser()
        user.email = "aiux." + random() + "@user.local"
        user.org_id = org_id
        user.role_id = role_id
        user = check_response(cls.admin.add_user(user))
        auth_key = rest_json(key, "POST", f"auth_keys/add/{user.id}", {"comment": "testlive_ai_ux"})["AuthKey"]
        cls.created_key_ids.append(int(auth_key["id"]))
        return user, auth_key["authkey_raw"]

    def __add_report(self, content, name=None):
        body = rest_json(key, "POST", f"eventReports/add/{self.event_id}", {
            "name": name or ("AI UX report " + random()),
            "content": content,
            "distribution": 5,
        })
        return int(body["EventReport"]["id"])

    def __report_content(self, report_id):
        return rest_json(key, "GET", f"eventReports/view/{report_id}")["EventReport"]["content"]

    def __event(self):
        return rest_json(key, "GET", f"events/view/{self.event_id}")["Event"]

    def __remember_tags(self, rows):
        for row in rows:
            if row.get("tag_id"):
                self.created_tag_ids.add(int(row["tag_id"]))

    # ---- settings + dry run -------------------------------------------------

    def test_01_settings_present(self):
        for name in ("Plugin.AI_services_enable", "Plugin.AI_services_url", "Plugin.AI_services_port",
                     "Plugin.AI_timeout", "Plugin.AI_model_id", "Plugin.AI_suggest_limit", "Plugin.AI_suggest_min_score"):
            setting = self.admin.get_server_setting(name)
            self.assertNotIn("errors", setting, name)
        self.assertTrue(self.admin.get_server_setting("Plugin.AI_services_enable")["value"])

    def test_02_dry_run_leaves_the_event_untouched(self):
        before = self.__event()
        body = rest_json(key, "POST", "servers/aiDryRun", {"event_id": self.event_id, "use_case": "summarization_on_event"})
        self.assertTrue(body["success"], body)
        self.assertEqual("summarization_on_event", body["use_case"])
        self.assertTrue(body["result"]["EventReport"]["content"])
        last = fake_last()["last"]
        self.assertEqual("summarization_on_event", last["use_case"])
        self.assertEqual(self.event_id, int(last["data"]["Event"]["id"]))
        self.assertIn("suggest_limit", last["params"])

        body = rest_json(key, "POST", "servers/aiDryRun", {"event_id": self.event_id, "use_case": "tag_suggest"})
        self.assertTrue(body["success"], body)
        self.assertTrue(body["result"]["Tag"])
        for row in body["result"]["Tag"]:
            self.assertIn("exists", row)
            self.assertTrue(row["name"])

        after = self.__event()
        self.assertEqual(before["timestamp"], after["timestamp"])
        self.assertEqual(len(before.get("EventReport", [])), len(after.get("EventReport", [])))
        self.assertEqual(len(before.get("Tag", [])), len(after.get("Tag", [])))

    # ---- A2 -----------------------------------------------------------------

    def test_03_summarise_event_adds_a_report(self):
        before = self.__event()
        body = rest_json(key, "POST", f"events/aiSummarize/{self.event_id}")
        self.assertTrue(body["saved"], body)
        self.assertIn("report_id", body, "background jobs are off, the report must be added at once")
        content = self.__report_content(body["report_id"])
        self.assertTrue(content)
        after = self.__event()
        self.assertEqual(len(before.get("EventReport", [])) + 1, len(after.get("EventReport", [])))
        self.assertFalse(after["published"])
        self.assertEqual("summarization_on_event", fake_last()["last"]["use_case"])

    # ---- A1 -----------------------------------------------------------------

    def test_04_summarise_report_puts_the_block_on_top_and_replaces_it(self):
        original = "# Incident notes\n\nThe actor used **mimikatz** on host A.\n\n- ioc one\n- ioc two\n"
        report_id = self.__add_report(original)

        body = rest_json(key, "POST", f"eventReports/aiSummarize/{report_id}")
        self.assertTrue(body["saved"], body)
        self.assertEqual(report_id, int(body["report_id"]))
        content = self.__report_content(report_id)
        self.assertTrue(content.startswith(AI_HEADING), content[:80])
        self.assertEqual((1, 1), count_blocks(content))
        self.assertTrue(content.rstrip().endswith(original.rstrip()), "the analyst's text must follow the block untouched")
        last = fake_last()["last"]
        self.assertEqual("summarization_on_eventReport", last["use_case"])
        self.assertEqual(original, last["data"]["EventReport"]["content"], "the module must see the original text")

        # re-run: one block, not two, and the module again saw the original
        body = rest_json(key, "POST", f"eventReports/aiSummarize/{report_id}")
        self.assertTrue(body["saved"], body)
        content = self.__report_content(report_id)
        self.assertEqual((1, 1), count_blocks(content))
        self.assertTrue(content.rstrip().endswith(original.rstrip()))
        self.assertEqual(original, fake_last()["last"]["data"]["EventReport"]["content"])

    # ---- A3 -----------------------------------------------------------------

    def test_05_recommend_tags_without_the_tag_editor_permission(self):
        body = rest_json(self.org_key, "GET", f"events/aiRecommendTags/{self.event_id}")
        self.assertFalse(body["local"], "the org user may modify the event: global tags")
        unknown = [row for row in body["Tag"] if not row["exists"] and row["cluster_id"] is None and row["status"] != "present"]
        for row in unknown:
            self.assertEqual("needs_tag_editor", row["status"], row)
            self.assertFalse(row["selectable"])
            self.assertIn("tag editor", row["reason"])
        name = 'ai-ux-editor-only:%s="1"' % random()
        body = rest_json(self.org_key, "POST", f"events/aiRecommendTags/{self.event_id}", {"tags": [name]})
        self.assertEqual(0, body["attached"], body)
        self.assertEqual(1, body["failed"], body)
        self.assertIn("tag editor", body["errors"][name])
        self.assertFalse(self.admin.search_tags(name), "no tag may have been created")

    def test_06_recommend_tags_host_org_user_gets_local_tags(self):
        body = rest_json(self.host_key, "GET", f"events/aiRecommendTags/{self.event_id}")
        self.assertTrue(body["local"], "no edit rights on another org's event: local tags")
        candidates = [row["name"] for row in body["Tag"] if row["selectable"] and row["cluster_id"] is None]
        self.assertTrue(candidates, body)
        before = self.__event()
        body = rest_json(self.host_key, "POST", f"events/aiRecommendTags/{self.event_id}", {"tags": candidates[:1]})
        self.assertEqual(1, body["attached"], body)
        self.assertTrue(body["local"])
        self.assertFalse(body["check_publish"])
        self.assertIn("local", body["success"])
        after = self.__event()
        self.assertEqual(before["timestamp"], after["timestamp"], "a local tag must not unpublish the event")
        local = [t for t in after.get("Tag", []) if t["name"].lower() == candidates[0].lower()]
        self.assertEqual(1, len(local), after.get("Tag"))
        self.assertTrue(local[0]["local"])
        self.__remember_tags(rest_json(key, "GET", f"events/aiRecommendTags/{self.event_id}")["Tag"])

    def test_07_recommend_tags_accept_creates_attaches_and_skips(self):
        body = rest_json(key, "GET", f"events/aiRecommendTags/{self.event_id}")
        self.assertFalse(body["local"])
        rows = body["Tag"]
        self.assertTrue(rows)
        for row in rows:
            self.assertIn(row["status"], ("ok", "present", "needs_tag_editor", "unknown_cluster", "restricted", "local_only", "exclusive"))
            self.assertEqual(row["status"] == "ok", row["selectable"])
            self.assertTrue(row["colour"].startswith("#"), row)
            self.assertEqual(row["name"].lower().startswith("misp-galaxy:"), row["is_galaxy"], row)
        names = [row["name"] for row in rows if row["selectable"]]
        new = [row["name"] for row in rows if row["selectable"] and not row["exists"]]
        self.assertTrue(names, rows)

        body = rest_json(key, "POST", f"events/aiRecommendTags/{self.event_id}", {"tags": names})
        self.assertTrue(body["saved"], body)
        self.assertEqual(len(names), body["attached"], body)
        self.assertEqual(len(new), body["created"], body)
        self.assertEqual(0, body["failed"], body)
        self.assertTrue(body["check_publish"])
        event = self.__event()
        on_event = {t["name"].lower() for t in event.get("Tag", [])}
        for name in names:
            self.assertIn(name.lower(), on_event)

        again = rest_json(key, "POST", f"events/aiRecommendTags/{self.event_id}", {"tags": names})
        self.assertEqual(0, again["attached"], again)
        self.assertEqual(len(names), again["skipped"], again)

        rows = rest_json(key, "GET", f"events/aiRecommendTags/{self.event_id}")["Tag"]
        self.__remember_tags(rows)
        for row in rows:
            if row["name"] in names:
                self.assertEqual("present", row["status"], row)
                self.assertFalse(row["selectable"])

    def test_08_recommend_tags_refusals(self):
        ghost = 'misp-galaxy:threat-actor="AI UX nobody %s"' % random()
        body = rest_json(key, "POST", f"events/aiRecommendTags/{self.event_id}", {"tags": [ghost]})
        self.assertEqual(0, body["attached"], body)
        self.assertEqual(1, body["failed"], body)
        self.assertIn("cluster", body["errors"][ghost])

        # an empty selection is a failed save: MISP's saveFailResponse answers 403
        body = rest_json(key, "POST", f"events/aiRecommendTags/{self.event_id}", {"tags": []}, expect=403)
        self.assertFalse(body["saved"])
        self.assertIn("No tags", body["errors"])

        # taxonomy exclusivity: a second tlp tag next to the one the fake
        # suggests, when that one is on the event
        event = self.__event()
        tlp = [t["name"] for t in event.get("Tag", []) if t["name"].startswith("tlp:")]
        if tlp:
            other = "tlp:red" if "tlp:red" not in tlp else "tlp:green"
            body = rest_json(key, "POST", f"events/aiRecommendTags/{self.event_id}", {"tags": [other]})
            self.assertEqual(0, body["attached"], body)
            self.assertIn("exclusiv", body["errors"].get(other, ""), body)

    # ---- ACL ----------------------------------------------------------------

    def test_09_acl(self):
        report_id = self.__add_report("acl probe")
        for method, path in (
            ("GET", f"events/aiRecommendTags/{self.event_id}"),
            ("POST", f"events/aiRecommendTags/{self.event_id}"),
            ("GET", f"events/aiActions/{self.event_id}"),
            ("POST", f"events/aiSummarize/{self.event_id}"),
            ("POST", f"eventReports/aiSummarize/{report_id}"),
        ):
            r = rest(self.reader_key, method, path, {"tags": ["tlp:amber"]} if method == "POST" else None)
            self.assertEqual(403, r.status_code, f"{method} {path} without perm_ai_tools: {r.text[:200]}")
        self.assertEqual(404, rest(key, "GET", "events/aiRecommendTags/999999999").status_code)
        self.assertEqual(404, rest(key, "POST", "events/aiSummarize/999999999").status_code)

        self.__setting("Plugin.AI_services_enable", False)
        try:
            for method, path in (
                ("GET", f"events/aiRecommendTags/{self.event_id}"),
                ("POST", f"events/aiSummarize/{self.event_id}"),
                ("POST", f"eventReports/aiSummarize/{report_id}"),
            ):
                r = rest(key, method, path)
                self.assertEqual(405, r.status_code, f"{method} {path} with AI off: {r.text[:200]}")
        finally:
            self.__setting("Plugin.AI_services_enable", True)

    # ---- workflow node --------------------------------------------------------

    def test_10_workflow_node_summarises_a_report(self):
        original = "Node input " + random() + "\n\nplain analyst text\n"
        report_id = self.__add_report(original)
        event = rest_json(key, "GET", f"events/view/{self.event_id}")
        r = rest(key, "POST", "workflows/moduleStatelessExecution/send-report-to-cti-info-extractor", {
            "input_data": json.dumps(event),
            "module_indexed_param": {},
            "convert_data": False,
        })
        if r.status_code == 404:
            self.skipTest("workflow stateless execution not available: " + r.text[:200])
        self.assertEqual(200, r.status_code, r.text[:300])
        content = self.__report_content(report_id)
        self.assertTrue(content.startswith(AI_HEADING), content[:80])
        self.assertEqual((1, 1), count_blocks(content))
        self.assertTrue(content.rstrip().endswith(original.rstrip()))


if __name__ == "__main__":
    unittest.main()
