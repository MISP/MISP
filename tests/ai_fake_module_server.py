#!/usr/bin/env python3
"""
Fake `ai_connector` misp-module server for the MISP AI UX tests.

Speaks the contract MISP assumes of the real module (PRD `misp_ai_ux` §3) so
every MISP code path — settings page status card, dry run, the three AI
actions, the workflow node — can be exercised without the real module or an
LLM. Standard library only.

    GET  /modules   -> the misp-modules listing: one module, `ai_connector`,
                       `meta["module-type"] == ["ai"]`
    POST /query     -> {"module", "data", "use_case", "params", "timeout"}
                       answered per use_case with a deterministic result:
        summarization_on_event        results.EventReport {name, content}
        summarization_on_eventReport  results.EventReport {name, content}
                                      (the summary block on top of the
                                      original content; a request whose
                                      content already carries the block is
                                      an error — MISP must strip it first)
        tag_suggest                   results.Tag [{name}, ...] filtered by
                                      params.suggest_min_score and capped by
                                      params.suggest_limit
    GET  /last      -> the last /query envelope received and the request
                       count, so a test can assert what MISP sent
    GET  /health    -> {"ok": true}

Failure knobs: `--fail` answers every query with {"error"}; `--delay N`
sleeps N seconds before answering (an {"error": "Timeout."} like misp-modules
when N exceeds the request's `timeout`); a request whose params.model_id is
`fake:error` gets an error answer regardless.

Usage:
    python3 tests/ai_fake_module_server.py [--port 6667] [--listen 127.0.0.1]
                                           [--delay 0] [--fail] [--verbose]
then point MISP at it: Plugin.AI_services_enable = true,
Plugin.AI_services_url = http://127.0.0.1, Plugin.AI_services_port = 6667.
"""

import argparse
import json
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODULE_NAME = "ai_connector"
USE_CASES = ("summarization_on_event", "summarization_on_eventReport", "tag_suggest")
PARAM_NAMES = (
    "openai_api_base", "api_key", "model_id", "temperature",
    "request_timeout", "suggest_limit", "suggest_min_score",
)
# The AI summary block (PRD §3.3): heading on top, summary, blank line, a
# visible delineator line of equals signs, then the report. MISP keys its
# strip on the heading-at-top + delineator pair.
SUMMARY_HEADING = "# AI summary"
SUMMARY_DELINEATOR = "=================="
SUMMARY_RE = re.compile(r"\A\s*#[ \t]*AI summary[ \t]*(?:\r?\n|\Z)(?:.*?\r?\n)?[ \t]*={10,}[ \t]*(?:\r?\n|\Z)", re.S | re.I)

# Fixed tag candidates with a confidence, so suggest_limit / suggest_min_score
# can be asserted: 0.9 and 0.8 exist on most instances, the rest are unknown.
TAG_CANDIDATES = [
    ("tlp:amber", 0.9),
    ('misp-galaxy:threat-actor="APT1"', 0.8),
    ("ai-fake:confidence=\"high\"", 0.7),
    ("ai-fake:confidence=\"medium\"", 0.5),
    ("ai-fake:confidence=\"low\"", 0.3),
    ("ai-fake:confidence=\"noise\"", 0.1),
]

STATE = {"last": None, "count": 0, "lock": threading.Lock()}
OPTIONS = {"delay": 0.0, "fail": False, "verbose": False}


def listing():
    return [{
        "name": MODULE_NAME,
        "type": "expansion",
        "mispattributes": {"input": [], "output": [], "format": "misp_standard"},
        "meta": {
            "module-type": ["ai"],
            "description": "Fake ai_connector answering the MISP AI contract with fixed results.",
            "version": "0.0-fake",
            "author": "MISP AI UX tests",
            "config": list(PARAM_NAMES),
        },
    }]


def summary_block(lines):
    body = "\n".join("- " + line for line in lines)
    return f"{SUMMARY_HEADING}\n{body}\n\n{SUMMARY_DELINEATOR}"


def event_facts(event, params):
    attributes = event.get("Attribute") or []
    objects = event.get("Object") or []
    tags = [t.get("name") for t in (event.get("Tag") or []) if t.get("name")]
    return [
        f"event {event.get('id', '?')} ({event.get('uuid', 'no uuid')}): {event.get('info', '')}".strip(),
        f"{len(attributes)} attributes, {len(objects)} objects, {len(tags)} tags",
        "tags: " + (", ".join(tags) if tags else "none"),
        f"model {params.get('model_id', 'unset')} at {params.get('openai_api_base', 'unset')}",
    ]


def answer(envelope):
    if envelope.get("module") != MODULE_NAME:
        return {"error": f"Unknown module `{envelope.get('module')}`."}
    use_case = envelope.get("use_case")
    if use_case not in USE_CASES:
        return {"error": f"Unknown use_case `{use_case}`."}
    params = envelope.get("params") or {}
    data = envelope.get("data") or {}
    if OPTIONS["fail"] or params.get("model_id") == "fake:error":
        return {"error": "Fake failure requested."}

    if use_case == "summarization_on_event":
        event = data.get("Event")
        if not isinstance(event, dict):
            return {"error": "summarization_on_event needs data.Event."}
        info = (event.get("info") or f"event {event.get('id', '?')}")[:60]
        return {"results": {"EventReport": {
            "name": f"AI summary: {info}",
            "content": summary_block(event_facts(event, params)),
        }}}

    if use_case == "summarization_on_eventReport":
        report = data.get("EventReport")
        if not isinstance(report, dict):
            return {"error": "summarization_on_eventReport needs data.EventReport."}
        content = report.get("content") or ""
        if SUMMARY_RE.search(content):
            return {"error": "The report already carries an AI summary block on top; MISP must strip it before sending."}
        words = len(content.split())
        block = summary_block([
            f"report {report.get('id', '?')} `{report.get('name', '')}` has {words} words",
            f"model {params.get('model_id', 'unset')}",
        ])
        return {"results": {"EventReport": {
            "name": report.get("name", ""),
            "content": f"{block}\n\n{content}",
        }}}

    # tag_suggest
    if not isinstance(data.get("Event"), dict):
        return {"error": "tag_suggest needs data.Event."}
    try:
        min_score = float(params.get("suggest_min_score", 0) or 0)
        limit = int(params.get("suggest_limit", 5) or 5)
    except (TypeError, ValueError):
        return {"error": "suggest_min_score / suggest_limit must be numbers."}
    tags = [{"name": name} for name, score in TAG_CANDIDATES if score >= min_score][:max(limit, 0)]
    return {"results": {"Tag": tags}}


class Handler(BaseHTTPRequestHandler):
    def _send(self, payload, status=200):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        if OPTIONS["verbose"]:
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def do_GET(self):
        if self.path == "/modules":
            return self._send(listing())
        if self.path == "/last":
            with STATE["lock"]:
                return self._send({"count": STATE["count"], "last": STATE["last"]})
        if self.path in ("/", "/health"):
            return self._send({"ok": True})
        self._send({"error": "Not found."}, 404)

    def do_POST(self):
        if self.path != "/query":
            return self._send({"error": "Not found."}, 404)
        length = int(self.headers.get("Content-Length") or 0)
        try:
            envelope = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self._send({"error": "Body is not JSON."})
        with STATE["lock"]:
            STATE["count"] += 1
            STATE["last"] = envelope
        if OPTIONS["verbose"]:
            sys.stderr.write("query: %s\n" % json.dumps(envelope)[:400])
        try:
            timeout = int(envelope.get("timeout", 300))
        except (TypeError, ValueError):
            timeout = 300
        if OPTIONS["delay"] > 0:
            time.sleep(min(OPTIONS["delay"], timeout))
            if OPTIONS["delay"] > timeout:
                return self._send({"error": "Timeout."})
        self._send(answer(envelope))


def main():
    parser = argparse.ArgumentParser(description="Fake ai_connector misp-module server")
    parser.add_argument("-p", "--port", type=int, default=6667, help="port (default 6667)")
    parser.add_argument("-l", "--listen", default="127.0.0.1", help="address (default 127.0.0.1)")
    parser.add_argument("--delay", type=float, default=0.0, help="seconds to sleep before answering a query")
    parser.add_argument("--fail", action="store_true", help="answer every query with an error")
    parser.add_argument("-v", "--verbose", action="store_true", help="log requests to stderr")
    args = parser.parse_args()
    OPTIONS.update(delay=args.delay, fail=args.fail, verbose=args.verbose)
    server = ThreadingHTTPServer((args.listen, args.port), Handler)
    sys.stderr.write(f"fake ai_connector listening on http://{args.listen}:{args.port}\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
