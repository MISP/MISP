#!/usr/bin/env python3
"""Golden snapshots for MISP's API contract.

A snapshot records a normalised API response and is committed. A later run
diffs against it, so an unintended change to the response shape shows up as a
reviewable diff rather than a silent break. Snapshots are regenerated only
under an explicit flag: automatic regeneration would bless regressions and
delete the entire value of the approach.

    UPDATE_SNAPSHOTS=1 python3 testlive_restsearch_contract.py

**Normalisation is aliasing, not erasure.** Volatile values (ids, uuids,
timestamps) are replaced by stable tokens, but the SAME value always maps to
the SAME token within one snapshot. That preserves relationships - if two
attributes share an event_id, the snapshot still shows they share it - while
staying stable across runs. Erasing the values outright would hide exactly
the structural regressions this is meant to catch.

Some snapshots record behaviour that is known to be wrong. Those carry a
`KNOWN-DEFECT` note naming the defect and the specification test that asserts
the desired behaviour; see docs/adr/0002-pin-known-defects-in-golden-snapshots.md.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

SNAPSHOT_DIR = Path(__file__).resolve().parent.parent / "snapshots"

UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
EPOCH_RE = re.compile(r"\b1[0-9]{9}\b")
DATE_RE = re.compile(r"\b20[0-9]{2}-[0-9]{2}-[0-9]{2}(?:[T ][0-9]{2}:[0-9]{2}:[0-9]{2})?\b")
HASH40_RE = re.compile(r"\b[0-9a-zA-Z]{40}\b")
# CakePHP's debug error pages embed a per-request DOM id. It is pure noise,
# but it appears in any snapshot of a response that raised a warning.
CAKEERR_RE = re.compile(r"cakeErr[0-9a-f]+")

# Keys whose values are database identities rather than content.
ID_KEYS = {
    "id", "event_id", "org_id", "orgc_id", "attribute_id", "object_id",
    "sharing_group_id", "user_id", "role_id", "sighting_id", "cluster_id",
    "galaxy_id", "tag_id", "server_id", "job_id", "collection_id",
}
# Keys that are wall-clock and therefore never stable.
TIME_KEYS = {
    "timestamp", "publish_timestamp", "sighting_timestamp", "date",
    "last_seen", "first_seen", "date_created", "date_modified",
    "current_login", "last_login", "last_pulled_id", "last_pushed_id",
}


# Kinds whose values are erased rather than numbered. A timestamp carries no
# relational meaning worth preserving in a contract snapshot, and numbering it
# actively harms stability: two rows written in the same second yield one
# distinct value, in the next second two, which would shift every later token.
UNNUMBERED = {"time", "date"}


class Aliaser:
    """Maps volatile values to stable tokens, consistently within a snapshot.

    Counters are PER KIND. A single global counter would couple the numbering
    of ids to how many distinct timestamps happened to appear, so an unrelated
    run-to-run variation would rewrite every token in the file.
    """

    def __init__(self) -> None:
        self._seen: dict[tuple[str, str], str] = {}
        self._counts: dict[str, int] = {}

    def token(self, kind: str, value: Any) -> str:
        if kind in UNNUMBERED:
            return f"<{kind}>"
        key = (kind, str(value))
        if key not in self._seen:
            self._counts[kind] = self._counts.get(kind, 0) + 1
            self._seen[key] = f"<{kind}:{self._counts[kind]}>"
        return self._seen[key]


def normalise(payload: Any, aliaser: Aliaser | None = None) -> Any:
    """Replace volatile values with stable, relationship-preserving tokens."""
    aliaser = aliaser or Aliaser()
    return _walk(payload, aliaser, parent_key=None)


def _walk(node: Any, aliaser: Aliaser, parent_key: str | None) -> Any:
    if isinstance(node, dict):
        return {k: _walk(v, aliaser, k) for k, v in sorted(node.items())}
    if isinstance(node, list):
        return [_walk(v, aliaser, parent_key) for v in node]

    if parent_key in ID_KEYS and node not in (None, "", "0", 0):
        return aliaser.token("id", node)
    if parent_key in TIME_KEYS and node not in (None, "", "0", 0):
        return aliaser.token("time", node)
    if isinstance(node, str):
        return normalise_text(node, aliaser)
    return node


def normalise_text(text: str, aliaser: Aliaser | None = None,
                   volatile: list | None = None) -> str:
    """Normalise a raw (non-JSON) response body such as CSV or a rule file.

    `volatile` is the caller's own list of values it knows are unstable -
    typically the auto-increment ids of the fixture it just created. Those are
    aliased by exact match, which is the only safe way to handle bare integers:
    a regex broad enough to catch an event id (3 digits) would also catch a
    port number in a Snort rule, and a regex narrow enough to spare the port
    would miss the id.
    """
    aliaser = aliaser or Aliaser()
    values = sorted({str(v) for v in (volatile or []) if v not in (None, "")},
                    key=len, reverse=True)
    if values:
        # One alternation, substituted left to right, so tokens are numbered by
        # first occurrence in the DOCUMENT. Substituting value-by-value would
        # number them by list order instead, and any run where the list length
        # differs would shift every subsequent token and produce a spurious diff.
        pattern = "(?<![0-9a-zA-Z])(" + "|".join(re.escape(v) for v in values) + ")(?![0-9a-zA-Z])"
        text = re.sub(pattern, lambda m: aliaser.token("id", m.group(0)), text)
    text = UUID_RE.sub(lambda m: aliaser.token("uuid", m.group(0)), text)
    text = DATE_RE.sub(lambda m: aliaser.token("date", m.group(0)), text)
    text = EPOCH_RE.sub(lambda m: aliaser.token("time", m.group(0)), text)
    text = HASH40_RE.sub(lambda m: aliaser.token("key", m.group(0)), text)
    text = CAKEERR_RE.sub("cakeErr<id>", text)
    return text


def normalise_response(body: str, volatile: list | None = None) -> Any:
    """Normalise an API response, structurally when it is JSON.

    A JSON body is parsed and normalised by KEY, which aliases every
    identity field generically. Only non-JSON bodies fall back to the
    text path, where the caller's `volatile` list does the same job.
    """
    # Deliberately NOT pre-seeded: tokens are assigned in document order, so
    # the same response structure yields the same numbering no matter how many
    # volatile values the caller happened to know about.
    aliaser = Aliaser()
    try:
        return normalise(json.loads(body), aliaser)
    except (ValueError, TypeError):
        return normalise_text(body, aliaser, volatile)


def _path(name: str) -> Path:
    return SNAPSHOT_DIR / f"{name}.snapshot"


def updating() -> bool:
    return os.environ.get("UPDATE_SNAPSHOTS", "") not in ("", "0", "false")


def render(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False)
    return str(value)


def compare(name: str, actual: Any, known_defect: str | None = None) -> tuple[bool, str]:
    """Compare against the committed snapshot.

    Returns (matches, message). Writes the snapshot when UPDATE_SNAPSHOTS is
    set, or when none exists yet - a first run records rather than fails, so
    adding a case does not require a separate blessing step.
    """
    path = _path(name)
    body = render(actual)
    header = ""
    if known_defect:
        header = (
            f"# KNOWN-DEFECT: {known_defect}\n"
            f"# This records current behaviour so refactors are still detected.\n"
            f"# It is NOT the intended contract. Fixing the defect should produce\n"
            f"# exactly one diff here plus a specification test flipping to passing.\n"
        )
    content = header + body

    if updating() or not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return True, f"snapshot written: {path.name}"

    expected = path.read_text(encoding="utf-8")
    if expected == content:
        return True, "matches"

    return False, _diff(expected, content, path.name)


def _diff(expected: str, actual: str, name: str) -> str:
    import difflib

    lines = list(difflib.unified_diff(
        expected.splitlines(), actual.splitlines(),
        fromfile=f"{name} (committed)", tofile=f"{name} (now)", lineterm="", n=2,
    ))
    if len(lines) > 60:
        lines = lines[:60] + [f"... {len(lines) - 60} more diff lines"]
    return (
        "response contract changed.\n" + "\n".join(lines) +
        "\n\nIf this change is intended, re-run with UPDATE_SNAPSHOTS=1 and "
        "commit the updated snapshot so the diff is reviewed."
    )
