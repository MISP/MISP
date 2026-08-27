#!/usr/bin/env python3
"""Shared helpers for MISP's live test suite.

Every testlive_* script re-implements the same three things: resolving the
instance URL and key, talking to endpoints PyMISP does not wrap, and undoing
whatever it changed. The third is the one that matters.

**Why the settings guard exists.** testlive_security.py mutates global server
settings and only restores them on a clean exit. Interrupting it once left
`Security.auth` set to `ShibbAuth.ApacheShibb` in app/Config/config.php, after
which the login page rendered with no form and *every* later run failed at
setUpClass with an error that looked nothing like its cause. Any script that
changes a server setting must restore it even when killed, which is what
SettingsGuard does via atexit and signal handlers.
"""
from __future__ import annotations

import atexit
import os
import signal
import sys
from typing import Any

import requests


def resolve_target() -> tuple[str, str]:
    """Return (url, key) from the environment, falling back to tests/keys.py."""
    try:
        return "http://" + os.environ["HOST"], os.environ["AUTH"]
    except KeyError:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        import keys  # type: ignore[import-not-found]

        return keys.url, keys.key


class MispApi:
    """Thin JSON client for endpoints PyMISP does not wrap.

    The dashboard and workflow controllers have no PyMISP surface, so they are
    driven directly here.
    """

    def __init__(self, url: str | None = None, key: str | None = None, timeout: int = 60) -> None:
        resolved_url, resolved_key = resolve_target()
        self.url = (url or resolved_url).rstrip("/")
        self.key = key or resolved_key
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": self.key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        })

    def request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        return self.session.request(
            method, f"{self.url}/{path.lstrip('/')}", timeout=self.timeout, **kwargs
        )

    def get(self, path: str, **kwargs: Any) -> requests.Response:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, json_body: Any = None, **kwargs: Any) -> requests.Response:
        return self.request("POST", path, json=json_body, **kwargs)

    def json(self, method: str, path: str, **kwargs: Any) -> Any:
        response = self.request(method, path, **kwargs)
        try:
            return response.json()
        except ValueError:
            return {"__status": response.status_code, "__text": response.text[:400]}

    # -- server settings ---------------------------------------------------

    def get_setting(self, name: str) -> Any:
        payload = self.json("GET", f"/servers/getSetting/{name}")
        return payload.get("value") if isinstance(payload, dict) else None

    def set_setting(self, name: str, value: Any, force: bool = True) -> Any:
        body = {"value": value}
        if force:
            body["force"] = 1
        return self.json("POST", f"/servers/serverSettingsEdit/{name}", json=body)


class SettingsGuard:
    """Record server settings on entry and restore them on ANY exit.

    Registered with atexit and SIGINT/SIGTERM so an interrupted run still puts
    the instance back, rather than leaving it unusable for later runs.
    """

    def __init__(self, api: MispApi, settings: list[str]) -> None:
        self.api = api
        self.settings = settings
        self.original: dict[str, Any] = {}
        self._armed = False

    def __enter__(self) -> "SettingsGuard":
        for name in self.settings:
            self.original[name] = self.api.get_setting(name)
        atexit.register(self.restore)
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                previous = signal.getsignal(sig)
                signal.signal(sig, self._make_handler(previous))
            except (ValueError, OSError):
                # Not on the main thread; atexit still covers a clean exit.
                pass
        self._armed = True
        return self

    def _make_handler(self, previous: Any):
        def handler(signum, frame):
            self.restore()
            if callable(previous):
                previous(signum, frame)
            else:
                sys.exit(128 + signum)
        return handler

    def restore(self) -> None:
        if not self._armed:
            return
        self._armed = False
        for name, value in self.original.items():
            if value is None:
                continue
            try:
                self.api.set_setting(name, value)
            except Exception as exc:  # pragma: no cover - best effort on the way out
                print(f"WARNING: could not restore {name}: {exc}", file=sys.stderr)

    def __exit__(self, exc_type, exc, tb) -> None:
        self.restore()


def is_error(payload: Any) -> bool:
    """MISP signals failure in several shapes; normalise the check."""
    if isinstance(payload, dict):
        if "errors" in payload:
            return True
        if payload.get("saved") is False:
            return True
        status = payload.get("__status")
        if isinstance(status, int) and status >= 400:
            return True
    return False
