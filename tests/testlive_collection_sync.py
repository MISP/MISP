#!/usr/bin/env python3
"""
Collection sync end-to-end test (T6.1 — PRD §9.2).

Exercises the bidirectional collection sync feature over real HTTP: feature
negotiation, push (local -> peer), pull (local <- peer), the pull/push job
messages (their new collection-count clauses), and — in two-instance mode — the
capture write branch (locked=1, distribution downgrade 2->1, element
replication, D6 idempotency).

Two modes:

  * LOOPBACK (default, CI-friendly, single instance) — set only HOST + AUTH.
    A Server row pointing the instance at itself (as testlive_sync.py does)
    drives the full sync machinery end-to-end and asserts the round-trips run
    without error and surface the collection-count clauses. A self-loopback
    CANNOT show a collection actually crossing: the remote index/filter always
    sees an equal local copy of every offered UUID, so D6 skip-on-equal keeps
    the transfer at zero. The write-branch assertions are therefore skipped in
    this mode — exactly as testlive_sync.py asserts all-zero transfers on a
    self-loopback.

  * TWO-INSTANCE (full fidelity) — additionally set REMOTE_HOST + REMOTE_AUTH
    for a *distinct* peer that also runs the feature code. The script then
    asserts a pushed collection actually lands on the peer with locked=1, a
    downgraded distribution and its element replicated, that a colliding
    locally-created (locked=0) collection is NOT overwritten (D6), and that a
    re-push is a no-op (idempotency). A pull write-branch check runs too when
    the peer is reachable with its own key.

Environment:
    HOST, AUTH                local instance (host:port + admin/sync API key)
    REMOTE_HOST, REMOTE_AUTH  optional distinct peer -> enables two-instance mode

Run (loopback):
    HOST=127.0.0.1:5007 AUTH=<key> python3 tests/testlive_collection_sync.py

Run (two instances):
    HOST=127.0.0.1:5007 AUTH=<keyA> \\
    REMOTE_HOST=127.0.0.1:5008 REMOTE_AUTH=<keyB> \\
    python3 tests/testlive_collection_sync.py
"""

import os
import sys
import time

from pymisp import PyMISP, MISPEvent


def check_response(response):
    if isinstance(response, dict) and "errors" in response:
        raise Exception(response["errors"])
    return response


def truthy(value):
    return value in (1, "1", True, "true", "True")


# ---------------------------------------------------------------------------
# raw collection REST helpers (PyMISP has no collection wrappers; mirror the
# _prepare_request pattern testlive_sync.py uses for the sync endpoints)
# ---------------------------------------------------------------------------

def supports_collection_sync(misp):
    """The negotiation surface: does GET /servers/getVersion advertise the flag?"""
    info = check_response(misp._check_response(misp._prepare_request('GET', 'servers/getVersion')))
    return truthy(info.get('collection_sync', False))


def add_collection(misp, name, distribution, elements):
    """POST /collections/add. `elements` is a list of {element_type, element_uuid}."""
    payload = {'Collection': {
        'name': name,
        'type': 'default',
        'description': 'collection sync E2E fixture',
        'distribution': distribution,
        'CollectionElement': elements,
    }}
    resp = check_response(misp._check_response(misp._prepare_request('POST', 'collections/add', data=payload)))
    return resp.get('Collection', resp)


def get_collection(misp, uuid):
    """GET the full collection (with elements) by uuid, or None if not visible."""
    url = f'collections/index/uuid[]:{uuid}.json'
    resp = check_response(misp._check_response(misp._prepare_request('GET', url)))
    rows = resp if isinstance(resp, list) else resp.get('response', resp)
    if not isinstance(rows, list):
        return None
    for row in rows:
        col = row.get('Collection', row)
        if col.get('uuid') == uuid:
            # elements may sit under Collection or as a sibling depending on view
            if 'CollectionElement' not in col and isinstance(row, dict) and 'CollectionElement' in row:
                col['CollectionElement'] = row['CollectionElement']
            return col
    return None


def delete_collection(misp, collection_id):
    if not collection_id:
        return
    try:
        misp._check_response(misp._prepare_request('POST', f'collections/delete/{collection_id}'))
    except Exception as exc:  # cleanup is best-effort
        print(f"  (cleanup) could not delete collection {collection_id}: {exc}")


def run_push(misp, server_id):
    url = f'servers/push/{server_id}/full/disable_background_processing:1'
    return check_response(misp._check_response(misp._prepare_request('POST', url)))


def run_pull(misp, server_id):
    url = f'servers/pull/{server_id}/disable_background_processing:1'
    return check_response(misp._check_response(misp._prepare_request('GET', url)))


# ---------------------------------------------------------------------------

def main():
    try:
        host = os.environ["HOST"]
        key = os.environ["AUTH"]
    except KeyError:
        print("HOST and AUTH must be set (host:port + API key of the local instance).")
        return 2

    remote_host = os.environ.get("REMOTE_HOST")
    remote_key = os.environ.get("REMOTE_AUTH")
    two_instance = bool(remote_host and remote_key)

    url = "http://" + host
    misp = PyMISP(url, key, False)
    misp.global_pythonify = False

    if two_instance:
        remote_url = "http://" + remote_host
        remote_misp = PyMISP(remote_url, remote_key, False)
        remote_misp.global_pythonify = False
        print(f"Mode: TWO-INSTANCE ({host} <-> {remote_host})")
    else:
        remote_url, remote_misp = url, misp
        print(f"Mode: LOOPBACK ({host} -> itself)")

    # --- feature negotiation surface ----------------------------------------
    assert supports_collection_sync(misp), "local getVersion does not advertise collection_sync"
    print("OK: local instance advertises collection_sync")
    if not supports_collection_sync(remote_misp):
        # An old peer that omits the flag: negotiation must skip collection sync
        # silently. That is a valid (negative) configuration, not a failure here.
        print("NOTE: peer does not advertise collection_sync -> collection sync would be "
              "skipped by negotiation. Nothing to assert; exiting cleanly.")
        return 0
    print("OK: peer advertises collection_sync")

    server = None
    server_id = None
    event = None
    col_uuid = None
    local_col_id = None
    remote_pull_col_id = None

    try:
        # --- a Server row local -> peer, collection toggles on ---------------
        server = check_response(misp.add_server({
            "pull": True,
            "push": True,
            "pull_collections": True,
            "push_collections": True,
            "remote_org_id": 1,
            "name": "collection-sync-e2e",
            "url": remote_url,
            "authkey": remote_key if two_instance else key,
        }))
        server_id = server.get('Server', server).get('id') if isinstance(server, dict) else server.id
        print(f"OK: created sync Server row #{server_id}")

        server_test = check_response(misp.test_server(server))
        assert server_test["status"] == 1, f"server test failed: {server_test}"
        print("OK: server connection test passed")

        # --- a source collection with one Event-pointer element -------------
        event = MISPEvent()
        event.info = "collection sync E2E - element target"
        event.distribution = 1
        event = check_response(misp.add_event(event))
        event_uuid = event.get('Event', event).get('uuid') if isinstance(event, dict) else event.uuid
        print(f"OK: created target event {event_uuid}")

        col_name = f"e2e-collection-{int(time.time())}"
        local_col = add_collection(misp, col_name, distribution=2, elements=[
            {'element_type': 'Event', 'element_uuid': event_uuid, 'description': ''},
        ])
        col_uuid = local_col['uuid']
        local_col_id = local_col['id']
        print(f"OK: created source collection {col_uuid} (dist=2, 1 element)")

        # --- PUSH (local -> peer) -------------------------------------------
        # NB the push *caller* message surfaces only events (parity with the
        # sibling sync types — T5.2); the collections push count lives in the
        # Server::push $change DB-log, not in this message. So we assert the push
        # completed cleanly; the real collection-crossing proof is the peer-side
        # write-branch check below (two-instance mode).
        push_resp = run_push(misp, server_id)
        push_msg = push_resp.get("message", "") if isinstance(push_resp, dict) else str(push_resp)
        assert "Push complete" in push_msg, f"push did not complete cleanly: {push_msg!r}"
        print(f"OK: push completed: {push_msg!r}")

        if two_instance:
            remote_col = get_collection(remote_misp, col_uuid)
            assert remote_col is not None, "pushed collection did not land on the peer"
            assert truthy(remote_col.get('locked')), f"peer copy not locked=1: {remote_col.get('locked')!r}"
            assert int(remote_col.get('distribution')) == 1, \
                f"distribution not downgraded 2->1 on the peer: {remote_col.get('distribution')!r}"
            elements = remote_col.get('CollectionElement', [])
            assert any(e.get('element_uuid') == event_uuid for e in elements), \
                "element not replicated on the peer"
            print("OK: peer captured the collection locked=1, dist 2->1, element replicated")

            # idempotency: a second push must not duplicate or re-import it (D6)
            run_push(misp, server_id)
            again = get_collection(remote_misp, col_uuid)
            assert again is not None and again.get('modified') == remote_col.get('modified'), \
                "re-push changed the peer copy (idempotency broken)"
            print("OK: re-push is a no-op (D6 skip-on-equal idempotency)")

            # D6 origin protection: the peer's now-locked=1 copy offered back on a
            # pull must NOT overwrite our locked=0 authoritative original.
            pull_resp = run_pull(misp, server_id)
            pull_msg = pull_resp.get("message", "") if isinstance(pull_resp, dict) else str(pull_resp)
            local_after = get_collection(misp, col_uuid)
            assert local_after is not None and not truthy(local_after.get('locked')), \
                "local authoritative (locked=0) original was overwritten by a pull-back (D6 violated)"
            print("OK: pulled back without clobbering the local locked=0 original (D6 origin protection)")
        else:
            # loopback: assert the pull machinery runs and surfaces its clause
            pull_resp = run_pull(misp, server_id)
            pull_msg = pull_resp.get("message", "") if isinstance(pull_resp, dict) else str(pull_resp)
            assert "collections pulled" in pull_msg, \
                f"pull message missing collections clause: {pull_msg!r}"
            print(f"OK: pull ran, message carries the collections clause: {pull_msg!r}")

        # --- PULL write branch (two-instance only): peer-origin collection ---
        if two_instance:
            remote_only = add_collection(remote_misp, f"e2e-remote-{int(time.time())}",
                                         distribution=2, elements=[
                                             {'element_type': 'Event', 'element_uuid': event_uuid, 'description': ''},
                                         ])
            remote_only_uuid = remote_only['uuid']
            remote_pull_col_id = remote_only['id']
            print(f"OK: created peer-origin collection {remote_only_uuid} for the pull test")

            run_pull(misp, server_id)
            pulled = get_collection(misp, remote_only_uuid)
            assert pulled is not None, "peer-origin collection was not pulled to the local instance"
            assert truthy(pulled.get('locked')), "pulled copy not locked=1"
            assert int(pulled.get('distribution')) == 1, "pulled copy distribution not downgraded 2->1"
            print("OK: pull captured the peer-origin collection locked=1, dist 2->1")
            # clean the local copy of the pulled collection too
            local_pulled = get_collection(misp, remote_only_uuid)
            if local_pulled and local_pulled.get('id'):
                delete_collection(misp, local_pulled['id'])

        print("\nAll collection sync E2E assertions passed.")
        return 0

    finally:
        # best-effort teardown, in reverse creation order
        print("Cleaning up...")
        if two_instance and remote_pull_col_id:
            delete_collection(remote_misp, remote_pull_col_id)
        # remove the peer copy of the pushed collection
        if two_instance and col_uuid:
            try:
                peer_copy = get_collection(remote_misp, col_uuid)
                if peer_copy and peer_copy.get('id'):
                    delete_collection(remote_misp, peer_copy['id'])
            except Exception:
                pass
        delete_collection(misp, local_col_id)
        if server_id:
            try:
                check_response(misp.delete_server(server_id))
            except Exception as exc:
                print(f"  (cleanup) could not delete server {server_id}: {exc}")
        if event is not None:
            try:
                event_id = event.get('Event', event).get('id') if isinstance(event, dict) else event.id
                misp.delete_event(event_id)
                misp.delete_event_blocklist(event.get('Event', event).get('uuid') if isinstance(event, dict) else event.uuid)
            except Exception as exc:
                print(f"  (cleanup) could not delete event: {exc}")


if __name__ == "__main__":
    sys.exit(main())
