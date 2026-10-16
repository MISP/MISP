import os
import uuid
from pymisp import PyMISP, MISPEvent, MISPGalaxyCluster


def check_response(response):
    if isinstance(response, dict) and "errors" in response:
        raise Exception(response["errors"])


# Load access information for env variables
url = "http://" + os.environ["HOST"]
key = os.environ["AUTH"]

pymisp = PyMISP(url, key, False)
pymisp.global_pythonify = True

# Create new remote server, that is the same just for test
remote_server = pymisp.add_server({
    "pull": True,
    "pull_galaxy_clusters": True,
    "push_galaxy_clusters": True,
    "push": True,
    "push_sightings": True,
    "pull_analyst_data": True,
    "push_analyst_data": True,
    "caching_enabled": True,
    "remote_org_id": 1,
    "name": "Localhost",
    "url": url,
    "authkey": key,
})
check_response(remote_server)

# Check connection
server_test = pymisp.test_server(remote_server)
check_response(server_test)
assert server_test["status"] == 1
assert server_test["post"] == 1

# Get remote user
url = f'servers/getRemoteUser/{remote_server["id"]}'
remote_user = pymisp._check_response(pymisp._prepare_request('GET', url))
check_response(remote_user)
assert remote_user["Sync flag"] == "Yes"
assert remote_user["Role name"] == "admin"
assert remote_user["User"] == "admin@admin.test"

# Create testing event
event = MISPEvent()
event.load_file(os.path.dirname(os.path.realpath(__file__)) + "/event.json")
event.info = "OSINT - F-Secure W32/Regin, Stage #1 - from testlive_sync.py"
# pymisp.delete_event_blocklist(event)
event = pymisp.add_event(event, metadata=True)
check_response(event)

# Publish that event
check_response(pymisp.publish(event))

# Publish event inline
url = f'events/publish/{event.id}/disable_background_processing:1'
push_event = pymisp._check_response(pymisp._prepare_request('POST', url))
check_response(push_event)

# Create testing galaxy cluster
galaxy = pymisp.galaxies()[0]
galaxy_cluster = MISPGalaxyCluster()
galaxy_cluster.value = "Test Cluster"
galaxy_cluster.authors = ["MISP"]
galaxy_cluster.distribution = 1
galaxy_cluster.description = "Example test cluster"
galaxy_cluster = pymisp.add_galaxy_cluster(galaxy.id, galaxy_cluster)
check_response(galaxy_cluster)

# Publish that galaxy cluster
check_response(pymisp.publish_galaxy_cluster(galaxy_cluster))

# Analyst graphs. A loopback cannot show one crossing, so a peer's push is
# replayed by hand; the pull and push below run with the graph present.
version = pymisp._check_response(pymisp._prepare_request('GET', 'servers/getVersion'))
assert version.get("analyst_graph") is True, version

graph = pymisp._check_response(pymisp._prepare_request('POST', f'analyst_data/add/Graph/{event.uuid}/Event', data={
    "name": "Graph from testlive_sync.py",
    "distribution": 2,
    "content": {"nodes": [{"type": "Event", "uuid": event.uuid}, {"type": "Value", "value": "8.8.8.8"}]},
}))
check_response(graph)
graph = pymisp._check_response(pymisp._prepare_request('GET', f'analyst_data/view/Graph/{graph["Graph"]["uuid"]}'))
check_response(graph)
graph = graph["Graph"]

# A puller that does not name the types it understands never sees a graph
index = pymisp._check_response(pymisp._prepare_request('POST', 'analyst_data/indexMinimal', data={}))
assert "Graph" not in index, index
index = pymisp._check_response(pymisp._prepare_request('POST', 'analyst_data/indexMinimal', data={
    "types": ["Note", "Opinion", "Relationship", "Graph"],
}))
assert index["Graph"][graph["uuid"]] == {"modified": graph["modified"], "size": int(graph["content_size"])}, index["Graph"]

peer_graph = {key: graph[key] for key in (
    "object_uuid", "object_type", "orgc_uuid", "name", "created", "modified", "content",
)}
peer_graph.update({"uuid": str(uuid.uuid4()), "distribution": 1, "locked": True, "revision": 9, "Orgc": graph["Orgc"]})
check_response(pymisp._check_response(pymisp._prepare_request('POST', 'analyst_data/pushAnalystData', data={"Graph": peer_graph})))
pushed_graph = pymisp._check_response(pymisp._prepare_request('GET', f'analyst_data/view/Graph/{peer_graph["uuid"]}'))
check_response(pushed_graph)
pushed_graph = pushed_graph["Graph"]
assert pushed_graph["locked"] in (True, 1, "1"), pushed_graph["locked"]
assert int(pushed_graph["revision"]) == 1, pushed_graph["revision"]
assert int(pushed_graph["node_count"]) == 2, pushed_graph["node_count"]

# An invalid document is refused, not acknowledged
invalid_graph = dict(peer_graph, uuid=str(uuid.uuid4()), content={"nodes": [{"type": "Tag", "uuid": str(uuid.uuid4())}]})
refused = pymisp._check_response(pymisp._prepare_request('POST', 'analyst_data/pushAnalystData', data={"Graph": invalid_graph}))
assert isinstance(refused, dict) and "errors" in refused, refused

# A batched push reports on each record, in order
assert version.get("analyst_data_batch_push") is True, version
batch = [{"Graph": dict(peer_graph, uuid=str(uuid.uuid4()))}, {"Graph": peer_graph}, {"Graph": invalid_graph}]
report = pymisp._check_response(pymisp._prepare_request('POST', 'analyst_data/pushAnalystDataBatch', data=batch))
assert [r["result"] for r in report["results"]] == ["imported", "ignored", "failed"], report
assert report["results"][0]["uuid"] == batch[0]["Graph"]["uuid"], report
batch_graph = pymisp._check_response(pymisp._prepare_request('GET', f'analyst_data/view/Graph/{batch[0]["Graph"]["uuid"]}'))
check_response(batch_graph)
batch_graph = batch_graph["Graph"]

# Preview index
url = f'servers/previewIndex/{remote_server["id"]}'
index_preview = pymisp._check_response(pymisp._prepare_request('GET', url))
check_response(index_preview)

# Preview event
url = f'servers/previewEvent/{remote_server["id"]}/{event.uuid}'
event_preview = pymisp._check_response(pymisp._prepare_request('GET', url))
check_response(event_preview)
assert event_preview["Event"]["uuid"] == event.uuid

# Test pull
url = f'servers/pull/{remote_server["id"]}/disable_background_processing:1'
pull_response = pymisp._check_response(pymisp._prepare_request('POST', url))
check_response(pull_response)
assert "Pull completed. 0 events pulled, 0 events could not be pulled, 0 proposals pulled, 0 sightings pulled, 0 clusters pulled, 0 analyst data pulled, 0 collections pulled." == pull_response["message"], pull_response["message"]

# Test pull background. Raw POST rather than pymisp.server_pull(): the CI venv
# installs the PyMISP release pinned in requirements.txt, and no release yet
# sends POST to the (now POST-only) pull, push and cache actions.
check_response(pymisp._check_response(pymisp._prepare_request('POST', f'servers/pull/{remote_server["id"]}')))

# Test push
url = f'servers/push/{remote_server["id"]}/full/disable_background_processing:1'
push_response = pymisp._check_response(pymisp._prepare_request('POST', url))
check_response(push_response)
assert "Push complete. 0 events pushed, 0 events could not be pushed." == push_response["message"], push_response["message"]

# Test push background, raw POST for the same reason as the pull above.
check_response(pymisp._check_response(pymisp._prepare_request('POST', f'servers/push/{remote_server["id"]}')))

# Test caching
url = f'servers/cache/{remote_server["id"]}/disable_background_processing:1'
cache_response = pymisp._check_response(pymisp._prepare_request('POST', url))
check_response(cache_response)
assert "Caching the servers has successfully completed." == cache_response["message"], cache_response["message"]

# Test fetching available sync filtering rules
url = f'servers/queryAvailableSyncFilteringRules/{remote_server["id"]}'
rules_response = pymisp._check_response(pymisp._prepare_request('GET', url))
check_response(rules_response)

# Delete server, graphs and test event
check_response(pymisp.delete_server(remote_server))
for graph_id in (graph["id"], pushed_graph["id"], batch_graph["id"]):
    url = f'analyst_data/delete/Graph/{graph_id}/0'
    check_response(pymisp._check_response(pymisp._prepare_request('POST', url)))
check_response(pymisp.delete_event(event))
check_response(pymisp.delete_event_blocklist(event))
check_response(pymisp.delete_galaxy_cluster(galaxy_cluster))
