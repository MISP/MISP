import os
from pymisp import PyMISP, MISPEvent, MISPGalaxyCluster


def check_response(response):
    if isinstance(response, dict) and "errors" in response:
        raise Exception(response["errors"])


# Load access information for env variables
url = "http://" + os.environ["HOST"]
key = os.environ["AUTH"]

pymisp = PyMISP(url, key)
pymisp.global_pythonify = True

# Create new remote server, that is the same just for test
remote_server = pymisp.add_server({
    "pull": True,
    "pull_galaxy_clusters": True,
    "push_galaxy_clusters": True,
    "push": True,
    "push_sightings": True,
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
remote_user = pymisp._check_json_response(pymisp._prepare_request('GET', url))
check_response(remote_user)
assert remote_user["Sync flag"] == "Yes"
assert remote_user["Role name"] == "admin"
assert remote_user["User"] == "admin@admin.test"

# Create testing event
event = MISPEvent()
event.load_file(os.path.dirname(os.path.realpath(__file__)) + "/event.json")
pymisp.delete_event_blocklist(event)
event = pymisp.add_event(event, metadata=True)
check_response(event)

# Publish that event
check_response(pymisp.publish(event))

# Publish event inline
url = f'events/publish/{event.id}/disable_background_processing:1'
push_event = pymisp._check_json_response(pymisp._prepare_request('POST', url))
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

# Preview index
url = f'servers/previewIndex/{remote_server["id"]}'
index_preview = pymisp._check_json_response(pymisp._prepare_request('GET', url))
check_response(index_preview)

# Preview event
url = f'servers/previewEvent/{remote_server["id"]}/{event.uuid}'
event_preview = pymisp._check_json_response(pymisp._prepare_request('GET', url))
check_response(event_preview)
assert event_preview["Event"]["uuid"] == event.uuid

# Test pull
url = f'servers/pull/{remote_server["id"]}/disable_background_processing:1'
pull_response = pymisp._check_json_response(pymisp._prepare_request('GET', url))
check_response(pull_response)
assert "Pull completed. 0 events pulled, 0 events could not be pulled, 0 proposals pulled, 0 sightings pulled, 0 clusters pulled." == pull_response["message"], pull_response["message"]

# Test pull background
check_response(pymisp.server_pull(remote_server))

# Test push
url = f'servers/push/{remote_server["id"]}/full/disable_background_processing:1'
push_response = pymisp._check_json_response(pymisp._prepare_request('GET', url))
check_response(push_response)
assert "Push complete. 0 events pushed, 0 events could not be pushed." == push_response["message"], push_response["message"]

# Test push background
check_response(pymisp.server_push(remote_server))

# Test caching
url = f'servers/cache/{remote_server["id"]}/disable_background_processing:1'
cache_response = pymisp._check_json_response(pymisp._prepare_request('GET', url))
check_response(cache_response)
assert "Caching the servers has successfully completed." == cache_response["message"], cache_response["message"]

# Test fetching available sync filtering rules
url = f'servers/queryAvailableSyncFilteringRules/{remote_server["id"]}'
rules_response = pymisp._check_json_response(pymisp._prepare_request('GET', url))
check_response(rules_response)

# Delete server and test event
check_response(pymisp.delete_server(remote_server))
check_response(pymisp.delete_event(event))
check_response(pymisp.delete_event_blocklist(event))
check_response(pymisp.delete_galaxy_cluster(galaxy_cluster))
