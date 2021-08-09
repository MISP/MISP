import os
from pymisp import PyMISP


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

# Test pull
url = f'servers/pull/{remote_server["id"]}/disable_background_processing:1'
pull_response = pymisp._check_json_response(pymisp._prepare_request('GET', url))
check_response(pull_response)
assert "Pull completed. 0 events pulled, 0 events could not be pulled, 0 proposals pulled, 0 sightings pulled, 0 clusters pulled." == pull_response["message"], pull_response["message"]

# Delete server
check_response(pymisp.delete_server(remote_server))
