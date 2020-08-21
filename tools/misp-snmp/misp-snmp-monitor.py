#!/usr/bin/python3
import requests
import json
import sys

misp_key = ""	# MISP API key
misp_url = ""	# MISP URL
misp_cachefile = "/home/misp/misp-snmp/misp-snmp.cache"	# Cache file to store statistics data
# Cache file needs to be writable by the user of your SNMP daemon user
# Add a crontab to update the cache with
#	*/30 * * * * 	misp	/home/misp/misp-snmp/misp-monitor.py update

# Add to SNMP configuration
#	extend  misp-workers    /home/misp/misp-snmp/misp-snmp-monitor.py workers
#	extend  misp-jobs       /home/misp/misp-snmp/misp-snmp-monitor.py jobs
#	extend  misp-stats      /home/misp/misp-snmp/misp-snmp-monitor.py stats
#	extend  misp-users      /home/misp/misp-snmp/misp-snmp-monitor.py users

misp_fail_data = -1
misp_verifycert = False
misp_useragent = "MISP SNMP"

if not misp_verifycert:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

headers = {'Authorization': '{misp_key}'.format(misp_key=misp_key), 'Accept': 'application/json', 'content-type': 'application/json', 'User-Agent': '{misp_useragent}'.format(misp_useragent=misp_useragent)}


def get_worker_status():
    workers_ok = 0
    workers_dead = 0
    try:
        res = requests.get("{misp_url}/servers/getWorkers".format(misp_url=misp_url), headers=headers, verify=misp_verifycert).json()
        for el in res:
            worker = res.get(el)
            if type(worker) is dict:
                if 'ok' in worker:
                    if worker.get('ok') is True:
                        workers_ok += len(worker.get('workers'))
                    else:
                        workers_dead += 1
    except AttributeError:
        workers_ok = misp_fail_data
        workers_dead = misp_fail_data

    print("{}\n{}".format(workers_ok, workers_dead))


def get_job_count():
    res = requests.get("{misp_url}/servers/getWorkers".format(misp_url=misp_url), headers=headers, verify=misp_verifycert).json()
    jobs = 0
    try:
        for el in res:
            worker = res.get(el)
            if type(worker) is dict:
                if 'jobCount' in worker:
                    jobs = int(worker.get('jobCount'))
    except AttributeError:
        jobs = misp_fail_data

    print("{}".format(jobs))


def update_cache():
    res = requests.get("{misp_url}/users/statistics.json".format(misp_url=misp_url), headers=headers, verify=misp_verifycert).json()
    events = 0
    attributes = 0
    users = 0
    orgs = 0
    try:
        stats = res.get('stats')
        events = stats.get('event_count_month')
        attributes = stats.get('attribute_count_month')
        users = stats.get('user_count')
        orgs = stats.get('org_count')
    except AttributeError:
        events = misp_fail_data
        attributes = misp_fail_data
        users = misp_fail_data
        orgs = misp_fail_data

    cache = {}
    cache['events'] = events
    cache['attributes'] = attributes
    cache['users'] = users
    cache['orgs'] = orgs

    with open(misp_cachefile, 'w') as outfile:
        json.dump(cache, outfile)


def get_data_stats_cached():
    with open(misp_cachefile) as json_file:
        cache = json.load(json_file)

        print("{}\n{}".format(cache['events'], cache['attributes']))


def get_data_users_cached():
    with open(misp_cachefile) as json_file:
        cache = json.load(json_file)

        print("{}\n{}".format(cache['users'], cache['orgs']))


if sys.argv[1] == "jobs":
    get_job_count()
elif sys.argv[1] == "workers":
    get_worker_status()
elif sys.argv[1] == "stats":
    get_data_stats_cached()
elif sys.argv[1] == "users":
    get_data_users_cached()
elif sys.argv[1] == "update":
    update_cache()
