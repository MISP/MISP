#!/usr/bin/python3

import argparse
from collections import defaultdict
from datetime import datetime
import json
import logging
import logging.config
from pathlib import Path
import sys
import time
from typing import List, Optional, Union
import yaml

from utils import MISPInstance


logging_file_path = Path(__file__).parent / 'logging.yml'
with open(logging_file_path,  'r') as f:
    yaml_config = yaml.safe_load(f.read())
    try:
        yaml_config['handlers']['file']['filename'] = Path(__file__).parent / 'logs' / yaml_config['handlers']['file']['filename']
    except KeyError:
        pass
    logging.config.dictConfig(yaml_config)

logger = logging.getLogger('misp-delegation')
last_timestamp_path = Path(__file__).parent / 'last_sync_timestamp.txt'
unpublish_event_on_remote = False
sourceEventUUIDToID = {}

def main():
    global unpublish_event_on_remote
    parser = argparse.ArgumentParser(Path(__file__).name)
    parser.add_argument('-c', '--config', default='config.json', help='The JSON config file to use')
    options = parser.parse_args()

    config = {}
    config_file_path = Path(__file__).parent / options.config
    with open(config_file_path, 'r') as f:
        config = json.load(f)

    source_instance = MISPInstance(config['misp_instance']['source'])
    destination_instance = MISPInstance(config['misp_instance']['destination'])
    filters = config['filters']
    delegation_config = config['delegation']
    unpublish_event_on_remote = config['unpublish_event_on_remote']
    incremental_sync = config['incremental_sync']
    tag_actions = config['tag_actions']

    # Check connectivity
    if test_connectivity(source_instance):
        logger.debug(f'Connection to MISP source<{source_instance.base_url}> successfull')
    else:
        logger.error('Could not connect to source MISP instance')
        return 1
    if test_connectivity(destination_instance):
        logger.debug(f'Connection to MISP remote<{destination_instance.base_url}> successfull')
    else:
        logger.error('Could not connect to remote MISP instance')
        return 1


    # Get target sharing group
    if delegation_config['desired_distribution'] == 4:
        logger.debug(f'Fetching requested sharing group...')
        sharinggroup_uuid = delegation_config['sharing_group_uuid']
        try:
            sharinggroup_id = get_sharing_group_id(destination_instance, sharinggroup_uuid)
            delegation_config['sharinggroup_id'] = sharinggroup_id
        except Exception as err:
            logger.debug(f'Unexpected error "{err}", type={type(err)}')
            logger.error(f'Could not fetch sharing group with UUID {sharinggroup_uuid} on remote')
            return 1

    # Collect events from source
    logger.debug('Collecting events from source...')
    try:
        events_on_source = collect_events_from_source(source_instance, filters, incremental_sync)
    except Exception as err:
        logger.debug(f'Unexpected error "{err}", type={type(err)}')
        events_on_source = None

    if events_on_source is None:
        logger.error(f'Could not collect events from source<{source_instance.base_url}>')
        return 1
    logger.debug(f'Collected {len(events_on_source)} events from source')
    for event in events_on_source:
        sourceEventUUIDToID[event['uuid']] = event['id']

    # Collect events from remote
    logger.debug('Collecting events from remote...')
    try:
        events_on_remote = collect_existing_events_on_remote(destination_instance, incremental_sync)
    except Exception as err:
        logger.debug(f'Unexpected error "{err}", type={type(err)}')
        events_on_remote = None

    if events_on_remote is None:
        logger.error(f'Could not collect events from remote<{destination_instance.base_url}>')
        return 1
    logger.debug(f'Collected {len(events_on_remote)} events from remote')

    # Peform event diff for source and remote
    logger.debug('Finding events missing on the remote by diffing with the source...')
    events_to_push = get_outdated_or_non_existing_events(events_on_source, events_on_remote)
    if not events_to_push:
        logger.info(f'All {len(events_on_source)} events exist and are up-to-date on the remote<{destination_instance.base_url}>')
        if incremental_sync:
            save_current_sync_timestamp()
        return 0
    logger.debug(f'Found {len(events_to_push)} missing/outdated on the remote')

    # Push events
    logger.debug(f'Pushing the {len(events_to_push)} missing events on the remote...')
    pushed_event_uuids = push_eligible_events_to_remote(source_instance, destination_instance, events_to_push)
    rejected_push_count = len(events_to_push) - len(pushed_event_uuids)
    if rejected_push_count > 0:
        logger.warning(f'Could not push all events. {rejected_push_count} events were rejected by the remote<{destination_instance.base_url}>')
    logger.debug(f'Successfully pushed {len(pushed_event_uuids)} events')

    # Delegate events
    logger.debug('Requesting delegation on the remote...')
    delegated_event_uuids = request_delegation_for_pushed_events(destination_instance, pushed_event_uuids, delegation_config)
    rejected_delegation_count = len(pushed_event_uuids) - len(delegated_event_uuids)
    if rejected_delegation_count > 0:
        logger.warning(f'Could not delegate all events. {rejected_delegation_count} events were not delegated')
    logger.debug(f'Successfully delegated {len(delegated_event_uuids)} events')

    # Attach tags on delegated events
    if tag_actions['attach'] or tag_actions['detach']:
        all_tag_ids = get_tag_ids_from_name(source_instance, tag_actions)
        if all_tag_ids:
            if all_tag_ids['attach']:
                attach_tags_on_events(source_instance, all_tag_ids['attach'], delegated_event_uuids)
            if all_tag_ids['detach']:
                detach_tags_from_events(source_instance, all_tag_ids['detach'], delegated_event_uuids)

    if incremental_sync:
        save_current_sync_timestamp()

    logger.info(f'Pushed {len(pushed_event_uuids)}/{len(events_to_push)} events and delegated {len(delegated_event_uuids)}/{len(pushed_event_uuids)}')
    return 0


def test_connectivity(instance: MISPInstance) -> bool:
    response = instance.GET('/servers/getVersion')
    return 'version' in response


def get_sharing_group_id(destination_instance: MISPInstance, sharinggroup_uuid: str) -> int:
    sharinggroup = destination_instance.GET(f'/sharing_groups/view/{sharinggroup_uuid}.json')
    return sharinggroup['SharingGroup']['id'] # type: ignore


def save_current_sync_timestamp() -> None:
    last_timestamp = int(time.time())
    with open(last_timestamp_path, 'w') as f:
        f.write(str(last_timestamp))


def get_last_sync_timestamp() -> Union[int, None]:
    try:
        with open(last_timestamp_path, 'r') as f:
            last_timestamp = int(f.readline())
    except Exception:
        return None
    return last_timestamp


def update_event_for_push(event: dict) -> dict:
    logger.debug('Downgrading distribution levels and removing local tags')

    if unpublish_event_on_remote:
        event['published'] = False

    for t, tag in enumerate(event['Tag'][:]):
        if tag['local']:
            event['Tag'].pop(t)

    # Downgrade distribution for Attribute
    for i, attribute in enumerate(event['Attribute'][:]):
        if int(attribute['distribution']) < 2:
            event['Attribute'].pop(i)
        elif attribute['distribution'] == 2:
            event['Attribute'][i]['distribution'] = 1

        for t, tag in enumerate(attribute['Tag']):
            if tag['local']:
                event['Attribute'][i]['Tag'].pop(t)

    # Downgrade distribution for Objects and their Attributes
    for i, object in enumerate(event['Object'][:]):
        if int(object['distribution']) < 2:
            event['Object'].pop(i)
        elif object['distribution'] == 2:
            event['Object'][i]['distribution'] = 1
        for j, attribute in enumerate(object['Attribute']):
            if int(attribute['distribution']) < 2:
                event['Object'][i]['Attribute'].pop(j)
            elif attribute['distribution'] == 2:
                event['Object'][i]['Attribute'][j]['distribution'] = 1

            for t, tag in enumerate(attribute['Tag']):
                if tag['local']:
                    event['Object'][i]['Attribute'][j]['Tag'].pop(t)

    # Downgrade distribution for EventReport
    for i, report in enumerate(event['EventReport'][:]):
        if int(report['EventReport']) < 2:
            event['EventReport'].pop(i)
        elif report['distribution'] == 2:
            event['EventReport'][i]['distribution'] = 1

    return event


def collect_events_from_source(source_instance: MISPInstance, filters: dict, incremental_sync: bool = False) -> List[dict]:
    sync_filters = {
        'minimal': True,
        'published': True,
    }
    last_timestamp = get_last_sync_timestamp()
    if incremental_sync and last_timestamp is not None:
        logger.debug('Using timestamp from last synchronisation %s (%s)', last_timestamp, datetime.fromtimestamp(last_timestamp))
        sync_filters['timestamp'] = last_timestamp # type: ignore
    sync_filters.update(filters)
    events = source_instance.POST('/events/index', payload=sync_filters)
    return events # type: ignore


def collect_existing_events_on_remote(destination_instance: MISPInstance, incremental_sync: bool = False) -> Optional[List[dict]]:
    sync_filters = {
        'minimal': True,
        'published': True,
    }
    last_timestamp = get_last_sync_timestamp()
    if incremental_sync and last_timestamp is not None:
        logger.debug('Using timestamp from last synchronisation %s (%s)', last_timestamp, datetime.fromtimestamp(last_timestamp))
        sync_filters['timestamp'] = last_timestamp # type: ignore
    events = destination_instance.POST('/events/index', payload=sync_filters)
    return events # type: ignore


def get_outdated_or_non_existing_events(events_on_source: List[dict], events_on_remote: List[dict]) -> List[dict]:
    non_existing_e = []
    lookup_dest_events = {event['uuid']: event for event in events_on_remote}
    for src_e in events_on_source:
        if src_e['uuid'] not in lookup_dest_events or src_e['timestamp'] > lookup_dest_events[src_e['uuid']]['timestamp']:
            non_existing_e.append(src_e)
    return non_existing_e


def push_eligible_events_to_remote(source_instance: MISPInstance, destination_instance: MISPInstance, eligible_events: List[dict]) -> List[str]:
    pushed_uuids = []
    for eligible_event in eligible_events:
        uuid = eligible_event['uuid']
        try:
            event_on_src = source_instance.GET(f'/events/view/{uuid}.json')
        except Exception as err:
            logger.debug(f'Unexpected error "{err}", type={type(err)}')
            logger.warning(f'Event {uuid} could not be retrieved from source<{source_instance.base_url}>. error "{err}"')
            continue

        event_on_src['Event']['distribution'] = 0  # type: ignore # Downgrade distribution level to `org_only` to prevent data leak and allow delegation
        event_on_src['Event'] = update_event_for_push(event_on_src['Event']) # type: ignore
        try:
            pushed_event = destination_instance.POST('/events/add', payload=event_on_src) # type: ignore
        except Exception as err:
            logger.debug(f'Unexpected error "{err}", type={type(err)}')
            logger.warning(f'Event {uuid} was not pushed. error "{err}"')
            continue
        pushed_uuids.append(pushed_event['Event']['uuid']) # type: ignore
    return pushed_uuids


def request_delegation_for_pushed_events(destination_instance: MISPInstance, pushed_events_uuids: List[str], delegation_config: dict) -> List[str]:
    delegated_events = []
    payload = {
        'EventDelegation': {
            'distribution': delegation_config['desired_distribution'],
            'sharing_group_id': 0,
            'org_id': delegation_config['target_org_uuid'],
            'message': delegation_config['message'],
        }
    }
    if delegation_config['desired_distribution'] == 4:
        payload['EventDelegation']['sharing_group_id'] = delegation_config['sharinggroup_id']

    for uuid in pushed_events_uuids:
        try:
            delegated_event = destination_instance.POST(f'/event_delegations/delegateEvent/{uuid}', payload)
        except Exception as err:
            logger.debug(f'Unexpected error "{err}", type={type(err)}')
            logger.warning(f'Event {uuid} could not be delegated. error "{err}"')
            continue
        delegated_events.append(uuid)
    return delegated_events


def get_tag_ids_from_name(source_instance: MISPInstance, tag_actions: dict) -> Union[dict, None]:
    tag_ids = defaultdict(list)
    try:
        all_tags = source_instance.GET(f'/tags/index')['Tag'] # type: ignore
    except Exception as err:
        logger.debug(f'Unexpected error "{err}", type={type(err)}')
        logger.warning(f'Could not fetch tags on source<{source_instance.base_url}>. error "{err}"')
        return None

    for tag in all_tags:
        for action, action_tags in tag_actions.items():
            if tag['name'] in action_tags:
                tag_ids[action].append(tag['id'])
    return tag_ids


def attach_tags_on_events(source_instance: MISPInstance, tag_ids: List[int], event_uuids: List[str]) -> None:
    logger.debug('Attaching local tags on delegated events')
    for event_uuid in event_uuids:
        payload = {
            'tag': json.dumps(tag_ids),
        }
        try:
            source_instance.POST(f'/events/addTag/{sourceEventUUIDToID[event_uuid]}/local:1', payload=payload)
        except Exception as err:
            logger.debug(f'Unexpected error "{err}", type={type(err)}')
            logger.warning(f'Could not attach tags on event {event_uuid}. error "{err}"')


def detach_tags_from_events(source_instance: MISPInstance, tag_ids: List[int], event_uuids: List[str]) -> None:
    logger.debug('Detaching tags on delegated events')
    for event_uuid in event_uuids:
        payload = {}
        for tag_id in tag_ids:
            try:
                source_instance.POST(f'/events/removeTag/{sourceEventUUIDToID[event_uuid]}/{tag_id}', payload=payload)
            except Exception as err:
                logger.debug(f'Unexpected error "{err}", type={type(err)}')
                logger.warning(f'Could not attach tag {tag_id} on event {event_uuid}. error "{err}"')


if __name__ == '__main__':
    sys.exit(main())
