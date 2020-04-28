#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
'''
### MISP to Slack ####
ZMQ client to post events, attributes or sighting updates from a MISP instance to a slack channel.

This tool is part of the MISP core project and released under the GNU Affero
General Public License v3.0

Copyright (C) 2020 Christophe Vandeplas

For instructions on creating your BOT, please read: https://api.slack.com/bot-users
Your bot will need the permissions:
- channels:join
- chat:write
- users:write

WARNING WARNING - THIS SCRIPT DOES NOT MAGICALLY RESPECT ACLs
MAKE SURE YOU SET THE RIGHT FILTERS IN THE SETTINGS
'''


import argparse
import sys
import time
import zmq
import json
try:
    import slack
except ImportError:
    exit("Missing slackclient dependency. Please 'pip3 install slackclient'")
try:
    from slackbot_settings import channel_name, slack_token, misp_url, misp_is_public, allowed_distributions, allowed_sharing_groups, max_value_len, include_attr, include_obj
except ImportError:
    exit("Missing slackbot_settings.py. Please create from 'slackbot_settings.py.sample'")


def sanitize_value(s):
    # very dirty cleanup
    s = s.replace('http', 'hxxp')
    s = s.replace('.', '[.]')
    s = s.replace('@', '[AT]')
    s = s.replace('\n', ' ')
    # truncate long strings
    return (s[:max_value_len] + '..') if len(s) > max_value_len else s


def gen_attrs_text(attrs):
    attrs_text_lst = []
    type_value_mapping = {}
    for a in attrs:
        try:
            type_value_mapping[a['type']].add(sanitize_value(a['value']))
        except Exception:
            type_value_mapping[a['type']] = set()
            type_value_mapping[a['type']].add(sanitize_value(a['value']))
    for k, v in type_value_mapping.items():
        attrs_text_lst.append(f"- *{k}*: {','.join(v)}")
    attrs_text = '\n'.join(attrs_text_lst)
    return attrs_text


def publish_event(e):
    cnt_attr = len(e.get('Attribute') or '')
    cnt_obj = len(e.get('Object') or '')
    cnt_tags = len(e.get('Tag') or '')
    url = misp_url + '/events/view/' + e['id']
    zmq_message_short = f"New MISP event '{e['info']}' with {cnt_attr} attributes, {cnt_obj} objects and {cnt_tags} tags."

    image_url = 'https://raw.githubusercontent.com/MISP/MISP/2.4/docs/img/misp.png'
    if misp_is_public:
        image_url = f"{misp_url}/img/orgs/{e['Orgc']['name']}.png"

    zmq_message_blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*A new MISP <{url}|event> has been published:*\n"
                        f"Title: {e['info']}\n"
                        f"Date: {e['date']}\n"
                        f"Threat Level: {e['threat_level_id']}\n"
                        f"Contains {cnt_attr} attributes, {cnt_obj} objects and {cnt_tags} tags\n"
                        f"Full event: <{url}|{url}>"
            },
            "accessory": {
                "type": "image",
                "image_url": image_url,
                "alt_text": "MISP or org logo"
            }
        }
    ]

    if 'Tag' in e:
        tag_block = {
            "type": "actions",
            "elements": [
            ]
        }
        tags = set([t['name'] for t in e['Tag']])
        for a in e['Attribute']:
            if 'Tag' in a:
                for t in a['Tag']:
                    tags.add(t['name'])
        for o in e['Object']:
            for a in o['Attribute']:
                if 'Tag' in a:
                    for t in a['Tag']:
                        tags.add(t['name'])

        tags = sorted(tags)
        for t in tags:
            t = t.replace('misp-galaxy:', '').replace('mitre-', '')
            tag_block['elements'].append({
                "type": "button",
                "text": {
                    "type": "plain_text",
                    "text": t
                },
                "value": "#"
            })
        zmq_message_blocks.append(tag_block)

    # List attributes
    if include_attr:
        zmq_message_blocks.append({"type": "divider"})
        attrs_text = gen_attrs_text(e['Attribute'])
        if attrs_text:
            zmq_message_blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Attributes:*\n{attrs_text}"
                    }
                }
            )
    # List Objects
    if include_obj:
        zmq_message_blocks.append({"type": "divider"})
        for o in e['Object']:
            attrs_text = gen_attrs_text(o['Attribute'])
            if attrs_text:
                # print(json.dumps(o, indent=2))
                zmq_message_blocks.append(
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*{o['name'].capitalize()} object:*\n{attrs_text}"
                        }
                    }
                )

    # Send the message
    client = slack.WebClient(token=slack_token)
    client.users_setPresence(presence='auto')
    channel = client.channels_join(name=channel_name)
    client.chat_postMessage(
        channel=channel['channel']['id'],
        text=zmq_message_short,
        blocks=zmq_message_blocks
    )


parser = argparse.ArgumentParser(description='MISP to Slack bot - ZMQ client to gather events, attributes and sighting updates from a MISP instance')
parser.add_argument("-p", "--port", default="50000", help='set TCP port of the MISP ZMQ (default: 50000)')
parser.add_argument("-r", "--host", default="127.0.0.1", help='set host of the MISP ZMQ (default: 127.0.0.1)')
parser.add_argument("-t", "--sleep", default=0.1, help='sleep time (default: 0.1)', type=int)
args = parser.parse_args()

port = args.port
host = args.host
context = zmq.Context()
socket = context.socket(zmq.SUB)
socket.connect("tcp://%s:%s" % (host, port))
socket.setsockopt(zmq.SUBSCRIBE, b'')

poller = zmq.Poller()
poller.register(socket, zmq.POLLIN)

while True:
    socks = dict(poller.poll(timeout=None))
    if socket in socks and socks[socket] == zmq.POLLIN:
            message = socket.recv()
            topic, s, m = message.decode('utf-8').partition(" ")

            try:
                m_json = json.loads(m)
            except Exception:
                sys.stderr.write(f'Ignoring non-json message: {m}')
                time.sleep(args.sleep)
                continue

            if 'status' in m_json:
                pass
            elif 'Event' in m_json:
                # print(m_json)
                e = m_json['Event']
                if '*' in allowed_distributions or \
                   (e['distribution'] in allowed_distributions and (
                        e['distribution'] != '5' or (
                            '*' in allowed_sharing_groups or e['sharing_group_id'] in allowed_sharing_groups)
                   )):
                    print(f"Publishing event {e['id']} on slack")
                    publish_event(e)
                else:
                    print(f"Ignoring event {e['id']} as it has a filtered distribution.")
            else:
                print(f'Non supported message: {m}')
            time.sleep(args.sleep)
