#!/usr/bin/python3
'''
Title:          MISP_Whitelist.py
Date:           2018-04-13
Author:         Nick Driver (@TheDr1ver)
Description:    While using the built-in whitelisting function works great for pretty much every 
                export method MISP can handle, ensuring the proper To_IDS values are set is important 
                when ingesting indicators directly from the MySQL database (e.g. Splunk DBConnect).
 
                This script checks a designated "whitelist event" for indicators and makes sure 
                to_ids is set to True or False for each indicator across all events in the 
                MISP database.
 
Requirements:   PyMISP
 
Usage:          Set white_id to the unique MISP event ID where a running whitelist of attributes
                will be kept. If an attribute is set as To_IDS=True, then running this script will
                set all instances of this attribute across the database as To_IDS=True. The opposite
                effect occurs for toggling To_IDS to False. For best results, set this script to
                run as a regular cronjob.
'''
 
from pymisp import PyMISP
from pprint import pprint
 
# Try disabling the Unverified HTTPS Warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
 
def get_whitelist_event(misp, white_id):
 
    white_event = misp.get_event(white_id)
    attributes = white_event['Event']['Attribute']
    return attributes
 
if __name__ == "__main__":
 
    # Set event ID where collection of whitelisted attributes is located
    white_id = '12345'
 
    # MISP Login Info - SET THIS OR IT WON'T WORK!
    misp_url = 'https://127.0.0.1'
    misp_key = '<YOUR_API_KEY>'
 
    misp = PyMISP(misp_url, misp_key, False, 'json')
 
    # Get list of attributes from whitelisted event
    attributes = get_whitelist_event(misp, white_id)
 
    # Divide into two lists - To_IDS_T and To_IDS_F
    to_ids_true = []
    to_ids_false = []
    for attribute in attributes:
        if attribute['to_ids']==True:
            to_ids_true.append(attribute['value'])
        else:
            to_ids_false.append(attribute['value'])
 
    # Loop through attribute lists
    # For each attribute in the list, find every instance of it and *if To_IDS has changed* 
    # set To_IDS to T or F
 
    for att in to_ids_true:
        response = misp.search(controller='attributes', values=att, to_ids=False)
        if 'Attribute' in response['response']:
            for ioc in response['response']['Attribute']:
                if ioc['value']==att:
                    if ioc['to_ids']==False:
                        misp.change_toids(ioc['uuid'],True)
                        print('Changing '+att+' ('+ioc['uuid']+') to True')
 
    for att in to_ids_false:
        print(att)
        response = misp.search(controller='attributes', values=att, to_ids=True)
        if 'Attribute' in response['response']:
            for ioc in response['response']['Attribute']:
                if ioc['value']==att:
                    #pprint(ioc)
                    if ioc['to_ids']==True:
                        pprint(ioc)
                        r = misp.change_toids(ioc['uuid'],False)
                        #pprint(r)
                        print('Changing '+att+' ('+ioc['uuid']+') to False')
