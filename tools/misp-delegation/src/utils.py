#!/usr/bin/env python3


import copy
import json
from typing import Optional, List, Union

import requests


class MISPInstance():

    headers = {
        'Accept': 'application/json',
        'content-type': 'application/json',
        'User-Agent': 'misp-delegation'
    }

    def __init__(self, config: dict) -> None:
        self.base_url = config['url'][:-1] if config['url'][-1] == '/' else config['url']
        self.api_key = config['api_key']
        self.verify_ssl = config.get('verify_ssl', True)

        if not self.verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


    def GET(self, url: str) -> Union[List, dict]:
        url = self.genURL(url)
        r = requests.get(url, headers=self.getHeaders(), verify=(self.verify_ssl))
        r.raise_for_status()
        return r.json()


    def POST(self, url: str, payload: Optional[Union[List, dict]] = {}) -> Union[List, dict]:
        url = self.genURL(url)
        r = requests.post(url, data=json.dumps(payload), headers=self.getHeaders(), verify=(self.verify_ssl))
        r.raise_for_status()
        return r.json()


    def genURL(self, url: str) -> str:
        return f'{self.base_url}{url}'
    
    def getHeaders(self) -> dict:
        headers = copy.copy(self.headers)
        headers['Authorization'] = self.api_key
        return headers