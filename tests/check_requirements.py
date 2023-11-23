#!/usr/bin/env python3

import re

requirements_file = 'requirements.txt'
app_controller = 'app/Controller/AppController.php'

with open(requirements_file) as f:
    req_version = re.findall('pymisp==(.*)', f.read())[0]

with open(app_controller) as f:
    controller_version = re.findall('pyMispVersion = \'(.*)\'', f.read())[0]

if not req_version == controller_version:
    raise Exception(f'PyMISP in {requirements_file} ({req_version}) differs from the one in {app_controller} ({controller_version})')
