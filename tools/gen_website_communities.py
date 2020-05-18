#!/usr/bin/env python3
'''
Takes the MISP communities metadata [1] and generates the website page [2]
[1] https://github.com/MISP/MISP/blob/2.4/app/files/community-metadata/defaults.json
[2] https://www.misp-project.org/communities/
'''

import json

code_communities_filename = '../app/files/community-metadata/defaults.json'
website_communities_filename = '../../misp-website/_pages/communities.md'


communities_header = '''
---
layout: page
title: MISP Communities and MISP Feeds
permalink: /communities/
toc: true
---

## MISP Communities

MISP is an open source software and it is also a large community of MISP users creating, maintaining and operating communities of users or organizations sharing information about threats or cyber security indicators worldwide. The MISP project doesn't maintain an exhaustive list of all communities relying on MISP especially that some communities use MISP internally or privately.

# Known Existing and Public MISP Communities

Each community might have specific rules to join them. Below is a brief overview of existing communities, feel free to contact the respective communities that fit your organization. Some of existing public communities might be interconnected and some might be in an island mode. By running MISP, these communities usually allow their members to connect using the MISP API, MISP user-interface or even to synchronize your MISP instance with their communities. If you want to add your MISP community to the list, don't hesitate to [contact us](mailto:info@misp-project.org).
The <i class="icon far fa-check-circle" style="color:green;"></i> sign indicates the community is vetted by the MISP Project.

'''

communities_footer = '''
### Adding your community to the list

You can add your community to the list by doing a Pull Request on the [Community Metadata json file](https://github.com/MISP/MISP/blob/2.4/app/files/community-metadata/defaults.json). Alternatively [contact us](mailto:info@misp-project.org?subject=new_community) by email and specify `name`, `uuid`, `rg_uuid`, `org_name`, `description`, `url`, `sector`, `nationality`, `type`, `email`, `logo`, `pgp_key`, `misp_project_vetted`, `scope_of_data_to_be_shared`.


## MISP Feed Communities

MISP integrates a functionality called feed that allows to fetch directly MISP events from a server without prior agreement. Two OSINT feeds are included by default in MISP and can be enabled in any new installation. Providers and partners can provide easily their feeds by using the simple [PyMISP feed-generator](https://github.com/MISP/PyMISP/tree/master/examples/feed-generator). For more information, an article about "[Using open source intelligence feeds, OSINT, with MISP](https://www.vanimpe.eu/2016/03/23/using-open-source-intelligence-osint-with-misp/)".

### CIRCL OSINT Feed

[CIRCL](https://www.circl.lu/) provides a MISP OSINT feed from various sources including their own analysis.

MISP URL location is [https://www.circl.lu/doc/misp/feed-osint](https://www.circl.lu/doc/misp/feed-osint).

### Botvrij.eu OSINT feed

[Botvrij.eu](http://www.botvrij.eu/) provides a MISP OSINT feed out of public report.

MISP URL location is [http://www.botvrij.eu/data/feed-osint](http://www.botvrij.eu/data/feed-osint).
'''


vetted_image = ' <i class="icon far fa-check-circle" style="color:green;"></i>\n'


with open(code_communities_filename, 'r') as f_in:
    entries = json.load(f_in)


with open(website_communities_filename, 'w') as f_out:
    f_out.write(communities_header)
    for entry in entries:
        f_out.write(f'### {entry["name"]}')
        f_out.write(vetted_image if entry.get('misp_project_vetted') else '\n')
        if entry.get('logo'):
            f_out.write(f'![Logo]({entry["logo"]}){{: style="float: right; max-width: 300px; max-height: 150px;"}}\n')
        if entry.get('url'):
            f_out.write(f'- Website: {entry["url"]}\n')
        if entry.get('type'):
            f_out.write(f'- Type: {entry["type"]}\n')
        if entry.get('sector'):
            f_out.write(f'- Sector: {entry["sector"]}\n')
        if entry.get('scope'):
            f_out.write(f'- Scope of data to be shared: {entry["scope_of_data_to_be_shared"]}\n')
        if entry.get('nationality'):
            f_out.write(f'- Nationality: {entry["nationality"]}\n')
        if entry.get('description'):
            f_out.write(f'- Description: {entry["description"]}\n')
        if entry.get('org'):
            f_out.write(f'- Managed by: {entry["org"]}\n')
        if entry.get('email'):
            f_out.write(f'- Contact: {entry["email"]}')
            if entry.get('pgp_key'):
                f_out.write('\n<details><summary>GPG key</summary>\n\n```')
                f_out.write(entry['pgp_key'])
                f_out.write('```\n</details>\n')
            f_out.write('\n')
        f_out.write('\n')
    f_out.write(communities_footer)


print(f"The communities file has been generated. ({website_communities_filename}).\nPlease commit this in the misp-website repository, and publish the generated website.")
