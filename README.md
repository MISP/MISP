MISP - Threat Intelligence Sharing Platform
-------------------------------------------
<img align="right" alt="MISP logo" src="./INSTALL/logos/misp-logo.png"/> 

MISP is an open source software solution for collecting, storing, distributing and sharing cyber security indicators and threats about cyber security incidents analysis and malware analysis. MISP is designed by and for incident analysts, security and ICT professionals or malware reversers to support their day-to-day operations to share structured information efficiently.

The objective of MISP is to foster the sharing of structured information within the security community and abroad. MISP provides functionalities to support the exchange of information but also the consumption of said information by Network Intrusion Detection Systems (NIDS), LIDS but also log analysis tools, SIEMs.

  &nbsp;&nbsp;&#x25CF;&nbsp;&nbsp;<a href="#core-functions">Core functions</a>
  &nbsp;&nbsp;&#x25CF;&nbsp;&nbsp;<a href="#website--support">Website / Support</a>
  &nbsp;&nbsp;&#x25CF;&nbsp;&nbsp;<a href="#installation">Installation</a>
  &nbsp;&nbsp;&#x25CF;&nbsp;&nbsp;<a href="#documentation">Documentation</a>
  &nbsp;&nbsp;&#x25CF;&nbsp;&nbsp;<a href="#contributing">Contributing</a><br>
  &nbsp;&nbsp;&#x25CF;&nbsp;&nbsp;<a href="#license">License</a>

<table>
<tr>
  <td>Latest Release</td>
  <td><a href="https://badge.fury.io/gh/MISP%2FMISP"><img src="https://badge.fury.io/gh/MISP%2FMISP.svg" alt="GitHub version" height="25"></a></td>
</tr><tr>
  <td>CI</td>
  <td><a href="https://github.com/MISP/MISP/actions?query=workflow%3Amisp"><img src="https://img.shields.io/github/actions/workflow/status/MISP/MISP/main.yml?label=test" height="25" /></a></td>
</tr>
<tr>
  <td>Gitter</td>
  <td><a href="https://gitter.im/MISP/MISP?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge"><img src="https://badges.gitter.im/MISP/MISP.svg" height="25" /></a></td>
</tr>
<tr>
  <td>Mastodon</td>
  <td><a href="https://misp-community.org/@misp"><img src="https://img.shields.io/badge/follow-@misp-purple" height="25" /></a></td>
</tr><tr>
<tr>
  <td>Twitter</td>
  <td><a href="https://twitter.com/MISPProject"><img src="https://img.shields.io/badge/follow-@MISPProject-blue" height="25" /></a></td>
</tr><tr>
  <td>Localization</td>
  <td><a href="https://crowdin.com/project/misp"><img src="https://badges.crowdin.net/misp/localized.svg" height="25" /></a></td>
</tr>
<tr>
   <td>Contributors</td>
  <td><img src="https://img.shields.io/github/contributors/MISP/MISP.svg" height="25" /></td>
  </tr><tr>
     <td>License</td>
  <td><img src="https://img.shields.io/github/license/MISP/MISP.svg" height="25" /></td>
</tr>
</table>

[![CLA FREE initiative](https://raw.githubusercontent.com/ossbase-org/ossbase.org/main/logos/cla-free-small.png)](https://ossbase.org/initiatives/cla-free/)

Core functions
------------------
- An **efficient IOC and indicators** database, allowing to store technical and non-technical information about malware samples, incidents, attackers and intelligence.
- Automatic **correlation** finding relationships between attributes and indicators from malware, attack campaigns or analysis. The correlation engine includes correlation between attributes and more advanced correlations like Fuzzy hashing correlation (e.g. ssdeep) or CIDR block matching. Correlation can also be enabled or event disabled per attribute.
- A **flexible data model** where complex [objects](https://www.misp-project.org/objects.html) can be expressed and **linked together to express threat intelligence, incidents or connected elements**.
- Built-in **sharing functionality** to ease data sharing using different model of distributions. MISP can automatically synchronize events and attributes among different MISP instances. Advanced filtering functionalities can be used to meet each organization's sharing policy including a **flexible sharing group** capacity and an attribute level distribution mechanisms.
- An **intuitive user-interface** for end-users to create, update and collaborate on events and attributes/indicators. A **graphical interface** to navigate seamlessly between events and their correlations. An **event graph** functionality to create and view relationships between objects and attributes. Advanced filtering functionalities and [warning lists](https://github.com/MISP/misp-warninglists) to help the analysts to contribute events and attributes and limit the risk of false-positives.
- **storing data** in a structured format (allowing automated use of the database for various purposes) with an extensive support of cyber security indicators along fraud indicators as in the financial sector.
- **export**: generating IDS, OpenIOC, plain text, CSV, MISP XML or JSON output to integrate with other systems (network IDS, host IDS, custom tools), Cache format (used for forensic tools), STIX (XML and JSON) 1 and 2, NIDS export (Suricata, Snort and Bro/Zeek) or RPZ zone. Many other formats can be easily added via the [misp-modules](https://github.com/MISP/misp-modules).
- **import**: bulk-import, batch-import, import from OpenIOC, GFI sandbox, ThreatConnect CSV, MISP standard format or STIX 1.1/2.0. Many other formats easily added via the [misp-modules](https://github.com/MISP/misp-modules).
- Flexible **free text import** tool to ease the integration of unstructured reports into MISP.
- A user-friendly system to **collaborate** on events and attributes allowing MISP users to propose changes or updates to attributes/indicators.
- **data-sharing**: automatically exchange and synchronize with other parties and trust-groups using MISP.
- **delegating of sharing**: allows for a simple, pseudo-anonymous mechanism to delegate publication of event/indicators to another organization.
- Flexible **API** to integrate MISP with your own solutions. MISP is bundled with [PyMISP](https://github.com/MISP/PyMISP) which is a flexible Python Library to fetch, add or update events attributes, handle malware samples or search for attributes. An exhaustive restSearch API to easily search for indicators in MISP and exports those in all the format supported by MISP.
- **Adjustable taxonomy** to classify and tag events following your own classification schemes or [existing classification](https://github.com/MISP/misp-taxonomies). The taxonomy can be local to your MISP but also shareable among MISP instances.
- **Intelligence vocabularies** called MISP galaxy and bundled with existing [threat actors, malware, RAT, ransomware or MITRE ATT&CK](https://www.misp-project.org/galaxy.html) which can be easily linked with events and attributes in MISP.
- **Expansion modules in Python** to expand MISP with your own services or activate already available [misp-modules](https://github.com/MISP/misp-modules).
- **Sighting support** to get observations from organizations concerning shared indicators and attributes. Sighting [can be contributed](https://www.circl.lu/doc/misp/automation/index.html#sightings-api) via MISP user-interface, API as MISP document or STIX sighting documents.
- **STIX support**: import and export data in the STIX version 1 and version 2 format.
- **Integrated encryption and signing of the notifications** via GnuPG and/or S/MIME depending on the user's preferences.
- **Real-time** publish-subscribe channel within MISP to automatically get all changes (e.g. new events, indicators, sightings or tagging) in ZMQ (e.g. [misp-dashboard](https://github.com/MISP/misp-dashboard)) or Kafka publishing.

Exchanging info results in *faster detection* of targeted attacks and improves the detection ratio while reducing the false positives. We also avoid reversing similar malware as we know very fast that other teams or organizations have already analyzed a specific malware.

![MISP 2.5 overview](https://raw.githubusercontent.com/MISP/MISP/2.5/INSTALL/screenshots/misp-panorama.png)

A sample event encoded in MISP:

![MISP event view](./INSTALL/screenshots/event-view.png?raw=true "MISP")

Website / Support
------------------

Checkout the [website](https://www.misp-project.org) for more information about MISP software, standards, tools and communities.

Information, news and updates are also regularly posted on the MISP project [Mastodon account](https://misp-community.org/@misp), [twitter account](https://twitter.com/MISPProject) and [news page](https://www.misp-project.org/news/).

Installation
-------------
For test- og production installations we recommend you check out the possible options on [misp-project.org/download](https://www.misp-project.org/download/).

Documentation
-------------

[MISP user-guide (MISP-book)](https://github.com/MISP/misp-book) is available [online](https://www.circl.lu/doc/misp/) or as [PDF](https://www.circl.lu/doc/misp/book.pdf) or as [EPUB](https://www.circl.lu/doc/misp/book.epub) or as [MOBI/Kindle](https://www.circl.lu/doc/misp/book.mobi).

It is also recommended to read the [FAQ](https://github.com/MISP/MISP/wiki/Frequently-Asked-Questions)

Contributing
------------

If you are interested to contribute to the MISP project, review our [contributing page](CONTRIBUTING.md). There are many ways to contribute
and participate to the project.

Please see our [Code of conduct](code_of_conduct.md).

Feel free to fork the code, play with it, make some patches and send us the pull requests via the [issues](https://github.com/MISP/MISP/issues).

Feel free to contact us, create [issues](https://github.com/MISP/MISP/issues), if you have questions, remarks or bug reports.

There is one main branch (2.5) and one stable branch for 2.4:

- [2.5](https://github.com/MISP/MISP/tree/2.5) (current stable version): what we consider as stable with frequent updates as hot-fixes.
- [2.4](https://github.com/MISP/MISP/tree/2.4) (legacy stable version): what we consider as stable with frequent updates as hot-fixes until April 2025.

Along with two development branches:
- [develop](https://github.com/MISP/MISP/tree/develop) (main dev branch): The branch containing all ongoing work, to be merged into 2.5 at each release
- [2.4-develop](https://github.com/MISP/MISP/tree/2.4-develop) (2.4 dev branch): The branch containing ongoing work to be merged into 2.4 on each legacy release along with frequent merges into develop. We consider this the main entry point for new development for 2.x until the 6 months grace period is up.


License
-------

This software is licensed under [GNU Affero General Public License version 3](http://www.gnu.org/licenses/agpl-3.0.html)

* Copyright (C) 2012-2024 Christophe Vandeplas
* Copyright (C) 2012 Belgian Defence
* Copyright (C) 2012 NATO / NCIRC
* Copyright (C) 2013-2024 Andras Iklody
* Copyright (C) 2015-2024 CIRCL - Computer Incident Response Center Luxembourg
* Copyright (C) 2016 Andreas Ziegler
* Copyright (C) 2018-2024 Sami Mokaddem
* Copyright (C) 2018-2024 Christian Studer
* Copyright (C) 2015-2024 Alexandre Dulaunoy
* Copyright (C) 2018-2022 Steve Clement
* Copyright (C) 2020-2024 Jakub Onderka

For more information, [the list of authors and contributors](AUTHORS) is available.
