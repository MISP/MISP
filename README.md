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
- A **complete and robust threat intelligence sharing platform** that can be deployed on-premise, in the cloud, or as a SaaS solution, suitable for organizations of all sizes. 
- **Threat intelligence, ranging from indicators, through techniques to tactics, can be easily described in MISP**, from machine-readable actionable data to detailed reports in Markdown format.
- A flexible reporting system is integrated into MISP, enabling the description of threat intelligence with cross-references to the machine-readable components, including objects and attributes.
- A **fast and efficient database for atomic data points, indicators to complex objects and selectors**, enabling the storage of both technical and non-technical information related to cybersecurity intelligence as well as broader intelligence contexts.
- Automatic **correlation** engine, revealing relationships between attributes and indicators of malware, attack campaigns, analyses or other described threats. The correlation engine handles the interlinking of matching attributes as well as more advanced correlation patterns such as fuzzy hashing overlaps (e.g. ssdeep) and CIDR block matching. Correlations can also be enabled or event disabled at different levels of granularity.
- A **flexible data model**, where complex [objects](https://www.misp-project.org/objects.html) can be expressed and **linked together to express threat intelligence, incidents or connected elements**.
- Built-in **sharing functionality** to ease information exchange, using different, customisable, models of distribution. MISP can automatically synchronize events and attributes as well as higher level threat intelligence among different MISP instances. Advanced filtering functionalities can be used to meet each organization's sharing policy including a **flexible sharing group** capability and granularity up to the atomic attribute level.
- An **intuitive user-interface** for end-users to create, update and collaborate on events and attributes/indicators, in addition to a **graphical interface** to navigate seamlessly between events and their correlations as well as an **event graph** functionality to create and view relationships between objects and attributes. Advanced filtering functionalities and [warning lists](https://github.com/MISP/misp-warninglists) to help the analysts to contribute events and attributes and limit the risk of false-positives.
- A comprehensive **workflow system** to facilitate automatic, customisable data pipelines in MISP, including data qualification, automated analysis, modification, and publication control.
- **Storing data** in a structured format, enabling automated use of the database for various purposes, with extensive support for cybersecurity indicators, fraud indicators (e.g., in the financial sector), and broader intelligence contexts.
- All intelligence and information stored in MISP is accessible via the UI but also an [extensive ReST API described as OpenAPI](https://www.misp-project.org/openapi/).
- **Export**: Generate outputs in various formats, including various native IDS formats, OpenIOC, plain text, CSV, MISP JSON, STIX (XML and JSON) versions 1 and 2, NIDS exports (Suricata, Snort, and Bro/Zeek), RPZ zones, and cache formats for forensic tools. Additional formats, such as PDF, can be easily added and are available via the [misp-modules](https://github.com/MISP/misp-modules) or customised as built in export modules.
- **Import**: Support for free-text import, URL import, bulk import, batch import, and importing from formats a long list of formats, including MISP's own standard format, STIX 1.x/2.0, CSV, or various proprietary formats. Additional formats can be easily added via the [misp-modules](https://github.com/MISP/misp-modules) system.
- Flexible **free-text import** tool to simplify the integration of unstructured reports into MISP, with automatic detection and conversion of external reports via provided URLs and text reports with an automatic conversion into MISP reports, objects, and attributes.
- A user-friendly system to **collaborate** on events and attributes allowing MISP users to propose changes or updates to attributes/indicators or provide own perspectives or counter-analyses to shared information.
- An **extensive data analyst feature** allowing analysts to add opinions, relationships, or comments to any intelligence in MISP, which can be shared using MISP's sharing mechanisms.
- **Data sharing**: Automatically exchange and synchronize information in real-time with other parties and trust groups using MISP, with support for granular sharing levels and custom sharing groups.
- **delegating of sharing**: allows for a simple, pseudo-anonymous mechanism to delegate the publication of MISP data to communities.
- Flexible **API** to integrate MISP with your own solutions. MISP is bundled with [PyMISP](https://github.com/MISP/PyMISP) which is a flexible Python Library to fetch, add or update events attributes, handle malware samples or search for attributes. An exhaustive restSearch API to easily search for indicators in MISP and exports those in all the format supported by MISP.
- Built in tooling to build, test and analyse complex queries directly in the MISP GUI using a highly context aware, templated API client.
- **Adjustable taxonomy** to classify and tag events following your own classification schemes or [existing classification](https://github.com/MISP/misp-taxonomies). The taxonomy can be local to your MISP but also shareable among MISP instances.
- **Intelligence vocabularies** called MISP galaxy and bundled with existing [threat actors, malware, RAT, ransomware or MITRE ATT&CK](https://www.misp-project.org/galaxy.html) which can be easily linked with events, reports and attributes in MISP.
- **Expansion modules in Python** to expand MISP with your own services or activate already available [misp-modules](https://github.com/MISP/misp-modules).
- **Sighting support** to get observations from organizations concerning shared indicators and attributes. Sighting [can be contributed](https://www.circl.lu/doc/misp/automation/index.html#sightings-api) via the MISP user-interface and the API as MISP data or STIX sighting documents.
- **MISP Standard Format** support is integrated into MISP and used by a long list of tools and organisations worldwide. The [MISP standard format](https://www.misp-standard.org/) is stable and backward compatible with older datasets.
- **STIX support**: Import and export data in STIX versions 1 and 2 formats, leveraging the powerful [misp-stix library](https://github.com/misp/misp-stix).
- **Integrated encryption and signing of the notifications** via GnuPG and/or S/MIME depending on the user's preferences.
- **Dashboard feature**: Integrated into MISP, allowing users and organizations to create and share custom composited dashboard configurations as well as build bespoke monitoring solutions directly in a drag and drop interface.
- **Real-time** publish-subscribe channel within MISP to automatically get all changes (e.g. new events, indicators, sightings or tagging) in ZMQ (e.g. [SkillAegis](https://github.com/MISP/SkillAegis)) or Kafka publishing.
- **Flexible logging** subsystems to help with the auditing of the system as well as the user-base's actions on the system, with various output formats supported as well as a wide range of transport mechanisms for centralised logging needs.
- **Customisable RBAC**, allowing configurations of MISP to be run both as a permissive in-house tool as well as tightly regulated community instances.
- **Information signing and validation** for more diverse and sensitive information sharing communities.
- **Batteries included**: A long list of tooling for backups, integration with identity providers and authentication systems, information leakage prevention safety nets (such as [MISP-Guard](https://github.com/MISP/misp-guard)) as well as system monitoring tools.
- **Open-source commitment**: MISP and its copyright is fully owned by an interlocked license among all contributors, ensuring that no single organisation or company can ever change the license or model of MISP. Users of MISP can rely on the tool never turning into a closed source / proprietary / semi-open multi-tier model tool.

## Main advantages

The main benefit of using MISP is its ability to serve as a **comprehensive and robust platform for threat intelligence sharing and collaboration**, enabling organizations of all sizes to:

- **Centralize and manage intelligence:** Store, structure, and analyze both technical and non-technical threat intelligence efficiently.
- **Enhance collaboration:** Share information securely and flexibly with trust groups, leveraging granular sharing mechanisms and real-time synchronization.
- **Improve detection and response:** Correlate indicators, enrich intelligence, and automate workflows to enhance detection, analysis, and response capabilities.
- **Foster integration and interoperability:** Seamlessly integrate with existing tools and systems using APIs, modular extensions, and support for standard formats like STIX and MISP's own standardized format.
- **Enable actionable insights:** Provide actionable, machine-readable intelligence while also supporting detailed reporting for strategic and operational decision-making.

MISP empowers cybersecurity teams with a scalable, flexible, and user-friendly platform to streamline their threat intelligence processes and improve their collective defense capabilities.

![MISP 2.5 overview](https://raw.githubusercontent.com/MISP/MISP/2.5/INSTALL/screenshots/misp-panorama.png)

A sample event encoded in MISP:

![MISP event view](./INSTALL/screenshots/event-view.png?raw=true "MISP")

Website / Support
------------------

Checkout the [website](https://www.misp-project.org) for more information about MISP software, standards, tools and communities.

Information, news and updates are also regularly posted on the MISP project [Mastodon account](https://misp-community.org/@misp), [twitter account](https://twitter.com/MISPProject) and [news page](https://www.misp-project.org/news/).

Installation
-------------
For test- or production-installations we recommend you check out the possible options on [misp-project.org/download](https://www.misp-project.org/download/).

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
