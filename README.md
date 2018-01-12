MISP - Malware Information Sharing Platform and Threat Sharing
--------------------------------------------------------------

![logo](./INSTALL/logos/misp-logo.png?raw=true "MISP")

<table>
<tr>
  <td>Latest Release</td>
  <td><a href="https://badge.fury.io/gh/MISP%2FMISP"><img src="https://badge.fury.io/gh/MISP%2FMISP.svg" alt="GitHub version" height="18"></a></td>
</tr>
<tr>
  <td>Travis</td>
  <td><a href="https://travis-ci.org/MISP/MISP"><img src="https://img.shields.io/travis/MISP/MISP/2.4.svg" /></a></td>
</tr>
<tr>
  <td>Gitter</td>
  <td><a href="https://gitter.im/MISP/MISP?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge"><img src="https://badges.gitter.im/MISP/MISP.svg" /></a></td>
</tr>
<tr>
  <td>Twitter</td>
  <td><a href="https://twitter.com/MISPProject"><img src="https://img.shields.io/twitter/follow/MISPProject.svg?style=social&label=Follow" /></a></td>
</tr>
<tr>
  <td>Contributors</td>
  <td><img src="https://img.shields.io/github/contributors/MISP/MISP.svg" /></td>
</tr>
<tr>
  <td>License</td>
  <td><img src="https://img.shields.io/github/license/MISP/MISP.svg" /></td>
</tr>

</table>

MISP, Malware Information Sharing Platform and Threat Sharing, is an open source software solution for collecting, storing, distributing and sharing cyber security indicators and threat about cyber security incidents analysis and malware analysis. MISP is designed by and for incident analysts, security and ICT professionals or malware reverser to support their day-to-day operations to share structured informations efficiently.

The objective of MISP is to foster the sharing of structured information within the security community and abroad. MISP provides functionalities to support the exchange of information but also the consumption of the information by Network Intrusion Detection System (NIDS), LIDS but also log analysis tools, SIEMs.

MISP, Malware Information Sharing Platform and Threat Sharing, core functionalities are:

- An **efficient IOC and indicators** database allowing to store technical and non-technical information about malware samples, incidents, attackers and intelligence.
- Automatic **correlation** finding relationships between attributes and indicators from malware, attacks campaigns or analysis.
- A **flexible data model** where complex [objects](https://www.misp-project.org/objects.html) can be expressed and **linked together to express threat intelligence, incidents or connected elements**.
- Built-in **sharing functionality** to ease data sharing using different model of distributions. MISP can synchronize automatically events and attributes among different MISP. Advanced filtering functionalities can be used to meet each organization sharing policy including a **flexible sharing group** capacity and an attribute level distribution mechanisms.
- An **intuitive user-interface** for end-users to create, update and collaborate on events and attributes/indicators. A **graphical interface** to navigate seamlessly between events and their correlations. Advanced filtering functionalities and [warning list](https://github.com/MISP/misp-warninglists) to help the analysts to contribute events and attributes.
- **storing data** in a structured format (allowing automated use of the database for various purposes) with an extensive support of cyber security indicators along fraud indicators as in the financial sector.
- **export**: generating IDS, OpenIOC, plain text, CSV, MISP XML or JSON output to integrate with other systems (network IDS, host IDS, custom tools), STIX (XML and JSON), NIDS export (Suricata, Snort and Bro) or RPZ zone. Many other formats easily added via the [misp-modules](https://github.com/MISP/misp-modules).
- **import**: bulk-import, batch-import, import from OpenIOC, GFI sandbox, ThreatConnect CSV. Many other formats easily added via the [misp-modules](https://github.com/MISP/misp-modules).
- Flexible **free text import** tool to ease the integration of unstructured reports into MISP.
- A gentle system to **collaborate** on events and attributes allowing MISP users to propose changes or updates to attributes/indicators.
- **data-sharing**: automatically exchange and synchronization with other parties and trust-groups using MISP.
- **delegating of sharing**: allows a simple pseudo-anonymous mechanism to delegate publication of event/indicators to another organization.
- Flexible **API** to integrate MISP with your own solutions. MISP is bundled with [PyMISP](https://github.com/MISP/PyMISP) which is a flexible Python Library to fetch, add or update events attributes, handle malware samples or search for attributes.
- **Adjustable taxonomy** to classify and tag events following your own classification schemes or [existing classification](https://github.com/MISP/misp-taxonomies). The taxonomy can be local to your MISP but also shareable among MISP instances.
- **Intelligence vocabularies** called MISP galaxy and bundled with existing [threat actors, malware, RAT, ransomware or MITRE ATT&CK](https://www.misp-project.org/galaxy.org) which can be easily linked with events in MISP.
- **Expansion modules in Python** to expand MISP with your own services or activate already available [misp-modules](https://github.com/MISP/misp-modules).
- **Sighting support** to get observations from organizations concerning shared indicators and attributes. Sighting [can be contributed](https://www.circl.lu/doc/misp/automation/index.html#sightings-api) via MISP user-interface, API as MISP document or STIX sighting documents.
- **STIX support**: export data in the STIX format (XML and JSON). Additional STIX import and export is supported by [MISP-STIX-Converter](https://github.com/MISP/MISP-STIX-Converter) or [MISP-Taxii-Server](https://github.com/MISP/MISP-Taxii-Server).
- **Integrated encryption and signing of the notifications** via PGP and/or S/MIME depending of the user preferences.

Exchanging info results in *faster detection* of targeted attacks and improves the detection ratio while reducing the false positives. We also avoid reversing similar malware as we know very fast that others team or organizations who already analyzed a specific malware.

![MISP 2.4 overview](https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/screenshots/misp-panorama.png)

A sample event encoded in MISP:

![MISP event view](./INSTALL/screenshots/event-view.png?raw=true "MISP")

Website / Support
------------------

Checkout the [website](https://www.misp-project.org) for more information about MISP software, standards, tools and communities. 

Information, news and updates are also regularly posted on the [MISP project twitter account](https://twitter.com/MISPProject) or the [news page](https://www.misp-project.org/news/).

Documentation
-------------

[MISP user-guide](https://github.com/MISP/misp-book) is available [online](https://www.circl.lu/doc/misp/) or as [PDF](https://www.circl.lu/doc/misp/book.pdf) or as [EPUB](https://www.circl.lu/doc/misp/book.epub) or as [MOBI/Kindle](https://www.circl.lu/doc/misp/book.mobi).

For installation guide see [INSTALL](https://github.com/MISP/MISP/tree/2.4/INSTALL) or the [download section](https://www.misp-project.org/download/).

Contributing
------------

If you are interested to contribute to the MISP project, review our [contributing page](CONTRIBUTING.md). There are many ways to contribute
and participate to the project.

Please see our [Code of conduct](code_of_conduct.md).

Feel free to fork the code, play with it, make some patches and send us the pull requests via the [issues](https://github.com/MISP/MISP/issues).

Feel free to contact us, create [issues](https://github.com/MISP/MISP/issues), if you have questions, remarks or bug reports.

There is one main branch:

- 2.4 (current stable version): what we consider as stable with frequent updates as hot-fixes.

and features are developed in separated branches and then regularly merged into the 2.4 stable branch.


License
-------

This software is licensed under [GNU Affero General Public License version 3](http://www.gnu.org/licenses/agpl-3.0.html)

* Copyright (C) 2012 Christophe Vandeplas
* Copyright (C) 2012 Belgian Defence
* Copyright (C) 2012 NATO / NCIRC
* Copyright (C) 2013-2018 Andras Iklody
* Copyright (C) 2015-2018 CIRCL - Computer Incident Response Center Luxembourg
* Copyright (C) 2016 Andreas Ziegler

For more information, [the list of authors and contributors](AUTHORS) is available.
