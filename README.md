MISP - Malware Information Sharing Platform
-------------------------------------------

![logo](./INSTALL/logos/misp-logo.png?raw=true "MISP")

The problem that we experienced in the past was the difficulty to exchange information about (targeted) malwares and attacks within a group of trusted partners, or a bilateral agreement.
Even today much of the information exchange happens in unstructured reports where you have to copy-paste the information in your own text-files that you then have to parse to export to (N)IDS and systems like log-searches, etc...

A huge challenge in the Cyber Security domain is the information sharing inside and between organizations.
This Malware Information Sharing Platform has as goal to facilitate:
- **central IOC database**: storing technical and non-technical information about malwares and attacks, ... Data from external instances is also imported into your local instance
- **correlation**: automatically creating relations between malwares, events and attributes
- **storing data** in a structured format (allowing automated use of the database for various purposes)
- **export**: generating IDS, OpenIOC, plain text, xml output to integrate with other systems (network IDS, host IDS, custom tools, …)
- **import**: bulk-import, batch-import, import from OpenIOC, GFI sandbox, ThreatConnect CSV, ...
- **data-sharing**: automatically exchange and synchronization with other parties and trust-groups using MISP
- **STIX support**: export data in the STIX format (XML and json)

Exchanging info results in *faster detection* of targeted attacks and improves the detection ratio while reducing the false positives. We also avoid reversing similar malware as we know very fast that others already worked on this malware.
The Red October malware for example gives a similar view:

![red october](http://3.bp.blogspot.com/-B3h0xbX7RjI/Uftvmq05rHI/AAAAAAAAApo/I0OEYOAFUI4/s1600/red-oct-1.jpg)

![red october](http://1.bp.blogspot.com/-LnMVhq4Rpyk/UftvmguodBI/AAAAAAAAAps/e22fomGL2MU/s1600/red-oct-2.jpg)


Some people might think about CIF (Collective Intelligence Framework) and CRITs (Collaborative Research Into Threats), however those tools are different. Each one has its strenghts and weaknesses, but in the end MISP will rule the world of course.

Changelog
---------
v2.3 brings important improvements in features, performance and usability:
- STIX export
- Easier editing of large data sets, thanks to AJAX
- Impressive performance improvements in load time (and memory usage)
- Templating system: create templates for your organisation for easier data entry, and optionally share the templates with other organisations on your MISP instance
- Free-text import tool: just paste a list of indicators and let MISP figure out what it is
- Attribute merge tool: update the list of all attributes of the same type by pasting a new list of values 
- Diagnostic and configuration tool
- Improved synchronisation
- API improvements
- New Filtering for events / users with bookmarks
 
v2.2 brings some minor improvements and fixes

v2.1 implements important changes in the database format:
- A complete redesign of the UI
- Added a lot more import/exports formats
- Serious code cleanup

Roadmap
-------
v2.4
- Sharing groups : more control over sharability of data
- Modular import / export: make it easier to add more import/export plugins

v3.0+
- Reworking the MISP data model (phase 1): Move away from the current attribute model and go to a hierarchical object model that allows composite objects (for example a file described by hashes, filename, filesize, etc. being one object). Compatibility with STIX and OpenIOC, allowing us to import data in those formats
- Reworking the MISP data model (phase 2): Build extra structures on top of the current event / attribute structure, such as campaigns, threat actors, TTPs, and so on.
- Integration with other tools: Wide range of possibilities. Import from other sandboxes, directly import from feeds in popular formats. Automate sandboxing procedure (upload sample to your sandbox, automatically create an event based on the result, etc). 
- Automatic enrichment: Automatically gather additional information on the data that you are entering. Do look-ups based on hashes, IP addresses, domain and host-names.



Documentation
-------------
Feel free to have a look at the (pdf) documentation in the INSTALL directory.

We are actively developing this tool and many (code, documentation, export formats,...) improvements are coming.

Feel free to fork the code, play with it, make some patches and send us the pull requests.

Feel free to contact us, create issues, if you have questions, remarks or bug reports.

There are 2 branches:
- develop: (very active development) new features and improvements
- main: what we consider as stable

License
-------

This software is licensed under GNU Affero General Public License version 3

Copyright (c) 2012, 2013 Christophe Vandeplas, Belgian Defence, NATO / NCIRC.
