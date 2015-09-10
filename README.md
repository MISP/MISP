[![Build Status](https://travis-ci.org/MISP/MISP.svg?branch=master)](https://travis-ci.org/MISP/MISP)

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


Website / Support
------------------
Checkout the [website](http://www.misp-project.org) for more information about MISP like [features](http://www.misp-project.org/#features), [roadmap](http://www.misp-project.org/#roadmap), <small>(commercial)</small> [support](http://www.misp-project.org/#support), ... : http://misp-project.org


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

This software is licensed under [GNU Affero General Public License version 3](http://www.gnu.org/licenses/agpl-3.0.html)

Copyright (c) 2012, 2013 Christophe Vandeplas, Belgian Defence, NATO / NCIRC.
