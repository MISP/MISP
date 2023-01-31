# cerebrate

Cerebrate is an [open-source platform](https://github.com/cerebrate-project) meant to act as a trusted contact information provider and interconnection orchestrator for other security tools (such as [MISP](https://www.misp-project.org/)).

# Features

- Advanced repository to manage individuals and organisations;
- Key store for public encryption and signing cryptographic keys (e.g. PGP);
- Distributed synchronisation model where multiple Cerebrate instances can be interconnected amongst organisations and/or departments;
- Management of individuals and their affiliations to each organisations;
- Advanced API and CLI to integrate with existing tools (e.g. importing existing directory information);
- Dynamic model for creating new organisational structures;
- Support existing organisational structures such as [FIRST.org](https://www.first.org/) directory, EU [CSIRTs network](https://csirtsnetwork.eu/);
- Local tooling interconnection to easily connect existing tools with their native protocols;

Cerebrate is developed in the scope of the MeliCERTes v2 project.

## Screenshots

![Dashboard](https://www.cerebrate-project.org/assets/images/screenshots/Screenshot%20from%202021-10-19%2016-31-56.png)

List of individuals along with their affiliations

![List of individuals](https://www.cerebrate-project.org/assets/images/screenshots/Screenshot%20from%202021-10-19%2016-32-35.png)

Adding organisations

![Adding an organisation](https://www.cerebrate-project.org/assets/images/screenshots/Screenshot%20from%202021-10-19%2016-33-04.png)

Everything is available via the API, here an example of a search query for all international organisations in the DB.

![API query](/documentation/images/orgs_api.png)

Managing public keys and assigning them to users both for communication and validating signed information shared in the community

![Encryption key management](/documentation/images/add_encryption_key.png)

Dynamic model for creating new organisation structre

![Meta Field Templates](https://www.cerebrate-project.org/assets/images/screenshots/Screenshot%20from%202021-10-19%2016-38-21.png)

# Requirements and installation

The platform is built on CakePHP 4 along with Bootstrap 4 and shares parts of the code-base with [MISP](https://www.github.com/MISP).

The installation is documented at the following location [INSTALL/INSTALL.md](INSTALL/INSTALL.md). For upgrades, look at [INSTALL/UPGRADE.md](INSTALL/UPGRADE.md)

Hardware requirements:

A webserver with 4GB of memory and a single CPU core should be plenty for the current scope of Cerebrate. This might increase over the time with additional features being added, but the goal is to keep Cerebrate as lean as possible. Expect to have at least 40GB of disk space, depending on your log rotation strategy you might want to go higher.

For installation via docker, refer to the [cerebrate-docker](https://github.com/cerebrate-project/cerebrate-docker) repo.

# License

~~~~
    The software is released under the AGPLv3.

    Copyright (C) 2019, 2021  Andras Iklody
    Copyright (C) 2020-2021 Sami Mokaddem
    Copyright (C) CIRCL - Computer Incident Response Center Luxembourg
~~~~
