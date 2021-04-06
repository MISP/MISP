!!! notice
    This document also serves as a source for the [INSTALL-misp.sh](https://github.com/MISP/MISP/blob/2.4/INSTALL/INSTALL.sh) script.
    Which explains why you will see the use of shell *functions* in various steps.
    You will see bash-*functions* in various steps. You can either copy between the *{}*'s or copy the entire function and just run it.
    Henceforth the document will also follow a more logical flow. In the sense that all the dependencies are installed first then config files are generated, etc...

### -1/ Installer and Manual install instructions

To install MISP all you need to do is the following on a clean [supported](https://misp.github.io/MISP/) distribution.

!!! notice

    ```bash
    # Please check the installer options first to make the best choice for your install
    wget -O /tmp/INSTALL.sh https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/INSTALL.sh
    bash /tmp/INSTALL.sh

    # This will install MISP Core
    wget -O /tmp/INSTALL.sh https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/INSTALL.sh
    bash /tmp/INSTALL.sh -c
    ```
