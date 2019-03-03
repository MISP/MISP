# INSTALLATION INSTRUCTIONS
## for Kali Linux 2019.1
# 0/ Quick MISP Instance on Kali Linux - Status

This has been tested by @SteveClement on 20190221

# 1/ Prepare Kali with a MISP User

To install MISP on Kali copy paste this in your r00t shell:
```bash
wget -O /tmp/misp-kali.sh https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/INSTALL.debian.sh && bash /tmp/misp-kali.sh
```

!!! notice
    This assumes a **fresh** Kali install OR a Live CD.

!!! warning
    Please read the installer script before randomly doing the above.
    The script is tested on a plain vanilla Kali Linux Boot CD and installs quite a few dependencies.
