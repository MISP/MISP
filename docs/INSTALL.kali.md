# INSTALLATION INSTRUCTIONS
## for Kali Linux 2020.4
# 0/ Quick MISP Instance on Kali Linux - Status

This has been tested by @SteveClement on 20210203

# 1/ Prepare Kali with a MISP User

This only works on Kali 2020.4 and higher.

To install MISP on Kali copy paste this in your shell:
```bash
wget -O /tmp/misp-kali.sh https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/INSTALL.sh && bash /tmp/misp-kali.sh
```

!!! notice
    This assumes a **fresh** Kali install OR a Live CD.

!!! warning
    Please read the installer script before randomly doing the above.
    The script is tested on a plain vanilla Kali Linux Boot CD and installs quite a few dependencies.
