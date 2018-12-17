# INSTALLATION INSTRUCTIONS
## for Tsurugi Linux
# 0/ Quick MISP Instance on Tsurugi Linux - Status

This has been tested by @SteveClement on 20181105

# 1/ Prepare Tsurugi with a MISP User
--------------------------------

# openssh-server

It seems there are issues with the **openssh-server** package, thus we need to reconfigure to re-create the keys. (Only if ssh is NOT working)

```bash
sudo update-rc.d -f ssh remove
sudo update-rc.d -f ssh defaults
sudo dpkg-reconfigure openssh-server
sudo systemctl restart ssh
```

If you installed Tsurugi to your disk, the locale is a little all over the place.
We assume **en_US** to be default unless you know what you're doing, go with that default.

```bash
sudo sed -i 's/ja_JP/en_US/g' /etc/default/locale
sudo sed -i 's/ja_JP.UTF/# ja_JP.UTF/g' /etc/locale.gen
sudo dpkg-reconfigure locales
```

To install MISP on Tsurugi copy paste this in your r00t shell:
```bash
wget -O /tmp/misp-tsurugi.sh https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/xINSTALL.tsurugi.txt && bash /tmp/misp-tsurugi.sh
```

!!! warning
    Please read the installer script before randomly doing the above.
    The script is tested on a plain vanilla Tsurugi Linux Boot CD and installs quite a few dependencies.
