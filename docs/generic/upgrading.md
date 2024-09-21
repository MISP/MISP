#### Upgrading all of the above
-----------------------

##### MISP core

Also refer to this [UPDATE section](../UPDATE/) which might partially overlap on the information below.

There are 2 ways to upgrade MISP.
The preferred way is to go into the Web UI "Server Settings & Maintenance" -> "Diagnostics" and click "Update MISP".

If this fails most likely permissions are the reason.

More details can be found in [MISP Book](https://www.circl.lu/doc/misp/faq/#update-misp-fails) to resolve the issue.

To fix permissions refer to [the install guide](https://misp.github.io/MISP/INSTALL.ubuntu1804#5-set-the-permissions).

Another way is to open a shell on your MISP instance and go to the main MISP directory and pull the latest code:

```bash
cd /var/www/MISP
sudo -H -u www-data git pull origin 2.4
sudo -H -u www-data git submodule update --init --recursive
```

If the above fails, your permissions might be wrong. [Click here for the fix the permissions guide](https://misp.github.io/MISP/INSTALL.ubuntu1804#5-set-the-permissions).

##### MISP Dependencies

```bash
# MISP configuration variables
PATH_TO_MISP='/var/www/MISP'
CAKE="$PATH_TO_MISP/app/Console/cake"
```

###### virtualenv


```bash
sudo -H -u www-data virtualenv -p python3 ${PATH_TO_MISP}/venv
cd $PATH_TO_MISP/app/files/scripts/python-cybox
sudo -u www-data git pull
sudo -H -u www-data ${PATH_TO_MISP}/venv/bin/pip install -U .
cd $PATH_TO_MISP/app/files/scripts/python-stix
sudo -u www-data git pull
sudo -H -u www-data ${PATH_TO_MISP}/venv/bin/pip install -U .
cd $PATH_TO_MISP/app/files/scripts/python-maec
sudo -u www-data git pull
sudo -H -u www-data ${PATH_TO_MISP}/venv/bin/pip install -U .
cd ${PATH_TO_MISP}/app/files/scripts/misp-stix
sudo -H -u www-data ${PATH_TO_MISP}/venv/bin/pip install -I -U .

# install mixbox to accommodate the new STIX dependencies:
cd $PATH_TO_MISP/app/files/scripts/mixbox
sudo -u www-data git pull
sudo -H -u www-data ${PATH_TO_MISP}/venv/bin/pip install -U .
# install PyMISP
cd $PATH_TO_MISP/PyMISP
sudo -H -u www-data ${PATH_TO_MISP}/venv/bin/pip install -U .
```

###### misp-modules

```bash
cd /usr/local/src/misp-modules
git pull
sudo -H -u www-data ${PATH_TO_MISP}/venv/bin/pip install -U -I -r REQUIREMENTS
sudo -H -u www-data ${PATH_TO_MISP}/venv/bin/pip install -U .
sudo gem update asciidoctor-pdf --pre
# install additional dependencies for extended object generation and extraction
sudo -H -u www-data ${PATH_TO_MISP}/venv/bin/pip install -U maec lief python-magic pathlib
sudo -H -u www-data ${PATH_TO_MISP}/venv/bin/pip install -U git+https://github.com/kbandla/pydeep.git
```

###### pyzmq

```bash
sudo -H -u www-data ${PATH_TO_MISP}/venv/bin/pip install -U pyzmq
```

###### misp-dashboard

```bash
cd /var/www/misp-dashboard
sudo -H -u www-data git pull
sudo -H /var/www/misp-dashboard/install_dependencies.sh
```

###### viper

```bash
cd /usr/local/src/viper
git pull
virtualenv -p python3.6 venv
git submodule update --init --recursive
./venv/bin/pip install -U scrapy
./venv/bin/pip install -U -r requirements.txt
/usr/local/src/viper/viper-cli -h
```

###### mail-to-misp

```bash
cd /usr/local/src/faup
git pull
make clean
rm -r build ; mkdir build
cd build
cmake .. && make
sudo make install
sudo ldconfig
cd /usr/local/src/mail_to_misp
git pull
virtualenv -p python3.6 venv
./venv/bin/pip install -U -r requirements.txt
diff -u mail_to_misp_config.py-example mail_to_misp_config.py
```
