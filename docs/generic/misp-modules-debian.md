#### Install misp-modules (optional)

```bash
# <snippet-start misp-modules.sh>
sudo sed -i -e '$i \sudo -u www-data ${PATH_TO_MISP}/venv/bin/misp-modules -l 127.0.0.1 -s > /tmp/misp-modules_rc.local.log &\n' /etc/rc.local

# some misp-modules dependencies
sudo apt-get install libpq5 libjpeg-dev libfuzzy-dev -y

sudo chmod 2775 /usr/local/src
sudo chown root:staff /usr/local/src
cd /usr/local/src/
git clone https://github.com/MISP/misp-modules.git
cd misp-modules
# pip install
sudo -H -u www-data ${PATH_TO_MISP}/venv/bin/pip install -I -r REQUIREMENTS
sudo -H -u www-data ${PATH_TO_MISP}/venv/bin/pip install .
sudo apt install ruby-pygments.rb -y
sudo gem install asciidoctor-pdf --pre

# install additional dependencies for extended object generation and extraction
sudo -H -u www-data ${PATH_TO_MISP}/venv/bin/pip install maec lief python-magic pathlib
sudo -H -u www-data ${PATH_TO_MISP}/venv/bin/pip install git+https://github.com/kbandla/pydeep.git

# Start misp-modules
sudo -u www-data ${PATH_TO_MISP}/venv/bin/misp-modules -l 127.0.0.1 -s &

# Cake commands for enabling basic misp-modules
sudo -H -u www-data $CAKE Admin setSetting "Plugin.Enrichment_asn_history_enabled" true
sudo -H -u www-data $CAKE Admin setSetting "Plugin.Enrichment_cve_enabled" true
sudo -H -u www-data $CAKE Admin setSetting "Plugin.Enrichment_dns_enabled" true
# <snippet-end misp-modules.sh>
```

