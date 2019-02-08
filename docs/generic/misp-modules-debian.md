#### Install misp-modules (optional)

```bash
# <snippet-begin 3_misp-modules.sh>
# Main MISP Modules install function
mispmodules () {
  sudo sed -i -e '$i \sudo -u www-data ${PATH_TO_MISP}/venv/bin/misp-modules -l 127.0.0.1 -s > /tmp/misp-modules_rc.local.log &\n' /etc/rc.local
  $SUDO_WWW bash $PATH_TO_MISP/app/Console/worker/start.sh
  cd /usr/local/src/
  git clone https://github.com/MISP/misp-modules.git
  cd misp-modules
  # some misp-modules dependencies
  sudo apt-get install libpq5 libjpeg-dev libfuzzy-dev -y
  # pip install
  sudo -H -u www-data ${PATH_TO_MISP}/venv/bin/pip install -I -r REQUIREMENTS
  sudo -H -u www-data ${PATH_TO_MISP}/venv/bin/pip install -I .
  sudo apt install ruby-pygments.rb -y
  sudo gem install asciidoctor-pdf --pre
  # install additional dependencies for extended object generation and extraction
  sudo -H -u www-data ${PATH_TO_MISP}/venv/bin/pip install maec lief python-magic wand yara pathlib
  sudo -H -u www-data ${PATH_TO_MISP}/venv/bin/pip install git+https://github.com/kbandla/pydeep.git
  # Start misp-modules
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/misp-modules -l 127.0.0.1 -s &

  # Cake commands for enabling basic misp-modules
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Enrichment_asn_history_enabled" true
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Enrichment_cve_enabled" true
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Enrichment_dns_enabled" true
}
# <snippet-end 3_misp-modules.sh>
```
