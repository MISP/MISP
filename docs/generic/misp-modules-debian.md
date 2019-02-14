#### Install misp-modules (optional)

```bash
# <snippet-begin 3_misp-modules.sh>
# Main MISP Modules install function
mispmodules () {
  # FIXME:  this is broken, ${PATH_TO_MISP} is litteral
  sudo sed -i -e '$i \sudo -u www-data /var/www/MISP/venv/bin/misp-modules -l 127.0.0.1 -s > /tmp/misp-modules_rc.local.log &\n' /etc/rc.local
  cd /usr/local/src/
  ## TODO: checkUsrLocalSrc in main doc
  $SUDO_USER git clone https://github.com/MISP/misp-modules.git
  cd misp-modules
  # some misp-modules dependencies
  sudo apt-get install libpq5 libjpeg-dev libfuzzy-dev -y
  # If you build an egg, the user you build it as need write permissions in the CWD
  sudo chgrp $WWW_USER .
  sudo chmod g+w .
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install -I -r REQUIREMENTS
  sudo chgrp staff .
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install -I .
  sudo apt install ruby-pygments.rb -y
  sudo gem install asciidoctor-pdf --pre

  # install additional dependencies for extended object generation and extraction
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install wand yara pathlib
  # Start misp-modules
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/misp-modules -l 127.0.0.1 -s &

  # Sleep 9 seconds to give misp-modules a chance to spawn
  sleep 9

  # Enable Enrichment, set better timeouts
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_services_enable" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_hover_enable" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_timeout" 300
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_hover_timeout" 150
  # TODO:"Investigate why the next one fails"
  #$SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_asn_history_enabled" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_cve_enabled" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_dns_enabled" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_services_url" "http://127.0.0.1"
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_services_port" 6666

  # Enable Import modules, set better timeout
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Import_services_enable" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Import_services_url" "http://127.0.0.1"
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Import_services_port" 6666
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Import_timeout" 300
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Import_ocr_enabled" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Import_csvimport_enabled" true

  # Enable Export modules, set better timeout
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Export_services_enable" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Export_services_url" "http://127.0.0.1"
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Export_services_port" 6666
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Export_timeout" 300
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Export_pdfexport_enabled" true
}
# <snippet-end 3_misp-modules.sh>
```
