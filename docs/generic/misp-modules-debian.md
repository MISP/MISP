#### Install misp-modules (optional)

```bash
# <snippet-begin 3_misp-modules.sh>
# Main MISP Modules install function
mispmodules () {
  cd /usr/local/src/
  ## TODO: checkUsrLocalSrc in main doc
  debug "Cloning misp-modules"
  $SUDO_CMD git clone https://github.com/MISP/misp-modules.git
  cd misp-modules
  # some misp-modules dependencies
  sudo apt install libpq5 libjpeg-dev tesseract-ocr libpoppler-cpp-dev imagemagick libopencv-dev zbar-tools libzbar0 libzbar-dev libfuzzy-dev -y
  # If you build an egg, the user you build it as need write permissions in the CWD
  sudo chgrp $WWW_USER .
  sudo chmod g+w .
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install -I -r REQUIREMENTS
  sudo chgrp staff .
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install -I .
  ## sudo gem install asciidoctor-pdf --pre

  # Start misp-modules as a service
  sudo cp etc/systemd/system/misp-modules.service /etc/systemd/system/
  sudo systemctl daemon-reload
  sudo systemctl enable --now misp-modules

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
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_btc_steroids_enabled" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_ipasn_enabled" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_yara_syntax_validator_enabled" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_yara_query_enabled" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_pdf_enabled" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_docx_enabled" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_xlsx_enabled" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_pptx_enabled" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_ods_enabled" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_odt_enabled" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_services_url" "http://127.0.0.1"
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Enrichment_services_port" 6666

  # Enable Import modules, set better timeout
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Import_services_enable" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Import_services_url" "http://127.0.0.1"
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Import_services_port" 6666
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Import_timeout" 300
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Import_ocr_enabled" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Import_mispjson_enabled" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Import_openiocimport_enabled" true
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Import_threatanalyzer_import_enabled" true
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
