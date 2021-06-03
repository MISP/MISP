```bash
# <snippet-begin 3_misp-modules-cake.sh>
modulesCAKE () {
  # Enable Enrichment, set better timeouts
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_services_enable" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_hover_enable" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_hover_popover_only" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_hover_timeout" 150
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_timeout" 300
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_bgpranking_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_countrycode_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_cve_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_cve_advanced_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_cpe_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_dns_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_eql_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_btc_steroids_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_ipasn_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_reversedns_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_yara_syntax_validator_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_yara_query_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_wiki_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_threatminer_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_threatcrowd_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_hashdd_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_rbl_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_sigma_syntax_validator_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_stix2_pattern_syntax_validator_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_sigma_queries_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_dbl_spamhaus_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_btc_scam_check_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_macvendors_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_qrcode_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_ocr_enrich_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_pdf_enrich_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_docx_enrich_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_xlsx_enrich_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_pptx_enrich_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_ods_enrich_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_odt_enrich_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_urlhaus_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_malwarebazaar_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_html_to_markdown_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_socialscan_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_services_url" "http://127.0.0.1"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Enrichment_services_port" 6666

  # Enable Import modules, set better timeout
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Import_services_enable" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Import_services_url" "http://127.0.0.1"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Import_services_port" 6666
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Import_timeout" 300
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Import_ocr_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Import_mispjson_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Import_openiocimport_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Import_threatanalyzer_import_enabled" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Import_csvimport_enabled" true

  # Enable Export modules, set better timeout
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Export_services_enable" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Export_services_url" "http://127.0.0.1"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Export_services_port" 6666
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Export_timeout" 300
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Export_pdfexport_enabled" true
}
# <snippet-end 3_misp-modules-cake.sh>
```
