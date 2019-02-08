#### Initialize MISP configuration and set some defaults
```bash
# <snippet-start core-cake.sh>
# Core cake commands
coreCAKE () {
  sudo -H -u www-data -E $CAKE userInit -q

  $SUDO_WWW $CAKE Baseurl $MISP_BASEURL

  # Setup some more MISP default via cake CLI

  # Tune global time outs
  sudo -H -u www-data $CAKE Admin setSetting "Session.autoRegenerate" 0
  sudo -H -u www-data $CAKE Admin setSetting "Session.timeout" 600
  sudo -H -u www-data $CAKE Admin setSetting "Session.cookie_timeout" 3600

  # Change base url, either with this CLI command or in the UI
  sudo -H -u www-data $CAKE Baseurl $MISP_BASEURL
  # example: 'baseurl' => 'https://<your.FQDN.here>',
  # alternatively, you can leave this field empty if you would like to use relative pathing in MISP
  # 'baseurl' => '',

  # Enable GnuPG
  sudo -H -u www-data $CAKE Admin setSetting "GnuPG.email" "$GPG_EMAIL_ADDRESS"
  sudo -H -u www-data $CAKE Admin setSetting "GnuPG.homedir" "$PATH_TO_MISP/.gnupg"
  sudo -H -u www-data $CAKE Admin setSetting "GnuPG.password" "$GPG_PASSPHRASE"

  # Enable Enrichment set better timeouts
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Enrichment_services_enable" true
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Enrichment_hover_enable" true
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Enrichment_timeout" 300
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Enrichment_hover_timeout" 150
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Enrichment_cve_enabled" true
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Enrichment_dns_enabled" true
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Enrichment_services_url" "http://127.0.0.1"
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Enrichment_services_port" 6666

  # Enable Import modules set better timout
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Import_services_enable" true
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Import_services_url" "http://127.0.0.1"
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Import_services_port" 6666
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Import_timeout" 300
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Import_ocr_enabled" true
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Import_csvimport_enabled" true

  # Enable Export modules set better timout
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Export_services_enable" true
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Export_services_url" "http://127.0.0.1"
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Export_services_port" 6666
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Export_timeout" 300
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Export_pdfexport_enabled" true

  # Enable installer org and tune some configurables
  sudo -H -u www-data $CAKE Admin setSetting "MISP.host_org_id" 1
  sudo -H -u www-data $CAKE Admin setSetting "MISP.email" "info@admin.test"
  sudo -H -u www-data $CAKE Admin setSetting "MISP.disable_emailing" true
  sudo -H -u www-data $CAKE Admin setSetting "MISP.contact" "info@admin.test"
  sudo -H -u www-data $CAKE Admin setSetting "MISP.disablerestalert" true
  sudo -H -u www-data $CAKE Admin setSetting "MISP.showCorrelationsOnIndex" true
  sudo -H -u www-data $CAKE Admin setSetting "MISP.default_event_tag_collection" 0

  # Provisional Cortex tunes
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Cortex_services_enable" false
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Cortex_services_url" "http://127.0.0.1"
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Cortex_services_port" 9000
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Cortex_timeout" 120
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Cortex_services_url" "http://127.0.0.1"
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Cortex_services_port" 9000
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Cortex_services_timeout" 120
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Cortex_services_authkey" ""
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Cortex_ssl_verify_peer" false
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Cortex_ssl_verify_host" false
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Cortex_ssl_allow_self_signed" true

  # Various plugin sightings settings
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Sightings_policy" 0
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Sightings_anonymise" false
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.Sightings_range" 365

  # Plugin CustomAuth tuneable
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.CustomAuth_disable_logout" false

  # RPZ Plugin settings
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.RPZ_policy" "DROP"
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.RPZ_walled_garden" "127.0.0.1"
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.RPZ_serial" "\$date00"
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.RPZ_refresh" "2h"
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.RPZ_retry" "30m"
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.RPZ_expiry" "30d"
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.RPZ_minimum_ttl" "1h"
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.RPZ_ttl" "1w"
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.RPZ_ns" "localhost."
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.RPZ_ns_alt" ""
  sudo -H -u www-data $CAKE Admin setSetting "Plugin.RPZ_email" "root.localhost"

  # Force defaults to make MISP Server Settings less RED
  sudo -H -u www-data $CAKE Admin setSetting "MISP.language" "eng"
  sudo -H -u www-data $CAKE Admin setSetting "MISP.proposals_block_attributes" false

  # Redis block
  sudo -H -u www-data $CAKE Admin setSetting "MISP.redis_host" "127.0.0.1"
  sudo -H -u www-data $CAKE Admin setSetting "MISP.redis_port" 6379
  sudo -H -u www-data $CAKE Admin setSetting "MISP.redis_database" 13
  sudo -H -u www-data $CAKE Admin setSetting "MISP.redis_password" ""

  # Force defaults to make MISP Server Settings less YELLOW
  sudo -H -u www-data $CAKE Admin setSetting "MISP.ssdeep_correlation_threshold" 40
  sudo -H -u www-data $CAKE Admin setSetting "MISP.extended_alert_subject" false
  sudo -H -u www-data $CAKE Admin setSetting "MISP.default_event_threat_level" 4
  sudo -H -u www-data $CAKE Admin setSetting "MISP.newUserText" "Dear new MISP user,\\n\\nWe would hereby like to welcome you to the \$org MISP community.\\n\\n Use the credentials below to log into MISP at \$misp, where you will be prompted to manually change your password to something of your own choice.\\n\\nUsername: \$username\\nPassword: \$password\\n\\nIf you have any questions, don't hesitate to contact us at: \$contact.\\n\\nBest regards,\\nYour \$org MISP support team"
  sudo -H -u www-data $CAKE Admin setSetting "MISP.passwordResetText" "Dear MISP user,\\n\\nA password reset has been triggered for your account. Use the below provided temporary password to log into MISP at \$misp, where you will be prompted to manually change your password to something of your own choice.\\n\\nUsername: \$username\\nYour temporary password: \$password\\n\\nIf you have any questions, don't hesitate to contact us at: \$contact.\\n\\nBest regards,\\nYour \$org MISP support team"
  sudo -H -u www-data $CAKE Admin setSetting "MISP.enableEventBlacklisting" true
  sudo -H -u www-data $CAKE Admin setSetting "MISP.enableOrgBlacklisting" true
  sudo -H -u www-data $CAKE Admin setSetting "MISP.log_client_ip" false
  sudo -H -u www-data $CAKE Admin setSetting "MISP.log_auth" false
  sudo -H -u www-data $CAKE Admin setSetting "MISP.disableUserSelfManagement" false
  sudo -H -u www-data $CAKE Admin setSetting "MISP.block_event_alert" false
  sudo -H -u www-data $CAKE Admin setSetting "MISP.block_event_alert_tag" "no-alerts=\"true\""
  sudo -H -u www-data $CAKE Admin setSetting "MISP.block_old_event_alert" false
  sudo -H -u www-data $CAKE Admin setSetting "MISP.block_old_event_alert_age" ""
  sudo -H -u www-data $CAKE Admin setSetting "MISP.incoming_tags_disabled_by_default" false
  sudo -H -u www-data $CAKE Admin setSetting "MISP.footermidleft" "This is an initial install"
  sudo -H -u www-data $CAKE Admin setSetting "MISP.footermidright" "Please configure and harden accordingly"
  sudo -H -u www-data $CAKE Admin setSetting "MISP.welcome_text_top" "Initial Install, please configure"
  # TODO: Make sure $FLAVOUR is correct
  sudo -H -u www-data $CAKE Admin setSetting "MISP.welcome_text_bottom" "Welcome to MISP on $FLAVOUR, change this message in MISP Settings"

  # Force defaults to make MISP Server Settings less GREEN
  sudo -H -u www-data $CAKE Admin setSetting "Security.password_policy_length" 12
  sudo -H -u www-data $CAKE Admin setSetting "Security.password_policy_complexity" '/^((?=.*\d)|(?=.*\W+))(?![\n])(?=.*[A-Z])(?=.*[a-z]).*$|.{16,}/'

  # Tune global time outs
  sudo -H -u www-data $CAKE Admin setSetting "Session.autoRegenerate" 0
  sudo -H -u www-data $CAKE Admin setSetting "Session.timeout" 600
  sudo -H -u www-data $CAKE Admin setSetting "Session.cookie_timeout" 3600

  # Set MISP Live
  sudo -H -u www-data $CAKE Live $MISP_LIVE
}

# This updates Galaxies, ObjectTemplates, Warninglists, Noticelists, Templates
updateGOWNT () {
  AUTH_KEY=$(mysql -u $DBUSER_MISP -p$DBPASSWORD_MISP misp -e "SELECT authkey FROM users;" | tail -1)

  # Update the galaxies…
  # TODO: Fix updateGalaxies
  ##sudo -H -u www-data $CAKE Admin updateGalaxies
  curl --header "Authorization: $AUTH_KEY" --header "Accept: application/json" --header "Content-Type: application/json" -k -X POST https://127.0.0.1/galaxies/update
  # Updating the taxonomies…
  sudo -H -u www-data $CAKE Admin updateTaxonomies
  # Updating the warning lists…
  # TODO: Fix updateWarningLists
  ##sudo -H -u www-data $CAKE Admin updateWarningLists
  curl --header "Authorization: $AUTH_KEY" --header "Accept: application/json" --header "Content-Type: application/json" -k -X POST https://127.0.0.1/warninglists/update
  # Updating the notice lists…
  ## sudo -H -u www-data $CAKE Admin updateNoticeLists
  curl --header "Authorization: $AUTH_KEY" --header "Accept: application/json" --header "Content-Type: application/json" -k -X POST https://127.0.0.1/noticelists/update
  # Updating the object templates…
  ##sudo -H -u www-data $CAKE Admin updateObjectTemplates
  curl --header "Authorization: $AUTH_KEY" --header "Accept: application/json" --header "Content-Type: application/json" -k -X POST https://127.0.0.1/objectTemplates/update
}
# <snippet-end core-cake.sh>
```
