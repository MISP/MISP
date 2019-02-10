#### Initialize MISP configuration and set some defaults
```bash
# <snippet-begin 2_core-cake.sh>
# Core cake commands
coreCAKE () {
  $SUDO_WWW -E $CAKE userInit -q

  # This makes sure all Database upgrades are done, without logging in.
  $SUDO_WWW $CAKE Admin updateDatabase

  # Setup some more MISP default via cake CLI

  # Tune global time outs
  $SUDO_WWW $CAKE Admin setSetting "Session.autoRegenerate" 0
  $SUDO_WWW $CAKE Admin setSetting "Session.timeout" 600
  $SUDO_WWW $CAKE Admin setSetting "Session.cookieTimeout" 3600

  # Change base url, either with this CLI command or in the UI
  $SUDO_WWW $CAKE Baseurl $MISP_BASEURL
  # example: 'baseurl' => 'https://<your.FQDN.here>',
  # alternatively, you can leave this field empty if you would like to use relative pathing in MISP
  # 'baseurl' => '',

  # Enable GnuPG
  $SUDO_WWW $CAKE Admin setSetting "GnuPG.email" "$GPG_EMAIL_ADDRESS"
  $SUDO_WWW $CAKE Admin setSetting "GnuPG.homedir" "$PATH_TO_MISP/.gnupg"
  $SUDO_WWW $CAKE Admin setSetting "GnuPG.password" "$GPG_PASSPHRASE"

  # Enable installer org and tune some configurables
  $SUDO_WWW $CAKE Admin setSetting "MISP.host_org_id" 1
  $SUDO_WWW $CAKE Admin setSetting "MISP.email" "info@admin.test"
  $SUDO_WWW $CAKE Admin setSetting "MISP.disable_emailing" true
  $SUDO_WWW $CAKE Admin setSetting "MISP.contact" "info@admin.test"
  $SUDO_WWW $CAKE Admin setSetting "MISP.disablerestalert" true
  $SUDO_WWW $CAKE Admin setSetting "MISP.showCorrelationsOnIndex" true
  $SUDO_WWW $CAKE Admin setSetting "MISP.default_event_tag_collection" 0

  # Provisional Cortex tunes
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Cortex_services_enable" false
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Cortex_services_url" "http://127.0.0.1"
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Cortex_services_port" 9000
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Cortex_timeout" 120
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Cortex_authkey" ""
  # Mysteriously removed?
  #$SUDO_WWW $CAKE Admin setSetting "Plugin.Cortex_services_timeout" 120
  # Mysteriously removed?
  #$SUDO_WWW $CAKE Admin setSetting "Plugin.Cortex_services_authkey" ""
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Cortex_ssl_verify_peer" false
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Cortex_ssl_verify_host" false
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Cortex_ssl_allow_self_signed" true

  # Various plugin sightings settings
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Sightings_policy" 0
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Sightings_anonymise" false
  $SUDO_WWW $CAKE Admin setSetting "Plugin.Sightings_range" 365

  # Plugin CustomAuth tuneable
  $SUDO_WWW $CAKE Admin setSetting "Plugin.CustomAuth_disable_logout" false

  # RPZ Plugin settings
  $SUDO_WWW $CAKE Admin setSetting "Plugin.RPZ_policy" "DROP"
  $SUDO_WWW $CAKE Admin setSetting "Plugin.RPZ_walled_garden" "127.0.0.1"
  $SUDO_WWW $CAKE Admin setSetting "Plugin.RPZ_serial" "\$date00"
  $SUDO_WWW $CAKE Admin setSetting "Plugin.RPZ_refresh" "2h"
  $SUDO_WWW $CAKE Admin setSetting "Plugin.RPZ_retry" "30m"
  $SUDO_WWW $CAKE Admin setSetting "Plugin.RPZ_expiry" "30d"
  $SUDO_WWW $CAKE Admin setSetting "Plugin.RPZ_minimum_ttl" "1h"
  $SUDO_WWW $CAKE Admin setSetting "Plugin.RPZ_ttl" "1w"
  $SUDO_WWW $CAKE Admin setSetting "Plugin.RPZ_ns" "localhost."
  $SUDO_WWW $CAKE Admin setSetting "Plugin.RPZ_ns_alt" ""
  $SUDO_WWW $CAKE Admin setSetting "Plugin.RPZ_email" "root.localhost"

  # Force defaults to make MISP Server Settings less RED
  $SUDO_WWW $CAKE Admin setSetting "MISP.language" "eng"
  $SUDO_WWW $CAKE Admin setSetting "MISP.proposals_block_attributes" false

  # Redis block
  $SUDO_WWW $CAKE Admin setSetting "MISP.redis_host" "127.0.0.1"
  $SUDO_WWW $CAKE Admin setSetting "MISP.redis_port" 6379
  $SUDO_WWW $CAKE Admin setSetting "MISP.redis_database" 13
  $SUDO_WWW $CAKE Admin setSetting "MISP.redis_password" ""

  # Force defaults to make MISP Server Settings less YELLOW
  $SUDO_WWW $CAKE Admin setSetting "MISP.ssdeep_correlation_threshold" 40
  $SUDO_WWW $CAKE Admin setSetting "MISP.extended_alert_subject" false
  $SUDO_WWW $CAKE Admin setSetting "MISP.default_event_threat_level" 4
  $SUDO_WWW $CAKE Admin setSetting "MISP.newUserText" "Dear new MISP user,\\n\\nWe would hereby like to welcome you to the \$org MISP community.\\n\\n Use the credentials below to log into MISP at \$misp, where you will be prompted to manually change your password to something of your own choice.\\n\\nUsername: \$username\\nPassword: \$password\\n\\nIf you have any questions, don't hesitate to contact us at: \$contact.\\n\\nBest regards,\\nYour \$org MISP support team"
  $SUDO_WWW $CAKE Admin setSetting "MISP.passwordResetText" "Dear MISP user,\\n\\nA password reset has been triggered for your account. Use the below provided temporary password to log into MISP at \$misp, where you will be prompted to manually change your password to something of your own choice.\\n\\nUsername: \$username\\nYour temporary password: \$password\\n\\nIf you have any questions, don't hesitate to contact us at: \$contact.\\n\\nBest regards,\\nYour \$org MISP support team"
  $SUDO_WWW $CAKE Admin setSetting "MISP.enableEventBlacklisting" true
  $SUDO_WWW $CAKE Admin setSetting "MISP.enableOrgBlacklisting" true
  $SUDO_WWW $CAKE Admin setSetting "MISP.log_client_ip" false
  $SUDO_WWW $CAKE Admin setSetting "MISP.log_auth" false
  $SUDO_WWW $CAKE Admin setSetting "MISP.disableUserSelfManagement" false
  $SUDO_WWW $CAKE Admin setSetting "MISP.block_event_alert" false
  $SUDO_WWW $CAKE Admin setSetting "MISP.block_event_alert_tag" "no-alerts=\"true\""
  $SUDO_WWW $CAKE Admin setSetting "MISP.block_old_event_alert" false
  $SUDO_WWW $CAKE Admin setSetting "MISP.block_old_event_alert_age" ""
  $SUDO_WWW $CAKE Admin setSetting "MISP.incoming_tags_disabled_by_default" false
  $SUDO_WWW $CAKE Admin setSetting "MISP.footermidleft" "This is an initial install"
  $SUDO_WWW $CAKE Admin setSetting "MISP.footermidright" "Please configure and harden accordingly"
  $SUDO_WWW $CAKE Admin setSetting "MISP.welcome_text_top" "Initial Install, please configure"
  # TODO: Make sure $FLAVOUR is correct
  $SUDO_WWW $CAKE Admin setSetting "MISP.welcome_text_bottom" "Welcome to MISP on $FLAVOUR, change this message in MISP Settings"

  # Force defaults to make MISP Server Settings less GREEN
  $SUDO_WWW $CAKE Admin setSetting "Security.password_policy_length" 12
  $SUDO_WWW $CAKE Admin setSetting "Security.password_policy_complexity" '/^((?=.*\d)|(?=.*\W+))(?![\n])(?=.*[A-Z])(?=.*[a-z]).*$|.{16,}/'

  # Set MISP Live
  $SUDO_WWW $CAKE Live $MISP_LIVE
}

# This updates Galaxies, ObjectTemplates, Warninglists, Noticelists, Templates
updateGOWNT () {
  AUTH_KEY=$(mysql -u $DBUSER_MISP -p$DBPASSWORD_MISP misp -e "SELECT authkey FROM users;" | tail -1)

  # Update the galaxies…
  # TODO: Fix updateGalaxies
  ##$SUDO_WWW $CAKE Admin updateGalaxies
  curl --header "Authorization: $AUTH_KEY" --header "Accept: application/json" --header "Content-Type: application/json" -k -X POST https://127.0.0.1/galaxies/update
  # Updating the taxonomies…
  $SUDO_WWW $CAKE Admin updateTaxonomies
  # Updating the warning lists…
  # TODO: Fix updateWarningLists
  ##$SUDO_WWW $CAKE Admin updateWarningLists
  curl --header "Authorization: $AUTH_KEY" --header "Accept: application/json" --header "Content-Type: application/json" -k -X POST https://127.0.0.1/warninglists/update
  # Updating the notice lists…
  ## $SUDO_WWW $CAKE Admin updateNoticeLists
  curl --header "Authorization: $AUTH_KEY" --header "Accept: application/json" --header "Content-Type: application/json" -k -X POST https://127.0.0.1/noticelists/update
  # Updating the object templates…
  ##$SUDO_WWW $CAKE Admin updateObjectTemplates
  curl --header "Authorization: $AUTH_KEY" --header "Accept: application/json" --header "Content-Type: application/json" -k -X POST https://127.0.0.1/objectTemplates/update
}
# <snippet-end 2_core-cake.sh>
```
