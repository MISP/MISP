#### Initialize MISP configuration and set some defaults
```bash
# Default Cake path
export CAKE="$PATH_TO_MISP/app/Console/cake"
# Initialize user and fetch Auth Key
sudo -E $CAKE userInit -q
AUTH_KEY=$(mysql -u $DBUSER_MISP -p$DBPASSWORD_MISP misp -e "SELECT authkey FROM users;" | tail -1)

# Setup some more MISP default via cake CLI

# Change base url, either with this CLI command or in the UI
sudo $CAKE Baseurl $MISP_BASEURL
# example: 'baseurl' => 'https://<your.FQDN.here>',
# alternatively, you can leave this field empty if you would like to use relative pathing in MISP
# 'baseurl' => '',

# Tune global time outs
sudo $CAKE Admin setSetting "Session.autoRegenerate" 0
sudo $CAKE Admin setSetting "Session.timeout" 600
sudo $CAKE Admin setSetting "Session.cookie_timeout" 3600

# Enable GnuPG
sudo $CAKE Admin setSetting "GnuPG.email" "admin@admin.test"
sudo $CAKE Admin setSetting "GnuPG.homedir" "$PATH_TO_MISP/.gnupg"
sudo $CAKE Admin setSetting "GnuPG.password" "Password1234"

# Enable Enrichment set better timeouts
sudo $CAKE Admin setSetting "Plugin.Enrichment_services_enable" true
sudo $CAKE Admin setSetting "Plugin.Enrichment_hover_enable" true
sudo $CAKE Admin setSetting "Plugin.Enrichment_timeout" 300
sudo $CAKE Admin setSetting "Plugin.Enrichment_hover_timeout" 150
sudo $CAKE Admin setSetting "Plugin.Enrichment_cve_enabled" true
sudo $CAKE Admin setSetting "Plugin.Enrichment_dns_enabled" true
sudo $CAKE Admin setSetting "Plugin.Enrichment_services_url" "http://127.0.0.1"
sudo $CAKE Admin setSetting "Plugin.Enrichment_services_port" 6666

# Enable Import modules set better timout
sudo $CAKE Admin setSetting "Plugin.Import_services_enable" true
sudo $CAKE Admin setSetting "Plugin.Import_services_url" "http://127.0.0.1"
sudo $CAKE Admin setSetting "Plugin.Import_services_port" 6666
sudo $CAKE Admin setSetting "Plugin.Import_timeout" 300
sudo $CAKE Admin setSetting "Plugin.Import_ocr_enabled" true
sudo $CAKE Admin setSetting "Plugin.Import_csvimport_enabled" true

# Enable Export modules set better timout
sudo $CAKE Admin setSetting "Plugin.Export_services_enable" true
sudo $CAKE Admin setSetting "Plugin.Export_services_url" "http://127.0.0.1"
sudo $CAKE Admin setSetting "Plugin.Export_services_port" 6666
sudo $CAKE Admin setSetting "Plugin.Export_timeout" 300
sudo $CAKE Admin setSetting "Plugin.Export_pdfexport_enabled" true

# Enable installer org and tune some configurables
sudo $CAKE Admin setSetting "MISP.host_org_id" 1
sudo $CAKE Admin setSetting "MISP.email" "info@admin.test"
sudo $CAKE Admin setSetting "MISP.disable_emailing" true
sudo $CAKE Admin setSetting "MISP.contact" "info@admin.test"
sudo $CAKE Admin setSetting "MISP.disablerestalert" true
sudo $CAKE Admin setSetting "MISP.showCorrelationsOnIndex" true

# Provisional Cortex tunes
sudo $CAKE Admin setSetting "Plugin.Cortex_services_enable" false
sudo $CAKE Admin setSetting "Plugin.Cortex_services_url" "http://127.0.0.1"
sudo $CAKE Admin setSetting "Plugin.Cortex_services_port" 9000
sudo $CAKE Admin setSetting "Plugin.Cortex_timeout" 120
sudo $CAKE Admin setSetting "Plugin.Cortex_services_url" "http://127.0.0.1"
sudo $CAKE Admin setSetting "Plugin.Cortex_services_port" 9000
sudo $CAKE Admin setSetting "Plugin.Cortex_services_timeout" 120
sudo $CAKE Admin setSetting "Plugin.Cortex_services_authkey" ""
sudo $CAKE Admin setSetting "Plugin.Cortex_ssl_verify_peer" false
sudo $CAKE Admin setSetting "Plugin.Cortex_ssl_verify_host" false
sudo $CAKE Admin setSetting "Plugin.Cortex_ssl_allow_self_signed" true

# Various plugin sightings settings
sudo $CAKE Admin setSetting "Plugin.Sightings_policy" 0
sudo $CAKE Admin setSetting "Plugin.Sightings_anonymise" false
sudo $CAKE Admin setSetting "Plugin.Sightings_range" 365

# Plugin CustomAuth tuneable
sudo $CAKE Admin setSetting "Plugin.CustomAuth_disable_logout" false

# RPZ Plugin settings
sudo $CAKE Admin setSetting "Plugin.RPZ_policy" "DROP"
sudo $CAKE Admin setSetting "Plugin.RPZ_walled_garden" "127.0.0.1"
sudo $CAKE Admin setSetting "Plugin.RPZ_serial" "\$date00"
sudo $CAKE Admin setSetting "Plugin.RPZ_refresh" "2h"
sudo $CAKE Admin setSetting "Plugin.RPZ_retry" "30m"
sudo $CAKE Admin setSetting "Plugin.RPZ_expiry" "30d"
sudo $CAKE Admin setSetting "Plugin.RPZ_minimum_ttl" "1h"
sudo $CAKE Admin setSetting "Plugin.RPZ_ttl" "1w"
sudo $CAKE Admin setSetting "Plugin.RPZ_ns" "localhost."
sudo $CAKE Admin setSetting "Plugin.RPZ_ns_alt" ""
sudo $CAKE Admin setSetting "Plugin.RPZ_email" "root.localhost"

# Force defaults to make MISP Server Settings less RED
sudo $CAKE Admin setSetting "MISP.language" "eng"
sudo $CAKE Admin setSetting "MISP.proposals_block_attributes" false

## Redis block
sudo $CAKE Admin setSetting "MISP.redis_host" "127.0.0.1"
sudo $CAKE Admin setSetting "MISP.redis_port" 6379
sudo $CAKE Admin setSetting "MISP.redis_database" 13
sudo $CAKE Admin setSetting "MISP.redis_password" ""

# Force defaults to make MISP Server Settings less YELLOW
sudo $CAKE Admin setSetting "MISP.ssdeep_correlation_threshold" 40
sudo $CAKE Admin setSetting "MISP.extended_alert_subject" false
sudo $CAKE Admin setSetting "MISP.default_event_threat_level" 4
sudo $CAKE Admin setSetting "MISP.newUserText" "Dear new MISP user,\\n\\nWe would hereby like to welcome you to the \$org MISP community.\\n\\n Use the credentials below to log into MISP at \$misp, where you will be prompted to manually change your password to something of your own choice.\\n\\nUsername: \$username\\nPassword: \$password\\n\\nIf you have any questions, don't hesitate to contact us at: \$contact.\\n\\nBest regards,\\nYour \$org MISP support team"
sudo $CAKE Admin setSetting "MISP.passwordResetText" "Dear MISP user,\\n\\nA password reset has been triggered for your account. Use the below provided temporary password to log into MISP at \$misp, where you will be prompted to manually change your password to something of your own choice.\\n\\nUsername: \$username\\nYour temporary password: \$password\\n\\nIf you have any questions, don't hesitate to contact us at: \$contact.\\n\\nBest regards,\\nYour \$org MISP support team"
sudo $CAKE Admin setSetting "MISP.enableEventBlacklisting" true
sudo $CAKE Admin setSetting "MISP.enableOrgBlacklisting" true
sudo $CAKE Admin setSetting "MISP.log_client_ip" false
sudo $CAKE Admin setSetting "MISP.log_auth" false
sudo $CAKE Admin setSetting "MISP.disableUserSelfManagement" false
sudo $CAKE Admin setSetting "MISP.block_event_alert" false
sudo $CAKE Admin setSetting "MISP.block_event_alert_tag" "no-alerts=\"true\""
sudo $CAKE Admin setSetting "MISP.block_old_event_alert" false
sudo $CAKE Admin setSetting "MISP.block_old_event_alert_age" ""
sudo $CAKE Admin setSetting "MISP.incoming_tags_disabled_by_default" false
sudo $CAKE Admin setSetting "MISP.footermidleft" "This is an initial install"
sudo $CAKE Admin setSetting "MISP.footermidright" "Please configure and harden accordingly"
sudo $CAKE Admin setSetting "MISP.welcome_text_top" "Initial Install, please configure"
sudo $CAKE Admin setSetting "MISP.welcome_text_bottom" "Welcome to MISP, change this message in MISP Settings"

# Force defaults to make MISP Server Settings less GREEN
sudo $CAKE Admin setSetting "Security.password_policy_length" 12
sudo $CAKE Admin setSetting "Security.password_policy_complexity" '/^((?=.*\d)|(?=.*\W+))(?![\n])(?=.*[A-Z])(?=.*[a-z]).*$|.{16,}/'

# Tune global time outs
sudo $CAKE Admin setSetting "Session.autoRegenerate" 0
sudo $CAKE Admin setSetting "Session.timeout" 600
sudo $CAKE Admin setSetting "Session.cookie_timeout" 3600

# Update the galaxies…
sudo $CAKE Admin updateGalaxies

# Updating the taxonomies…
sudo $CAKE Admin updateTaxonomies

# Updating the warning lists…
##sudo $CAKE Admin updateWarningLists
curl --header "Authorization: $AUTH_KEY" --header "Accept: application/json" --header "Content-Type: application/json" -k -X POST https://127.0.0.1/warninglists/update

# Updating the notice lists…
## sudo $CAKE Admin updateNoticeLists
curl --header "Authorization: $AUTH_KEY" --header "Accept: application/json" --header "Content-Type: application/json" -k -X POST https://127.0.0.1/noticelists/update

# Updating the object templates…
##sudo $CAKE Admin updateObjectTemplates
curl --header "Authorization: $AUTH_KEY" --header "Accept: application/json" --header "Content-Type: application/json" -k -X POST https://127.0.0.1/objectTemplates/update

# Set MISP Live
sudo $CAKE Live $MISP_LIVE
```
