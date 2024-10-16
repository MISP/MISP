#### Initialize MISP configuration and set some defaults
```bash
# <snippet-begin 2_core-cake.sh>
# Core cake commands to tweak MISP and alleviate some of the configuration pains
# The ${RUN_PHP} is ONLY set on RHEL installs and can thus be ignored
# This file is NOT an excuse to NOT read the settings and familiarize ourselves with them ;)

coreCAKE () {
  debug "Running core Cake commands to set sane defaults for ${LBLUE}MISP${NC}"

  # IF you have logged in prior to running this, it will fail but the fail is NON-blocking
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} userInit -q

  # This makes sure all Database upgrades are done, without logging in.
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin runUpdates

  # The default install is Python >=3.6 in a virtualenv, setting accordingly
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.python_bin" "${PATH_TO_MISP}/venv/bin/python"

  # Set default role
  # TESTME: The following seem defunct, please test.
  # ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} setDefaultRole 3

  # Tune global time outs
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Session.autoRegenerate" 0
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Session.timeout" 600
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Session.cookieTimeout" 3600
 
  # Set the default temp dir
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.tmpdir" "${PATH_TO_MISP}/app/tmp"

  # Change base url, either with this CLI command or in the UI
  [[ ! -z ${MISP_BASEURL} ]] && ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Baseurl $MISP_BASEURL
  # example: 'baseurl' => 'https://<your.FQDN.here>',
  # alternatively, you can leave this field empty if you would like to use relative pathing in MISP
  # 'baseurl' => '',
  # The base url of the application (in the format https://www.mymispinstance.com) as visible externally/by other MISPs.
  # MISP will encode this URL in sharing groups when including itself. If this value is not set, the baseurl is used as a fallback.
  [[ ! -z ${MISP_BASEURL} ]] && ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.external_baseurl" ${MISP_BASEURL}

  # Enable GnuPG
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "GnuPG.email" "${GPG_EMAIL_ADDRESS}"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "GnuPG.homedir" "${PATH_TO_MISP}/.gnupg"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "GnuPG.password" "${GPG_PASSPHRASE}"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "GnuPG.obscure_subject" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "GnuPG.key_fetching_disabled" false
  # FIXME: what if we have not gpg binary but a gpg2 one?
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "GnuPG.binary" "$(which gpg)"

  # LinOTP
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "LinOTPAuth.enabled" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "LinOTPAuth.baseUrl" "https://<your-linotp-baseUrl>"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "LinOTPAuth.realm" "lino"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "LinOTPAuth.verifyssl" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "LinOTPAuth.mixedauth" false

  # Enable installer org and tune some configurables
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.host_org_id" 1
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.email" "info@admin.test"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.disable_emailing" true --force
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.contact" "info@admin.test"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.disablerestalert" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.showCorrelationsOnIndex" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.default_event_tag_collection" 0

  # Provisional Cortex tunes
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Cortex_services_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Cortex_services_url" "http://127.0.0.1"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Cortex_services_port" 9000
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Cortex_timeout" 120
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Cortex_authkey" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Cortex_ssl_verify_peer" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Cortex_ssl_verify_host" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Cortex_ssl_allow_self_signed" true

  # Various plugin sightings settings
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Sightings_policy" 0
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Sightings_anonymise" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Sightings_anonymise_as" 1
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Sightings_range" 365
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Sightings_sighting_db_enable" false

  # TODO: Fix the below list
  # Set API_Required modules to false
  PLUGS=(Plugin.Enrichment_cuckoo_submit_enabled
         Plugin.Enrichment_vmray_submit_enabled
         Plugin.Enrichment_circl_passivedns_enabled
         Plugin.Enrichment_circl_passivessl_enabled
         Plugin.Enrichment_domaintools_enabled
         Plugin.Enrichment_eupi_enabled
         Plugin.Enrichment_farsight_passivedns_enabled
         Plugin.Enrichment_passivetotal_enabled
         Plugin.Enrichment_passivetotal_enabled
         Plugin.Enrichment_virustotal_enabled
         Plugin.Enrichment_whois_enabled
         Plugin.Enrichment_shodan_enabled
         Plugin.Enrichment_geoip_asn_enabled
         Plugin.Enrichment_geoip_city_enabled
         Plugin.Enrichment_geoip_country_enabled
         Plugin.Enrichment_iprep_enabled
         Plugin.Enrichment_otx_enabled
         Plugin.Enrichment_vulndb_enabled
         Plugin.Enrichment_crowdstrike_falcon_enabled
         Plugin.Enrichment_onyphe_enabled
         Plugin.Enrichment_xforceexchange_enabled
         Plugin.Enrichment_vulners_enabled
         Plugin.Enrichment_macaddress_io_enabled
         Plugin.Enrichment_intel471_enabled
         Plugin.Enrichment_backscatter_io_enabled
         Plugin.Enrichment_hibp_enabled
         Plugin.Enrichment_greynoise_enabled
         Plugin.Enrichment_joesandbox_submit_enabled
         Plugin.Enrichment_virustotal_public_enabled
         Plugin.Enrichment_apiosintds_enabled
         Plugin.Enrichment_urlscan_enabled
         Plugin.Enrichment_securitytrails_enabled
         Plugin.Enrichment_apivoid_enabled
         Plugin.Enrichment_assemblyline_submit_enabled
         Plugin.Enrichment_assemblyline_query_enabled
         Plugin.Enrichment_ransomcoindb_enabled
         Plugin.Enrichment_lastline_query_enabled
         Plugin.Enrichment_sophoslabs_intelix_enabled
         Plugin.Enrichment_cytomic_orion_enabled
         Plugin.Enrichment_censys_enrich_enabled
         Plugin.Enrichment_trustar_enrich_enabled
         Plugin.Enrichment_recordedfuture_enabled
         Plugin.ElasticSearch_logging_enable
         Plugin.S3_enable)
  for PLUG in "${PLUGS[@]}"; do
    ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting ${PLUG} false 2> /dev/null
  done

  # Plugin CustomAuth tuneable
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.CustomAuth_disable_logout" false

  # RPZ Plugin settings
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.RPZ_policy" "DROP"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.RPZ_walled_garden" "127.0.0.1"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.RPZ_serial" "\$date00"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.RPZ_refresh" "2h"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.RPZ_retry" "30m"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.RPZ_expiry" "30d"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.RPZ_minimum_ttl" "1h"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.RPZ_ttl" "1w"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.RPZ_ns" "localhost."
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.RPZ_ns_alt" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.RPZ_email" "root.localhost"

  # Kafka settings
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_brokers" "kafka:9092"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_rdkafka_config" "/etc/rdkafka.ini"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_include_attachments" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_event_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_event_notifications_topic" "misp_event"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_event_publish_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_event_publish_notifications_topic" "misp_event_publish"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_object_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_object_notifications_topic" "misp_object"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_object_reference_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_object_reference_notifications_topic" "misp_object_reference"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_attribute_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_attribute_notifications_topic" "misp_attribute"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_shadow_attribute_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_shadow_attribute_notifications_topic" "misp_shadow_attribute"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_tag_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_tag_notifications_topic" "misp_tag"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_sighting_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_sighting_notifications_topic" "misp_sighting"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_user_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_user_notifications_topic" "misp_user"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_organisation_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_organisation_notifications_topic" "misp_organisation"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_audit_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_audit_notifications_topic" "misp_audit"

  # ZeroMQ settings
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_host" "127.0.0.1"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_port" 50000
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_redis_host" "localhost"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_redis_port" 6379
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_redis_database" 1
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_redis_namespace" "mispq"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_event_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_object_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_object_reference_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_attribute_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_sighting_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_user_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_organisation_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_include_attachments" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_tag_notifications_enable" false

  # Force defaults to make MISP Server Settings less RED
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.language" "eng"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.proposals_block_attributes" false

  # Redis block
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.redis_host" "127.0.0.1"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.redis_port" 6379
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.redis_database" 13
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.redis_password" ""

  # Force defaults to make MISP Server Settings less YELLOW
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.ssdeep_correlation_threshold" 40
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.extended_alert_subject" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.default_event_threat_level" 4
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.newUserText" "Dear new MISP user,\\n\\nWe would hereby like to welcome you to the \$org MISP community.\\n\\n Use the credentials below to log into MISP at \$misp, where you will be prompted to manually change your password to something of your own choice.\\n\\nUsername: \$username\\nPassword: \$password\\n\\nIf you have any questions, don't hesitate to contact us at: \$contact.\\n\\nBest regards,\\nYour \$org MISP support team"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.passwordResetText" "Dear MISP user,\\n\\nA password reset has been triggered for your account. Use the below provided temporary password to log into MISP at \$misp, where you will be prompted to manually change your password to something of your own choice.\\n\\nUsername: \$username\\nYour temporary password: \$password\\n\\nIf you have any questions, don't hesitate to contact us at: \$contact.\\n\\nBest regards,\\nYour \$org MISP support team"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.enableEventBlocklisting" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.enableOrgBlocklisting" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.log_client_ip" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.log_auth" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.log_user_ips" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.log_user_ips_authkeys" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.disableUserSelfManagement" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.disable_user_login_change" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.disable_user_password_change" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.disable_user_add" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.block_event_alert" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.block_event_alert_tag" "no-alerts=\"true\""
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.block_old_event_alert" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.block_old_event_alert_age" ""
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.block_old_event_alert_by_date" ""
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.event_alert_republish_ban" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.event_alert_republish_ban_threshold" 5
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.event_alert_republish_ban_refresh_on_retry" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.incoming_tags_disabled_by_default" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.maintenance_message" "Great things are happening! MISP is undergoing maintenance, but will return shortly. You can contact the administration at \$email."
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.footermidleft" "This is an initial install"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.footermidright" "Please configure and harden accordingly"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.welcome_text_top" "Initial Install, please configure"
  # TODO: Make sure $FLAVOUR is correct
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.welcome_text_bottom" "Welcome to MISP on ${FLAVOUR}, change this message in MISP Settings"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.attachments_dir" "${PATH_TO_MISP}/app/files"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.download_attachments_on_load" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.event_alert_metadata_only" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.title_text" "MISP"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.terms_download" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.showorgalternate" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.event_view_filter_fields" "id, uuid, value, comment, type, category, Tag.name"

  # Force defaults to make MISP Server Settings less GREEN
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "debug" 0
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Security.auth_enforced" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Security.log_each_individual_auth_fail" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Security.rest_client_baseurl" ""
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Security.advanced_authkeys" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Security.password_policy_length" 12
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Security.password_policy_complexity" '/^((?=.*\d)|(?=.*\W+))(?![\n])(?=.*[A-Z])(?=.*[a-z]).*$|.{16,}/'
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Security.self_registration_message" "If you would like to send us a registration request, please fill out the form below. Make sure you fill out as much information as possible in order to ease the task of the administrators."

  # Appease the security audit, #hardening
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Security.disable_browser_cache" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Security.check_sec_fetch_site_header" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Security.csp_enforce" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Security.advanced_authkeys" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Security.do_not_log_authkeys" true

  # Appease the security audit, #loggin
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Security.username_in_response_header" true

  # It is possible to updateMISP too, only here for reference how to to that on the CLI.
  ## ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin updateMISP

  # Set MISP Live
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Live ${MISP_LIVE}
}

# This updates Galaxies, ObjectTemplates, Warninglists, Noticelists, Templates
updateGOWNT () {
  # AUTH_KEY Place holder in case we need to **curl** something in the future
  # 
  ${SUDO_WWW} ${RUN_MYSQL} -- mysql -h ${DBHOST} -u ${DBUSER_MISP} -p${DBPASSWORD_MISP} misp -e "SELECT authkey FROM users;" | tail -1 > /tmp/auth.key
  AUTH_KEY=$(cat /tmp/auth.key)
  rm /tmp/auth.key

  debug "Updating Galaxies, ObjectTemplates, Warninglists, Noticelists and Templates"
  # Update the galaxies…
  # TODO: Fix updateGalaxies
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin updateGalaxies
  # Updating the taxonomies…
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin updateTaxonomies
  # Updating the warning lists…
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin updateWarningLists
  # Updating the notice lists…
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin updateNoticeLists
  # Updating the object templates…
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin updateObjectTemplates "1337"
}
# <snippet-end 2_core-cake.sh>
```
