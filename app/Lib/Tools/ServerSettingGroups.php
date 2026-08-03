<?php

/**
 * Thematic grouping of the server settings 
 * 
 * Server::serverSettingsRead() only knows about *tabs* — and, for plugins, a
 * subGroup derived from the setting name. That leaves a tab such as Security
 * as one flat list of ~65 entries, which is what the legacy view renders.
 *
 * This class splits such a tab into sections so the UI can render one
 * accordion card per concern. A section carries:
 *   id           slug used for DOM ids
 *   title        card header
 *   description  one-line subtitle under the header
 *   icon         Font Awesome name, without the `fa-` prefix
 *   accent       CSS colour driving the icon tile / left border / tint
 *   settings     the setting names it owns, in the order they are declared
 *
 * Anything a section does not claim ends up in a catch-all section, so a
 * newly added setting is never silently hidden from the UI.
 *
 * The Plugin tab is the exception: most of its settings are generated at
 * runtime from the modules the misp-modules server advertises, so its sections
 * cannot be listed by hand. They are derived from the subGroup the model
 * already attaches to every plugin setting, and only their presentation
 * (title, description, icon, colour) is declared here — see $subGroupStyles.
 */
class ServerSettingGroups
{
    const FALLBACK_ID = 'other';

    /**
     * Sections per settings tab. Only the tabs that have been migrated to the
     * Overmind renderer need an entry here; the others fall back to a single
     * catch-all section.
     *
     * @var array
     */
    private static $groups = array(
        'SimpleBackgroundJobs' => array(
            array(
                'id' => 'jobs',
                'title' => 'Background processing',
                'description' => 'Whether jobs run in the background, and how long their history is kept',
                'icon' => 'gears',
                'accent' => '#198754',
                'settings' => array(
                    'SimpleBackgroundJobs.enabled',
                    'SimpleBackgroundJobs.max_job_history_ttl',
                ),
            ),
            array(
                'id' => 'jobs-redis',
                'title' => 'Redis backend',
                'description' => 'The Redis instance holding the job queues — separate from the generic MISP one',
                'icon' => 'database',
                'accent' => '#d63384',
                'settings' => array(
                    'SimpleBackgroundJobs.redis_host',
                    'SimpleBackgroundJobs.redis_port',
                    'SimpleBackgroundJobs.redis_database',
                    'SimpleBackgroundJobs.redis_password',
                    'SimpleBackgroundJobs.redis_namespace',
                    'SimpleBackgroundJobs.redis_serializer',
                ),
            ),
            array(
                'id' => 'supervisor',
                'title' => 'Supervisor',
                'description' => 'XML-RPC API MISP uses to start, stop and monitor its workers',
                'icon' => 'robot',
                'accent' => '#0d6efd',
                'settings' => array(
                    'SimpleBackgroundJobs.supervisor_host',
                    'SimpleBackgroundJobs.supervisor_port',
                    'SimpleBackgroundJobs.supervisor_user',
                    'SimpleBackgroundJobs.supervisor_password',
                ),
            ),
        ),
        'Proxy' => array(
            array(
                'id' => 'proxy-endpoint',
                'title' => 'Proxy endpoint',
                'description' => 'HTTP proxy used for outgoing requests — leave empty to connect directly',
                'icon' => 'plug',
                'accent' => '#0dcaf0',
                'settings' => array(
                    'Proxy.host',
                    'Proxy.port',
                ),
            ),
            array(
                'id' => 'proxy-authentication',
                'title' => 'Proxy authentication',
                'description' => 'Credentials presented to the proxy, when it requires them',
                'icon' => 'user-lock',
                'accent' => '#6f42c1',
                'settings' => array(
                    'Proxy.method',
                    'Proxy.user',
                    'Proxy.password',
                ),
            ),
        ),
        'Encryption' => array(
            array(
                'id' => 'gnupg',
                'title' => 'GnuPG key & binary',
                'description' => 'Where the instance PGP key lives and how keys are handled',
                'icon' => 'key',
                'accent' => '#6f42c1',
                'settings' => array(
                    'GnuPG.binary',
                    'GnuPG.homedir',
                    'GnuPG.email',
                    'GnuPG.password',
                    'GnuPG.key_fetching_disabled',
                    'GnuPG.restrict_server_signing_to_host_org',
                ),
            ),
            array(
                'id' => 'mail-encryption',
                'title' => 'E-mail encryption & signing',
                'description' => 'How outgoing notifications are signed and encrypted',
                'icon' => 'envelope',
                'accent' => '#198754',
                'settings' => array(
                    'GnuPG.sign',
                    'GnuPG.onlyencrypted',
                    'GnuPG.bodyonlyencrypted',
                    'GnuPG.obscure_subject',
                ),
            ),
            array(
                'id' => 'smime',
                'title' => 'S/MIME',
                'description' => 'X.509 certificate used as an alternative to PGP',
                'icon' => 'certificate',
                'accent' => '#0d6efd',
                'settings' => array(
                    'SMIME.enabled',
                    'SMIME.email',
                    'SMIME.cert_public_sign',
                    'SMIME.key_sign',
                    'SMIME.password',
                ),
            ),
        ),
        'MISP' => array(
            array(
                'id' => 'instance',
                'title' => 'Instance identity',
                'description' => 'How this instance names, locates and presents itself',
                'icon' => 'server',
                'accent' => '#0d6efd',
                'settings' => array(
                    'MISP.baseurl',
                    'MISP.external_baseurl',
                    'MISP.disable_baseurl_coercion',
                    'MISP.live',
                    'MISP.maintenance_message',
                    'MISP.uuid',
                    'MISP.org',
                    'MISP.host_org_id',
                    'MISP.showorg',
                    'MISP.showorgalternate',
                    'MISP.language',
                    'MISP.self_update',
                    'MISP.online_version_check',
                ),
            ),
            array(
                'id' => 'appearance',
                'title' => 'Look & feel',
                'description' => 'Themes, logos and the texts shown around the interface',
                'icon' => 'palette',
                'accent' => '#6f42c1',
                'settings' => array(
                    'MISP.enable_themes',
                    'MISP.default_theme',
                    'MISP.custom_css',
                    'MISP.title_text',
                    'MISP.footermidleft',
                    'MISP.footermidright',
                    'MISP.footer_logo',
                    'MISP.home_logo',
                    'MISP.main_logo',
                    'MISP.welcome_text_top',
                    'MISP.welcome_text_bottom',
                    'MISP.welcome_logo',
                    'MISP.welcome_logo2',
                    'MISP.menu_custom_right_link',
                    'MISP.menu_custom_right_link_html',
                    'MISP.terms_download',
                    'MISP.terms_file',
                ),
            ),
            array(
                'id' => 'display',
                'title' => 'Event & attribute display',
                'description' => 'What the event index and event view expose to users',
                'icon' => 'eye',
                'accent' => '#d63384',
                'settings' => array(
                    'MISP.full_tags_on_event_index',
                    'MISP.collapse_attribute_in_object',
                    'MISP.showCorrelationsOnIndex',
                    'MISP.showProposalsCountOnIndex',
                    'MISP.showSightingsCountOnIndex',
                    'MISP.showDiscussionsCountOnIndex',
                    'MISP.showEventReportCountOnIndex',
                    'MISP.event_view_filter_fields',
                    'MISP.use_uuids_in_urls',
                    'MISP.disable_threat_level',
                    'MISP.enableEventReportImageParsingRule',
                    'MISP.cveurl',
                    'MISP.cweurl',
                    'MISP.hide_unknown_cluster',
                    'MISP.warning_for_all',
                ),
            ),
            array(
                'id' => 'defaults',
                'title' => 'Default values',
                'description' => 'Distribution and classification applied to newly created data',
                'icon' => 'sliders',
                'accent' => '#fd7e14',
                'settings' => array(
                    'MISP.default_event_distribution',
                    'MISP.default_attribute_distribution',
                    'MISP.default_object_distribution',
                    'MISP.default_eventreport_distribution',
                    'MISP.default_analyst_data_distribution',
                    'MISP.default_galaxy_distribution',
                    'MISP.default_event_threat_level',
                    'MISP.default_event_tag_collection',
                    'MISP.default_publish_alert',
                    'MISP.unpublishedprivate',
                ),
            ),
            array(
                'id' => 'features',
                'title' => 'Features & workflow',
                'description' => 'Platform capabilities that can be turned on or off',
                'icon' => 'toggle-on',
                'accent' => '#20c997',
                'settings' => array(
                    'MISP.tagging',
                    'MISP.incoming_tags_disabled_by_default',
                    'MISP.disable_taxonomy_consistency_checks',
                    'MISP.delegation',
                    'MISP.discussion_disable',
                    'MISP.proposals_block_attributes',
                    'MISP.take_ownership_xml_import',
                    'MISP.allow_users_override_locked_field_when_importing_events',
                    'MISP.enableEventBlocklisting',
                    'MISP.enableOrgBlocklisting',
                    'MISP.enableSightingBlocklisting',
                    'MISP.enable_clusters_mirroring_from_attributes_to_event',
                    'MISP.block_publishing_for_same_creator',
                    'MISP.enable_synchronisation_filtering_on_type',
                ),
            ),
            array(
                'id' => 'correlation',
                'title' => 'Correlation',
                'description' => 'Correlation engine, thresholds and visibility',
                'icon' => 'diagram-project',
                'accent' => '#0dcaf0',
                'settings' => array(
                    'MISP.correlation_engine',
                    'MISP.correlation_limit',
                    'MISP.correlation_chunk_size',
                    'MISP.enable_advanced_correlations',
                    'MISP.ssdeep_correlation_threshold',
                    'MISP.max_correlations_per_event',
                    'MISP.completely_disable_correlation',
                    'MISP.allow_disabling_correlation',
                    'MISP.show_server_correlations_for_all_users',
                ),
            ),
            array(
                'id' => 'emailing',
                'title' => 'E-mailing & notifications',
                'description' => 'Outgoing mail, alert subjects and alert throttling',
                'icon' => 'envelope',
                'accent' => '#198754',
                'settings' => array(
                    'MISP.email',
                    'MISP.disable_emailing',
                    'MISP.email_from_name',
                    'MISP.email_reply_to',
                    'MISP.contact',
                    'MISP.threatlevel_in_email_subject',
                    'MISP.email_subject_TLP_string',
                    'MISP.email_subject_tag',
                    'MISP.email_subject_include_tag_name',
                    'MISP.extended_alert_subject',
                    'MISP.event_alert_metadata_only',
                    'MISP.publish_alerts_summary_only',
                    'MISP.disablerestalert',
                    'MISP.block_event_alert',
                    'MISP.block_event_alert_tag',
                    'MISP.event_alert_republish_ban',
                    'MISP.event_alert_republish_ban_threshold',
                    'MISP.event_alert_republish_ban_refresh_on_retry',
                    'MISP.user_email_notification_ban',
                    'MISP.user_email_notification_ban_time_threshold',
                    'MISP.user_email_notification_ban_amount_threshold',
                    'MISP.org_alert_threshold',
                    'MISP.block_old_event_alert',
                    'MISP.block_old_event_alert_age',
                    'MISP.block_old_event_alert_by_date',
                    'MISP.newUserText',
                    'MISP.passwordResetText',
                    'MISP.forgotPasswordText',
                    'MISP.forgotPasswordTextNoEnc',
                ),
            ),
            array(
                'id' => 'users',
                'title' => 'User accounts & sessions',
                'description' => 'What users may change about their own account',
                'icon' => 'users',
                'accent' => '#6610f2',
                'settings' => array(
                    'MISP.disableUserSelfManagement',
                    'MISP.disable_user_login_change',
                    'MISP.disable_user_password_change',
                    'MISP.disable_user_add',
                    'MISP.disable_auto_logout',
                    'MISP.forceHTTPSforPreLoginRequestedURL',
                ),
            ),
            array(
                'id' => 'logging',
                'title' => 'Logging & audit',
                'description' => 'What gets recorded, how verbosely and where',
                'icon' => 'clipboard-list',
                'accent' => '#795548',
                'settings' => array(
                    'MISP.log_client_ip',
                    'MISP.log_client_ip_header',
                    'MISP.store_api_access_time',
                    'MISP.log_auth',
                    'MISP.log_skip_db_logs_completely',
                    'MISP.log_skip_access_logs_in_application_logs',
                    'MISP.log_paranoid',
                    'MISP.log_paranoid_api',
                    'MISP.log_paranoid_skip_db',
                    'MISP.log_paranoid_include_post_body',
                    'MISP.log_paranoid_include_sql_queries',
                    'MISP.log_user_ips',
                    'MISP.log_user_ips_authkeys',
                    'MISP.log_errors_ndjson',
                    'MISP.log_errors_ndjson_path',
                    'MISP.disable_seen_ips_authkeys',
                    'MISP.log_new_audit',
                    'MISP.log_new_audit_compress',
                ),
            ),
            array(
                'id' => 'performance',
                'title' => 'Performance & limits',
                'description' => 'Memory envelopes, timeouts and fetch limits',
                'icon' => 'gauge-high',
                'accent' => '#b8860b',
                'settings' => array(
                    'MISP.default_attribute_memory_coefficient',
                    'MISP.default_event_memory_divisor',
                    'MISP.object_fetch_hard_limit',
                    'MISP.event_index_pull_chunk_size',
                    'MISP.curl_request_timeout',
                    'MISP.disable_sighting_loading',
                    'MISP.disable_event_locks',
                    'MISP.enable_automatic_garbage_collection',
                    'MISP.disable_cached_exports',
                    'MISP.deadlock_avoidance',
                    'MISP.updateTimeThreshold',
                    'MISP.default_restsearch_limit',
                    'MISP.attribute_filters_block_only',
                    'MISP.fetchAttributeLegacyStrategy',
                ),
            ),
            array(
                'id' => 'storage',
                'title' => 'Storage & attachments',
                'description' => 'Where files live and how they are scanned',
                'icon' => 'paperclip',
                'accent' => '#495057',
                'settings' => array(
                    'MISP.attachments_dir',
                    'MISP.attachments_bucketed',
                    'MISP.download_attachments_on_load',
                    'MISP.attachment_scan_module',
                    'MISP.attachment_scan_hash_only',
                    'MISP.attachment_scan_timeout',
                    'MISP.tmpdir',
                    'MISP.thumbnail_in_redis',
                ),
            ),
            array(
                'id' => 'system',
                'title' => 'System, Redis & workers',
                'description' => 'Paths, binaries, the generic Redis instance and job processing',
                'icon' => 'gears',
                'accent' => '#6c757d',
                'settings' => array(
                    'MISP.python_bin',
                    'MISP.ca_path',
                    'MISP.osuser',
                    'MISP.redis_host',
                    'MISP.redis_port',
                    'MISP.redis_database',
                    'MISP.redis_password',
                    'MISP.redis_serializer',
                    'MISP.background_jobs',
                    'MISP.manage_workers',
                    'MISP.system_setting_db',
                    'MISP.server_settings_skip_backup_rotate',
                    'MISP.download_gpg_from_homedir',
                ),
            ),
            array(
                'id' => 'deprecated',
                'title' => 'Deprecated',
                'description' => 'Settings that no longer do anything and can be safely removed',
                'icon' => 'box-archive',
                'accent' => '#adb5bd',
                'settings' => array(
                    'MISP.name',
                    'MISP.version',
                    'MISP.header',
                    'MISP.footer',
                    'MISP.footerpart1',
                    'MISP.footerpart2',
                    'MISP.footerversion',
                    'MISP.logo',
                    'MISP.dns',
                    'MISP.taxii_sync',
                    'MISP.taxii_client_path',
                ),
            ),
        ),
        'Security' => array(
            array(
                'id' => 'authentication',
                'title' => 'Authentication & Sessions',
                'description' => 'Login process and session management configuration',
                'icon' => 'right-to-bracket',
                'accent' => '#6f42c1',
                'settings' => array(
                    'SecureAuth.amount',
                    'SecureAuth.expire',
                    'Security.alert_on_suspicious_logins',
                    'Security.log_each_individual_auth_fail',
                    'Security.allow_self_registration',
                    'Security.allow_password_forgotten',
                    'Security.self_registration_message',
                    'Security.require_password_confirmation',
                    'Security.auth_enforced',
                    'Security.authkey_keep_session',
                    'Security.otp_disabled',
                    'Security.otp_required',
                    'Security.otp_issuer',
                    'Session.defaults',
                    'Session.timeout',
                    'Session.cookieTimeout',
                    'Session.autoRegenerate',
                    'Session.checkAgent',
                ),
            ),
            array(
                'id' => 'authkeys',
                'title' => 'API & Auth Keys',
                'description' => 'API authentication and authorization key management',
                'icon' => 'key',
                'accent' => '#198754',
                'settings' => array(
                    'Security.advanced_authkeys',
                    'Security.advanced_authkeys_validity',
                    'Security.mandate_ip_allowlist_advanced_authkeys',
                    'Security.api_key_quick_lookup',
                    'Security.api_key_quick_lookup_expiration',
                    'Security.allow_unsafe_apikey_named_param',
                    'Security.allow_unsafe_cleartext_apikey_logging',
                    'Security.do_not_log_authkeys',
                    'Security.rest_client_enable_arbitrary_urls',
                    'Security.rest_client_baseurl',
                    'Security.workflow_enable_arbitrary_urls',
                    'Security.eventreport_enable_arbitrary_urls',
                ),
            ),
            array(
                'id' => 'mfa',
                'title' => 'Multi-Factor Authentication (MFA)',
                'description' => 'One-time password configuration for enhanced security',
                'icon' => 'mobile-screen-button',
                'accent' => '#d63384',
                'settings' => array(
                    'Security.email_otp_enabled',
                    'Security.email_otp_length',
                    'Security.email_otp_validity',
                    'Security.email_otp_text',
                    'Security.email_otp_exceptions',
                    'LinOTPAuth.enabled',
                    'LinOTPAuth.baseUrl',
                    'LinOTPAuth.realm',
                    'LinOTPAuth.verifyssl',
                    'LinOTPAuth.mixedauth',
                ),
            ),
            array(
                'id' => 'password',
                'title' => 'Password Policy',
                'description' => 'Password strength and complexity requirements',
                'icon' => 'lock',
                'accent' => '#dc3545',
                'settings' => array(
                    'Security.password_policy_length',
                    'Security.password_policy_complexity',
                ),
            ),
            array(
                'id' => 'access-control',
                'title' => 'Access Control & User Visibility',
                'description' => 'User permissions and information disclosure settings',
                'icon' => 'user-shield',
                'accent' => '#0d6efd',
                'settings' => array(
                    'Security.limit_site_admins_to_host_org',
                    'Security.hide_organisation_index_from_users',
                    'Security.hide_organisations_in_sharing_groups',
                    'Security.disclose_user_emails',
                    'Security.disable_local_feed_access',
                    'Security.disable_instance_file_uploads',
                    'Security.sanitise_attribute_on_delete',
                    'Security.enable_svg_logos',
                ),
            ),
            array(
                'id' => 'http',
                'title' => 'HTTP & Browser Security',
                'description' => 'Web security headers and browser-level protections',
                'icon' => 'globe',
                'accent' => '#0dcaf0',
                'settings' => array(
                    'Security.csp_enforce',
                    'Security.disable_browser_cache',
                    'Security.check_sec_fetch_site_header',
                    'Security.allow_cors',
                    'Security.cors_origins',
                    'Security.force_https',
                    'Security.username_in_response_header',
                    'Security.user_org_uuid_in_response_header',
                ),
            ),
            array(
                'id' => 'logging',
                'title' => 'Logging, Audit & Monitoring',
                'description' => 'System logging, auditing, and activity monitoring',
                'icon' => 'clipboard-list',
                'accent' => '#20c997',
                'settings' => array(
                    'Security.syslog',
                    'Security.syslog_json_format',
                    'Security.syslog_to_stderr',
                    'Security.syslog_ident',
                    'Security.sync_audit',
                    'Security.user_monitoring_enabled',
                    'debug',
                    'site_admin_debug',
                ),
            ),
            array(
                'id' => 'encryption',
                'title' => 'Encryption & Cryptography',
                'description' => 'Data protection at rest and in transit',
                'icon' => 'shield-halved',
                'accent' => '#6610f2',
                'settings' => array(
                    'Security.encryption_key',
                    'Security.min_tls_version',
                ),
            ),
        ),
    );

    /**
     * Tabs whose sections are the subGroups the model computed, rather than a
     * hand-written list. The value is the order the sections appear in; any
     * subGroup not listed (a brand new plugin family) is appended after them.
     *
     * @var array
     */
    private static $subGroupTabs = array(
        'Plugin' => array(
            'Enrichment', 'Import', 'Export', 'Cortex', 'Action', 'Workflow',
            'ZeroMQ', 'Kafka', 'ElasticSearch', 'S3', 'RPZ', 'Sightings',
            'CustomAuth', 'Geolocation', 'CyCat', 'CTIInfoExtractor', 'Benchmarking',
        ),
    );

    /**
     * Presentation of each known subGroup. A subGroup with no entry here still
     * gets a section — it just falls back to a neutral title and colour.
     *
     * @var array
     */
    private static $subGroupStyles = array(
        'Enrichment' => array(
            'title' => 'Enrichment modules',
            'description' => 'Hover and expansion modules adding context to attributes',
            'icon' => 'wand-magic-sparkles',
            'accent' => '#6f42c1',
        ),
        'Import' => array(
            'title' => 'Import modules',
            'description' => 'Modules turning external formats into MISP data',
            'icon' => 'file-import',
            'accent' => '#198754',
        ),
        'Export' => array(
            'title' => 'Export modules',
            'description' => 'Modules rendering MISP data into external formats',
            'icon' => 'file-export',
            'accent' => '#0d6efd',
        ),
        'Cortex' => array(
            'title' => 'Cortex',
            'description' => 'Cortex analyzers reachable from this instance',
            'icon' => 'microscope',
            'accent' => '#d63384',
        ),
        'Action' => array(
            'title' => 'Action modules',
            'description' => 'Modules a workflow can trigger to act on external systems',
            'icon' => 'bolt',
            'accent' => '#fd7e14',
        ),
        'Workflow' => array(
            'title' => 'Workflows',
            'description' => 'Workflow engine and the triggers it listens to',
            'icon' => 'diagram-project',
            'accent' => '#20c997',
        ),
        'ZeroMQ' => array(
            'title' => 'ZeroMQ',
            'description' => 'Real-time publishing of MISP activity over ZeroMQ',
            'icon' => 'tower-broadcast',
            'accent' => '#0dcaf0',
        ),
        'Kafka' => array(
            'title' => 'Kafka',
            'description' => 'Publishing MISP activity to Kafka topics',
            'icon' => 'paper-plane',
            'accent' => '#795548',
        ),
        'ElasticSearch' => array(
            'title' => 'Elasticsearch',
            'description' => 'Shipping logs to an Elasticsearch cluster',
            'icon' => 'magnifying-glass-chart',
            'accent' => '#b8860b',
        ),
        'S3' => array(
            'title' => 'S3 attachment storage',
            'description' => 'Storing attachments in an S3 compatible bucket',
            'icon' => 'cloud',
            'accent' => '#6610f2',
        ),
        'RPZ' => array(
            'title' => 'RPZ export',
            'description' => 'Response Policy Zone file generation',
            'icon' => 'shield-halved',
            'accent' => '#495057',
        ),
        'Sightings' => array(
            'title' => 'Sightings',
            'description' => 'How sightings are collected, anonymised and exposed',
            'icon' => 'eye',
            'accent' => '#0dcaf0',
        ),
        'CustomAuth' => array(
            'title' => 'Custom authentication',
            'description' => 'Authentication delegated to a header-setting reverse proxy',
            'icon' => 'id-badge',
            'accent' => '#6f42c1',
        ),
        'Geolocation' => array(
            'title' => 'Geolocation',
            'description' => 'Interactive map for geolocation objects',
            'icon' => 'map-location-dot',
            'accent' => '#198754',
        ),
        'CyCat' => array(
            'title' => 'CyCat',
            'description' => 'Lookups against the CyCat cybersecurity catalogue',
            'icon' => 'diagram-predecessor',
            'accent' => '#fd7e14',
        ),
        'CTIInfoExtractor' => array(
            'title' => 'CTI info extractor',
            'description' => 'Extraction of indicators out of free text',
            'icon' => 'highlighter',
            'accent' => '#20c997',
        ),
        'Benchmarking' => array(
            'title' => 'Benchmarking',
            'description' => 'Collection of performance counters',
            'icon' => 'gauge-high',
            'accent' => '#d63384',
        ),
    );

    /**
     * Settings that the UI never lists. Security.salt cannot be changed from
     * the interface and exposing it — even redacted — has no value, which is
     * why the legacy renderer skips it too.
     *
     * @var array
     */
    private static $hidden = array('Security.salt');

    /**
     * Every section of the server settings page, in the order the tab bar
     * shows them.
     *
     * The `tab` value is the pass argument ServersController::serverSettings()
     * expects, and therefore also the ajax fragment URL.
     *
     * @return array
     */
    public static function tabs()
    {
        return array(
            array('tab' => 'MISP', 'title' => __('MISP'), 'icon' => 'fas fa-sliders'),
            array('tab' => 'Encryption', 'title' => __('Encryption'), 'icon' => 'fas fa-lock'),
            array('tab' => 'Proxy', 'title' => __('Proxy'), 'icon' => 'fas fa-network-wired'),
            array('tab' => 'Security', 'title' => __('Security'), 'icon' => 'fas fa-shield-halved'),
            array('tab' => 'Plugin', 'title' => __('Plugins'), 'icon' => 'fas fa-puzzle-piece'),
            array('tab' => 'SimpleBackgroundJobs', 'title' => __('Background jobs'), 'icon' => 'fas fa-gears'),
            array('tab' => 'correlations', 'title' => __('Correlations'), 'icon' => 'fas fa-diagram-project'),
            array('tab' => 'diagnostics', 'title' => __('Diagnostics'), 'icon' => 'fas fa-stethoscope'),
            array('tab' => 'files', 'title' => __('Manage files'), 'icon' => 'fas fa-folder-open'),
            array('tab' => 'workers', 'title' => __('Workers'), 'icon' => 'fas fa-robot'),
        );
    }

    /**
     * @param string|false $tab
     * @return bool True when $tab designates one of the sections above.
     */
    public static function isKnownTab($tab)
    {
        foreach (self::tabs() as $definition) {
            if ($definition['tab'] === $tab) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param string $tab
     * @return bool True when $tab knows how to lay its settings out in sections.
     */
    public static function hasGroups($tab)
    {
        return isset(self::$groups[$tab]) || isset(self::$subGroupTabs[$tab]);
    }

    /**
     * @param string $tab
     * @return array Section definitions (without their settings).
     */
    public static function definitions($tab)
    {
        return isset(self::$groups[$tab]) ? self::$groups[$tab] : array();
    }

    /**
     * @param string $settingName
     * @return bool
     */
    public static function isHidden($settingName)
    {
        return in_array($settingName, self::$hidden, true);
    }

    /**
     * Label and glyph of each severity level, shared by the setting rows and
     * the per-section counters so both read the same.
     *
     * @return array
     */
    public static function levels()
    {
        return array(
            0 => array('label' => __('Critical'), 'icon' => 'triangle-exclamation'),
            1 => array('label' => __('Recommended'), 'icon' => 'circle-exclamation'),
            2 => array('label' => __('Optional'), 'icon' => 'circle-info'),
            3 => array('label' => __('Deprecated'), 'icon' => 'ban'),
        );
    }

    /**
     * Distribute a tab's settings over its sections.
     *
     * Sections keep their declared order; inside a section the settings keep
     * the order they arrive in (Server::serverSettingsRead() sorts them by
     * severity, so criticals come first). Empty sections are dropped and
     * unclaimed settings are collected in a trailing catch-all section.
     *
     * @param string $tab
     * @param array $settings Flat list of settings as returned for the tab,
     *                        each carrying at least a `setting` key.
     * @return array Sections, each with a `settings` list and an `errors` count.
     */
    public static function split($tab, array $settings)
    {
        if (isset(self::$subGroupTabs[$tab])) {
            return self::splitBySubGroup($tab, $settings);
        }

        $byName = array();
        foreach ($settings as $setting) {
            if (empty($setting['setting']) || self::isHidden($setting['setting'])) {
                continue;
            }
            $byName[$setting['setting']] = $setting;
        }

        $sections = array();
        foreach (self::definitions($tab) as $definition) {
            $owned = array();
            foreach ($definition['settings'] as $name) {
                if (isset($byName[$name])) {
                    $owned[] = $byName[$name];
                    unset($byName[$name]);
                }
            }
            if (empty($owned)) {
                continue;
            }
            $definition['settings'] = $owned;
            $sections[] = self::withCounters($definition);
        }

        if (!empty($byName)) {
            $sections[] = self::withCounters(array(
                'id' => self::FALLBACK_ID,
                'title' => empty($sections) ? __('Settings') : __('Other settings'),
                'description' => __('Settings that do not belong to any of the sections above'),
                'icon' => 'sliders',
                'accent' => '#6c757d',
                'settings' => array_values($byName),
            ));
        }

        return $sections;
    }

    /**
     * Build the sections of a subGroup-driven tab (Plugin).
     *
     * The subGroup travels with each setting — Server::__serverSettingsRead()
     * derives it from the part of the name before the first underscore — so
     * the sections follow whatever plugin families the instance actually has,
     * including the module settings misp-modules generates at runtime.
     *
     * Declared subGroups come first, in $subGroupTabs order; anything else is
     * appended alphabetically with a neutral style.
     *
     * @param string $tab
     * @param array $settings
     * @return array
     */
    private static function splitBySubGroup($tab, array $settings)
    {
        $bySubGroup = array();
        foreach ($settings as $setting) {
            if (empty($setting['setting']) || self::isHidden($setting['setting'])) {
                continue;
            }
            $bySubGroup[self::subGroupOf($setting)][] = $setting;
        }

        $order = self::$subGroupTabs[$tab];
        $unknown = array_diff(array_keys($bySubGroup), $order);
        sort($unknown);

        $sections = array();
        foreach (array_merge($order, $unknown) as $subGroup) {
            if (empty($bySubGroup[$subGroup])) {
                continue;
            }
            $style = isset(self::$subGroupStyles[$subGroup])
                ? self::$subGroupStyles[$subGroup]
                : array(
                    'title' => $subGroup,
                    'description' => __('Settings of the %s plugin', $subGroup),
                    'icon' => 'puzzle-piece',
                    'accent' => '#6c757d',
                );
            $sections[] = self::withCounters(array(
                'id' => strtolower($subGroup),
                'title' => $style['title'],
                'description' => $style['description'],
                'icon' => $style['icon'],
                'accent' => $style['accent'],
                'settings' => $bySubGroup[$subGroup],
            ));
        }

        return $sections;
    }

    /**
     * The subGroup a setting belongs to. Prefers the one the model computed,
     * and falls back to the same derivation for settings that reach the view
     * without it.
     *
     * @param array $setting
     * @return string
     */
    private static function subGroupOf(array $setting)
    {
        if (!empty($setting['subGroup'])) {
            return $setting['subGroup'];
        }
        $leaf = strpos($setting['setting'], '.') === false
            ? $setting['setting']
            : explode('.', $setting['setting'], 2)[1];

        return explode('_', $leaf)[0];
    }

    /**
     * Attach the per-section counters the card header displays: how many of
     * the section's settings are incorrectly set (or not set at all), broken
     * down by severity. Deprecated settings are never counted, as the tab
     * badges don't count them either.
     *
     * @param array $section
     * @return array With `errorsByLevel` => [0 => int, 1 => int, 2 => int].
     */
    private static function withCounters(array $section)
    {
        $errorsByLevel = array(0 => 0, 1 => 0, 2 => 0);
        foreach ($section['settings'] as $setting) {
            if (!isset($setting['error']) || $setting['level'] >= 3) {
                continue;
            }
            $errorsByLevel[$setting['level']]++;
        }
        $section['errorsByLevel'] = $errorsByLevel;

        return $section;
    }
}
