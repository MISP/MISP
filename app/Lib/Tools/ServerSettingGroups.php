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
 *
 * On top of the sections sits the page's navigation: destinations() routes
 * every section to one page of the sidebar (Instance, Users & access, …),
 * independently of the tab Server files the setting under.
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
                    'Security.pre_auth_flood_filter_enable',
                    'Security.pre_auth_flood_filter_threshold',
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
                    'Security.eventreport_max_fetch_size',
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
        'AI' => array(
            array(
                'id' => 'ai-connection',
                'title' => 'Connection',
                'description' => 'The misp-modules server running the ai_connector module, and how MISP reaches it',
                'icon' => 'plug',
                'accent' => '#0d6efd',
                'settings' => array(
                    'Plugin.AI_services_enable',
                    'Plugin.AI_services_url',
                    'Plugin.AI_services_port',
                    'Plugin.AI_timeout',
                    'Plugin.AI_ssl_verify_peer',
                    'Plugin.AI_ssl_verify_host',
                    'Plugin.AI_ssl_allow_self_signed',
                    'Plugin.AI_ssl_cafile',
                ),
            ),
            array(
                'id' => 'ai-model',
                'title' => 'Model',
                'description' => 'The LLM endpoint and model the module queries, passed with every request',
                'icon' => 'brain',
                'accent' => '#6f42c1',
                'settings' => array(
                    'Plugin.AI_openai_api_base',
                    'Plugin.AI_api_key',
                    'Plugin.AI_model_id',
                    'Plugin.AI_temperature',
                    'Plugin.AI_request_timeout',
                ),
            ),
            array(
                'id' => 'ai-tags',
                'title' => 'Tag recommendation',
                'description' => 'How many tags the module may recommend for an event, and the confidence it needs',
                'icon' => 'tags',
                'accent' => '#fd7e14',
                'settings' => array(
                    'Plugin.AI_suggest_limit',
                    'Plugin.AI_suggest_min_score',
                ),
            ),
            array(
                'id' => 'ai-extraction',
                'title' => 'Indicator extraction',
                'description' => 'The confidence the module needs before an indicator read out of an event report is kept',
                'icon' => 'magnifying-glass',
                'accent' => '#198754',
                'settings' => array(
                    'Plugin.AI_min_confidence',
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
            'CustomAuth', 'Geolocation', 'CyCat', 'Benchmarking',
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
     * Module families whose settings misp-modules generates per module
     * (`Plugin.<Family>_<module>_<param>`). Their pages show a module grid.
     *
     * @var array
     */
    private static $moduleFamilies = array('Enrichment', 'Import', 'Export', 'Action');

    /**
     * The settings the Overview lists as Essentials, with the label shown
     * there. Most instances have to get every one of them right.
     *
     * @return array setting name => label
     */
    public static function essentials()
    {
        return array(
            'MISP.baseurl' => __('Base URL'),
            'MISP.external_baseurl' => __('External base URL'),
            'MISP.live' => __('Instance live'),
            'MISP.uuid' => __('Instance UUID'),
            'MISP.host_org_id' => __('Host organisation'),
            'MISP.email' => __('Instance e-mail'),
            'MISP.contact' => __('Contact e-mail'),
            'MISP.disable_emailing' => __('Disable e-mailing'),
            'MISP.background_jobs' => __('Background jobs'),
            'MISP.default_event_distribution' => __('Default event distribution'),
            'MISP.language' => __('Interface language'),
            'Security.advanced_authkeys' => __('Advanced auth keys'),
            'Security.password_policy_length' => __('Minimum password length'),
            'GnuPG.email' => __('Signing key e-mail'),
            'Plugin.Enrichment_services_enable' => __('Enrichment services'),
        );
    }

    /**
     * How prominent a setting is: essential ones are on the Overview,
     * standard ones are shown in their section, advanced ones only on demand,
     * deprecated ones only through search and All settings.
     *
     * @param array $setting
     * @return string essential|standard|advanced|deprecated
     */
    public static function tier(array $setting)
    {
        if (isset(self::essentials()[$setting['setting']])) {
            return 'essential';
        }
        if ($setting['level'] >= 3) {
            return 'deprecated';
        }
        return $setting['level'] == 2 ? 'advanced' : 'standard';
    }

    /**
     * Every page of the settings navigation that does not depend on the
     * instance. `sources` routes the sections of the tabs Server knows about:
     * "Tab:section" claims one section, "Tab:*" whatever the tab has left.
     *
     * @return array id => definition
     */
    private static function fixedDestinations()
    {
        return array(
            'overview' => array(
                'group' => 'top', 'kind' => 'overview', 'icon' => 'gauge-high', 'accent' => '#1892B1',
                'title' => __('Overview'),
                'description' => __('What needs attention, the health of the system and the essential settings'),
            ),
            'instance' => array(
                'group' => 'config', 'kind' => 'settings', 'icon' => 'sliders', 'accent' => '#0d6efd',
                'title' => __('Instance'),
                'description' => __('Identity, appearance, display, performance and storage of this instance'),
                'sources' => array('MISP:instance', 'MISP:appearance', 'MISP:display', 'MISP:performance',
                    'MISP:storage', 'MISP:system', 'MISP:*', 'MISP:deprecated'),
            ),
            'users' => array(
                'group' => 'config', 'kind' => 'settings', 'icon' => 'users', 'accent' => '#6f42c1',
                'title' => __('Users & access'),
                'description' => __('Who can sign in, how, and what they get to see'),
                'sources' => array('Security:authentication', 'Security:authkeys', 'Security:mfa',
                    'Security:password', 'Security:access-control', 'MISP:users', 'Security:*'),
            ),
            'sharing' => array(
                'group' => 'config', 'kind' => 'settings', 'icon' => 'share-nodes', 'accent' => '#fd7e14',
                'title' => __('Sharing & data'),
                'description' => __('Defaults applied to new data, the features around it and correlation'),
                'sources' => array('MISP:defaults', 'MISP:features', 'MISP:correlation'),
            ),
            'mail' => array(
                'group' => 'config', 'kind' => 'settings', 'icon' => 'envelope', 'accent' => '#198754',
                'title' => __('Mail & encryption'),
                'description' => __('Outgoing notifications, and the PGP and S/MIME keys that sign them'),
                'sources' => array('MISP:emailing', 'Encryption:*'),
            ),
            'network' => array(
                'group' => 'config', 'kind' => 'settings', 'icon' => 'network-wired', 'accent' => '#0dcaf0',
                'title' => __('Network & HTTP'),
                'description' => __('Outgoing proxy, browser-facing protections and TLS'),
                'sources' => array('Proxy:*', 'Security:http', 'Security:encryption'),
            ),
            'logging' => array(
                'group' => 'config', 'kind' => 'settings', 'icon' => 'clipboard-list', 'accent' => '#795548',
                'title' => __('Logging & audit'),
                'description' => __('What gets recorded, how verbosely and where it is sent'),
                'sources' => array('MISP:logging', 'Security:logging'),
            ),
            'integrations' => array(
                'group' => 'config', 'kind' => 'integrations', 'icon' => 'puzzle-piece', 'accent' => '#48435C',
                'title' => __('Integrations'),
                'description' => __('misp-modules, message buses, external storage and the other plugins'),
            ),
            'ai' => array(
                'group' => 'config', 'kind' => 'settings', 'icon' => 'robot', 'accent' => '#8B5CF6',
                'title' => __('AI'),
                'description' => __('The LLM the ai_connector module queries, and what MISP asks of it'),
                'sources' => array('AI:*'),
            ),
            'jobs' => array(
                'group' => 'operations', 'kind' => 'settings', 'icon' => 'gears', 'accent' => '#198754',
                'title' => __('Background jobs'),
                'description' => __('The job queues, the workers that drain them and the services behind them'),
                'sources' => array('SimpleBackgroundJobs:*'),
                'probes' => array('workers'),
            ),
            'correlations' => array(
                'group' => 'operations', 'kind' => 'correlations', 'icon' => 'diagram-project', 'accent' => '#E67F0D',
                'title' => __('Correlations'),
                'description' => __('Correlation engines, their tables and the room they have left'),
            ),
            'files' => array(
                'group' => 'operations', 'kind' => 'files', 'icon' => 'folder-open', 'accent' => '#495057',
                'title' => __('Files'),
                'description' => __('Logos and other files uploaded to this instance'),
            ),
            'version' => array(
                'group' => 'health', 'kind' => 'health', 'icon' => 'code-branch', 'accent' => '#0d6efd',
                'title' => __('Version & updates'),
                'description' => __('Installed version, the latest release and the update tools'),
                'probes' => array('version'),
            ),
            'php' => array(
                'group' => 'health', 'kind' => 'health', 'icon' => 'code', 'accent' => '#20c997',
                'title' => __('PHP & filesystem'),
                'description' => __('Runtime, extensions, dependencies and file permissions'),
                'probes' => array('php', 'filesystem'),
            ),
            'database' => array(
                'group' => 'health', 'kind' => 'health', 'icon' => 'database', 'accent' => '#0dcaf0',
                'title' => __('Database'),
                'description' => __('Schema and migrations, space usage and server configuration'),
                'probes' => array('dbSchema', 'dbSpace', 'dbConfig'),
            ),
            'redis' => array(
                'group' => 'health', 'kind' => 'health', 'icon' => 'server', 'accent' => '#d63384',
                'title' => __('Redis'),
                'description' => __('Cache, job queues and correlation helpers'),
                'probes' => array('redis'),
            ),
            'services' => array(
                'group' => 'health', 'kind' => 'health', 'icon' => 'plug', 'accent' => '#198754',
                'title' => __('Services'),
                'description' => __('External tooling, misp-modules and the STIX libraries'),
                'probes' => array('services', 'modules', 'stix'),
            ),
            'audit' => array(
                'group' => 'health', 'kind' => 'health', 'icon' => 'shield-halved', 'accent' => '#dc3545',
                'title' => __('Security audit'),
                'description' => __('Configuration weaknesses MISP can detect on its own'),
                'probes' => array('audit'),
            ),
            'maintenance' => array(
                'group' => 'health', 'kind' => 'maintenance', 'icon' => 'screwdriver-wrench', 'accent' => '#495057',
                'title' => __('Maintenance tools'),
                'description' => __('One-off checks and clean-up routines'),
            ),
            'all' => array(
                'group' => 'bottom', 'kind' => 'all', 'icon' => 'list', 'accent' => '#6c757d',
                'title' => __('All settings'),
                'description' => __('Every setting of the instance, advanced and deprecated ones included'),
            ),
        );
    }

    /**
     * The tab names (and the non-settings tabs) the page used to be split in,
     * which links, redirects and bookmarks still carry.
     *
     * @var array
     */
    private static $aliases = array(
        'MISP' => 'instance',
        'Encryption' => 'mail',
        'Proxy' => 'network',
        'Security' => 'users',
        'Plugin' => 'integrations',
        'AI' => 'ai',
        'SimpleBackgroundJobs' => 'jobs',
        'workers' => 'jobs',
        'diagnostics' => 'maintenance',
    );

    /**
     * The whole navigation, the plugin families of this instance included
     * (one page each, under Integrations).
     *
     * @param array $subGroups plugin subGroup => destination id, from byDestination()
     * @return array id => definition
     */
    public static function destinations(array $subGroups = array())
    {
        $destinations = array();
        foreach (self::fixedDestinations() as $id => $definition) {
            $destinations[$id] = $definition;
            if ($id !== 'integrations') {
                continue;
            }
            foreach ($subGroups as $subGroup => $pluginId) {
                $style = self::subGroupStyle($subGroup);
                $destinations[$pluginId] = array(
                    'group' => 'config',
                    'parent' => 'integrations',
                    'kind' => in_array($subGroup, self::$moduleFamilies, true) ? 'modules' : 'settings',
                    'subGroup' => $subGroup,
                    'icon' => $style['icon'],
                    'accent' => $style['accent'],
                    'title' => $style['title'],
                    'description' => $style['description'],
                );
            }
        }
        return $destinations;
    }

    /**
     * @param string|false $id A destination id, or one of the former tab names.
     * @param array $subGroups plugin subGroup => destination id
     * @return string|false The canonical destination id, or false when unknown.
     */
    public static function resolve($id, array $subGroups = array())
    {
        if ($id === false || $id === null || $id === '') {
            return 'overview';
        }
        if (isset(self::$aliases[$id])) {
            return self::$aliases[$id];
        }
        $destinations = self::destinations($subGroups);
        return isset($destinations[$id]) ? $id : false;
    }

    /**
     * @param string $subGroup
     * @return string
     */
    private static function pluginDestinationId($subGroup)
    {
        $id = strtolower(preg_replace('/[^A-Za-z0-9]/', '', $subGroup));
        $fixed = self::fixedDestinations();
        return isset($fixed[$id]) || isset(self::$aliases[$id]) ? 'plugin-' . $id : $id;
    }

    /**
     * @return array tab => ['sections' => [id => order], 'wildcard' => order] with the destination
     */
    private static function routes()
    {
        $routes = array();
        foreach (self::fixedDestinations() as $id => $definition) {
            if (empty($definition['sources'])) {
                continue;
            }
            foreach ($definition['sources'] as $order => $source) {
                list($tab, $section) = explode(':', $source, 2);
                if ($section === '*') {
                    $routes[$tab]['wildcard'] = array($id, $order);
                } else {
                    $routes[$tab]['sections'][$section] = array($id, $order);
                }
            }
        }
        return $routes;
    }

    /**
     * Distribute every setting of the instance over the navigation.
     *
     * Each tab is split in its sections first (see split()), then every
     * section goes to the destination that claims it, in the order the
     * destination declares. A section nobody claims falls back to Instance,
     * so a new setting can never go missing from the page.
     *
     * @param array $settings Flat list from Server::serverSettingsRead()
     * @return array ['sections' => [destination => sections], 'subGroups' => [subGroup => destination]]
     */
    public static function byDestination(array $settings)
    {
        $settings = self::markModules($settings);

        $byTab = array();
        foreach ($settings as $setting) {
            if (empty($setting['setting']) || self::isHidden($setting['setting'])) {
                continue;
            }
            $byTab[isset($setting['tab']) ? $setting['tab'] : 'MISP'][] = $setting;
        }

        $routes = self::routes();
        $collected = array();
        $subGroups = array();
        foreach ($byTab as $tab => $tabSettings) {
            if (isset(self::$subGroupTabs[$tab])) {
                foreach (self::splitBySubGroup($tab, $tabSettings) as $index => $section) {
                    $destination = self::pluginDestinationId($section['subGroup']);
                    $subGroups[$section['subGroup']] = $destination;
                    $section['uid'] = 'plugin-' . $section['id'];
                    $collected[$destination][] = array(0, $index, $section);
                }
                continue;
            }
            foreach (self::split($tab, $tabSettings) as $index => $section) {
                if (isset($routes[$tab]['sections'][$section['id']])) {
                    list($destination, $order) = $routes[$tab]['sections'][$section['id']];
                } elseif (isset($routes[$tab]['wildcard'])) {
                    list($destination, $order) = $routes[$tab]['wildcard'];
                } else {
                    list($destination, $order) = array('instance', PHP_INT_MAX);
                }
                $section['uid'] = strtolower($tab) . '-' . $section['id'];
                $collected[$destination][] = array($order, $index, $section);
            }
        }

        $sections = array();
        foreach ($collected as $destination => $entries) {
            usort($entries, function ($a, $b) {
                return $a[0] === $b[0] ? $a[1] <=> $b[1] : $a[0] <=> $b[0];
            });
            $sections[$destination] = array_column($entries, 2);
        }

        return array('sections' => $sections, 'subGroups' => $subGroups);
    }

    /**
     * @param array $sections
     * @return array [0 => int, 1 => int, 2 => int] settings in error per level
     */
    public static function counters(array $sections)
    {
        $total = array(0 => 0, 1 => 0, 2 => 0);
        foreach ($sections as $section) {
            foreach ($section['errorsByLevel'] as $level => $count) {
                $total[$level] += $count;
            }
        }
        return $total;
    }

    /**
     * A setting whose current value fails its check. Two cases are left out:
     * the settings of a disabled module, and a non-critical setting that is
     * simply not set, which leaves its default in place — that is several
     * hundred settings on a stock instance, and `cake Admin configLint`
     * skips them for the same reason. Unset essentials, and unset parameters
     * of an enabled module (bar its organisation restriction), still count.
     *
     * @param array $setting
     * @return bool
     */
    public static function inError(array $setting)
    {
        if (!isset($setting['error']) || $setting['level'] >= 3 || !empty($setting['dormant'])) {
            return false;
        }
        $unset = isset($setting['errorMessage']) && $setting['errorMessage'] === __('Value not set.');
        return !$unset
            || $setting['level'] == 0
            || isset(self::essentials()[$setting['setting']])
            || (!empty($setting['module']) && empty($setting['moduleToggle'])
                && substr($setting['setting'], -strlen('_restrict')) !== '_restrict');
    }

    /**
     * Give a setting read on its own (row reload) the module marks
     * byDestination() would have given it.
     *
     * @param array $setting
     * @param string $module The module the row was rendered for
     * @return array
     */
    public static function markModule(array $setting, $module)
    {
        if (!preg_match('/^Plugin\.(' . implode('|', self::$moduleFamilies) . ')_/', $setting['setting'], $matches)
            || $module === '' || strpos($setting['setting'], 'Plugin.' . $matches[1] . '_' . $module . '_') !== 0) {
            return $setting;
        }
        $toggle = 'Plugin.' . $matches[1] . '_' . $module . '_enabled';
        $setting['module'] = $module;
        if ($setting['setting'] === $toggle) {
            $setting['moduleToggle'] = true;
        } elseif (!Configure::read($toggle)) {
            $setting['dormant'] = true;
        }
        return $setting;
    }

    /**
     * Tag the settings misp-modules generates with the module they belong
     * to. Those of a disabled module are `dormant`: still listed, never
     * counted as a problem (an unset API key matters only once the module
     * runs).
     *
     * @param array $settings
     * @return array
     */
    private static function markModules(array $settings)
    {
        $enabled = array();
        foreach ($settings as $setting) {
            $parsed = self::parseModuleToggle(isset($setting['setting']) ? $setting['setting'] : '');
            if ($parsed) {
                $enabled[$parsed[0]][$parsed[1]] = !empty($setting['value']) && $setting['value'] !== 'false';
            }
        }
        if (empty($enabled)) {
            return $settings;
        }
        foreach ($enabled as $family => $modules) {
            uksort($enabled[$family], function ($a, $b) {
                return strlen($b) <=> strlen($a);
            });
        }

        foreach ($settings as $key => $setting) {
            if (empty($setting['setting']) || strpos($setting['setting'], 'Plugin.') !== 0) {
                continue;
            }
            $leaf = substr($setting['setting'], 7);
            $family = explode('_', $leaf, 2)[0];
            if (!isset($enabled[$family])) {
                continue;
            }
            $rest = substr($leaf, strlen($family) + 1);
            foreach ($enabled[$family] as $module => $isEnabled) {
                if (strpos($rest, $module . '_') !== 0) {
                    continue;
                }
                $settings[$key]['module'] = $module;
                if ($rest === $module . '_enabled') {
                    $settings[$key]['moduleToggle'] = true;
                } elseif (!$isEnabled) {
                    $settings[$key]['dormant'] = true;
                }
                break;
            }
        }
        return $settings;
    }

    /**
     * @param string $name
     * @return array|false [family, module] for a module's `_enabled` switch
     */
    private static function parseModuleToggle($name)
    {
        $pattern = '/^Plugin\.(' . implode('|', self::$moduleFamilies) . ')_(.+)_enabled$/';
        if (!preg_match($pattern, $name, $matches)) {
            return false;
        }
        return array($matches[1], $matches[2]);
    }

    /**
     * The module grid of a module family page: the settings of the service
     * itself, and one entry per module with its switch and its own settings.
     *
     * @param array $sections The sections of the family's destination
     * @return array ['service' => settings, 'modules' => [module => entry]]
     */
    public static function modules(array $sections)
    {
        $service = array();
        $modules = array();
        foreach ($sections as $section) {
            foreach ($section['settings'] as $setting) {
                if (empty($setting['module'])) {
                    $service[] = $setting;
                    continue;
                }
                $module = $setting['module'];
                if (!isset($modules[$module])) {
                    $modules[$module] = array(
                        'id' => $module, 'toggle' => null, 'settings' => array(),
                        'enabled' => false, 'needsConfig' => false, 'description' => '',
                    );
                }
                if (!empty($setting['moduleToggle'])) {
                    $modules[$module]['toggle'] = $setting;
                    $modules[$module]['enabled'] = !empty($setting['value']) && $setting['value'] !== 'false';
                    $modules[$module]['description'] = self::moduleDescription($setting['description']);
                } else {
                    $modules[$module]['settings'][] = $setting;
                }
            }
        }
        foreach ($modules as $module => $entry) {
            foreach ($entry['settings'] as $setting) {
                if ($entry['enabled'] && isset($setting['error']) && $setting['level'] < 3) {
                    $modules[$module]['needsConfig'] = true;
                }
            }
        }
        uasort($modules, function ($a, $b) {
            return $a['enabled'] === $b['enabled'] ? strcmp($a['id'], $b['id']) : ($a['enabled'] ? -1 : 1);
        });
        return array('service' => $service, 'modules' => $modules);
    }

    /**
     * @param string $description "[<span>Enable or disable the X module.</span>] what it does"
     * @return string what it does
     */
    private static function moduleDescription($description)
    {
        $text = trim(html_entity_decode(strip_tags((string)$description), ENT_QUOTES));
        $text = preg_replace('/^\[[^\]]*\]\s*/', '', $text);
        return $text;
    }

    /**
     * @param string $subGroup
     * @return array title, description, icon, accent
     */
    private static function subGroupStyle($subGroup)
    {
        if (isset(self::$subGroupStyles[$subGroup])) {
            return self::$subGroupStyles[$subGroup];
        }
        return array(
            'title' => $subGroup,
            'description' => __('Settings of the %s plugin', $subGroup),
            'icon' => 'puzzle-piece',
            'accent' => '#6c757d',
        );
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
            $style = self::subGroupStyle($subGroup);
            $sections[] = self::withCounters(array(
                'id' => strtolower($subGroup),
                'subGroup' => $subGroup,
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
            if (!self::inError($setting)) {
                continue;
            }
            $errorsByLevel[$setting['level']]++;
        }
        $section['errorsByLevel'] = $errorsByLevel;

        return $section;
    }
}
