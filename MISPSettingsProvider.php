<?php

[
    'MISP' => [
        'General' => [
            'URLs' => [
                'baseurl' => [
                    'name' => __('Base URL'),
                    'type' => 'string',
                    'description' => __('The base url of the application (in the format https://www.mymispinstance.com or https://myserver.com/misp). Several features depend on this setting being correctly set to function.'),
                    'severity' => 'critical',
                    'test' => 'testBaseURL',
                ],
                'external_baseurl' => [
                    'name' => __('External Base URL'),
                    'type' => 'string',
                    'description' => __('The base url of the application (in the format https://www.mymispinstance.com) as visible externally/by other MISPs. MISP will encode this URL in sharing groups when including itself. If this value is not set, the baseurl is used as a fallback.'),
                    'severity' => 'critical',
                    'test' => 'testURL',
                ],
            ],
            'Instance Owner' => [
                'host_org_id' => [
                    'name' => __('Host organisation'),
                    'type' => 'select',
                    'description' => __('The hosting organisation of this instance. If this is not selected then replication instances cannot be added.'),
                    'default' => 0,
                    'options' => function () {
                        return [];
                        // return $this->loadLocalOrganisations(true);
                    },
                    'test' => 'testLocalOrgStrict',
                ],
                'org' => [
                    'name' => __('Host organisation display name'),
                    'type' => 'string',
                    'description' => __('The organisation tag of the hosting organisation. This is mainly used in the e-mail subjects. Usually the organisation of the `Host organisation`.'),
                    'default' => '',
                    'test' => 'testForEmpty',
                ],
                'contact' => array(
                    'name' => __('Instance\'s support team e-mail address'),
                    'type' => 'string',
                    'description' => __('The e-mail address that MISP should include as a contact address for the instance\'s support team.'),
                    'default' => '',
                    'test' => 'testForEmpty',
                ),
            ],
            'live' => [
                'name' => 'Live Mode',
                'type' => 'boolean',
                'description' => __('Unless set to true, the instance will only be accessible by site admins.'),
                'default' => false,
                'test' => 'testLive',
            ],
            'language' => [
                'name' => 'Language',
                'type' => 'select',
                'description' => __('Select the language MISP should use. The default is english.'),
                'default' => 'eng',
                'options' => function () {
                    return ['en' => 'en', 'fr' => 'fr'];
                    // return $this->loadAvailableLanguages();
                },
                'test' => 'testLanguage',
                'afterSave' => 'cleanCacheFiles'
            ],
            'uuid' => array(
                'name' => __('Instance UUID'),
                'type' => 'string',
                'description' => __('The MISP instance UUID. This UUID is used to identify this instance.'),
                'test' => 'testUuid',
            ),
            'Background Jobs' => [
                'background_jobs' => [
                    'name' => __('Background Jobs'),
                    'type' => 'boolean',
                    'description' => __('Enables the use of MISP\'s background processing.'),
                    'default' => true,
                    'test' => 'testBoolTrue',
                ],
                'manage_workers' => [
                    'name' => __('Enable automatic workers managements'),
                    'type' => 'boolean',
                    'description' => __('Set this to false if you would like to disable MISP managing its own worker processes (for example, if you are managing the workers with a systemd unit).'),
                    'default' => true,
                    'test' => 'testBool',
                ],
            ]
        ],
        'Behaviours' => [
            'Data Fetching' => [
                'unpublishedprivate' => [
                    'name' => __('Restrict access to unpublished events'),
                    'type' => 'boolean',
                    'description' => __('Enabling this setting will deny access to unpublished events to users outside the organisation of the submitter (except site admins).'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'proposals_block_attributes' => [
                    'name' => __('Block Attributes having a Proposal disabling their IDS flag'),
                    'type' => 'boolean',
                    'description' => __('Enable this setting to allow blocking attributes from to_ids sensitive exports if a proposal has been made to it to remove the IDS flag or to remove the attribute altogether. This is a powerful tool to deal with false-positives efficiently.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'attribute_filters_block_only' => [
                    'name' => __('Ignore Attribute filters used in Event scope (Unless blocking rule)'),
                    'type' => 'boolean',
                    'description' => __('This is a performance tweak to change the behaviour of restSearch to use attribute filters solely for blocking. This means that a lookup on the event scope with for example the type field set will be ignored unless it\'s used to strip unwanted attributes from the results. If left disabled, passing [ip-src, ip-dst] for example will return any event with at least one ip-src or ip-dst attribute. This is generally not considered to be too useful and is a heavy burden on the database.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
            ],
            'Deletion' => [
                'sanitise_attribute_on_delete' => [
                    'name' => __('Sanitize deleted Attributes'),
                    'type' => 'boolean',
                    'description' => __('Enabling this setting will sanitise the contents of an attribute on a soft delete'),
                    'default' => false,
                ],
            ],
            'Default settings' => [
                'default_event_distribution' => [
                    'name' => __('Event: Default distribution level'),
                    'type' => 'select',
                    'description' => __('The default distribution level for events.'),
                    'default' => 1,
                    'options' => [0 => __('Your organisation only'), 1 => __('This community only'), 2 => __('Connected communities'), 3 => __('All communities')],
                    'test' => 'testForEmpty',
                ],
                'default_event_threat_level' => [
                    'name' => __('Event: Default Threat Level'),
                    'type' => 'select',
                    'description' => __('The default threat level setting when creating events.'),
                    'default' => 4,
                    'options' => [1 => 'High', 2 => 'Medium', 3 => 'Low', 4 => 'undefined'],
                    'test' => 'testForEmpty',
                ],
                'default_attribute_distribution' => [
                    'name' => __('Attribute: Default distribution level'),
                    'type' => 'select',
                    'description' => __('The default distribution setting for attributes, set it to \'event\' if you would like the attributes to default to the event distribution level.'),
                    'default' => 'event',
                    'options' => [0 => __('Your organisation only'), 1 => __('This community only'), 2 => __('Connected communities'), 3 => __('All communities'), 'event' => __('Inherit from event')],
                    'test' => 'testForEmpty',
                ],
                'default_event_tag_collection' => [
                    'name' => __('Default Tag collection'),
                    'type' => 'select',
                    'description' => __('The tag collection to be applied to all events created manually.'),
                    'default' => 0,
                    'options' => function() {
                        return [];
                        // return $this->loadTagCollections();
                    },
                    'test' => 'testTagCollections',
                ],
                'default_publish_alert' => [
                    'name' => __('User: Event notification strategy used by default'),
                    'type' => 'boolean',
                    'description' => __('The default setting for publish alerts when creating users.'),
                    'default' => 1,
                    'options' => [0 => __('Do not receive email notifications when Events are published'), 1 => __('Receive email notifications when Events are published')],
                    'test' => 'testBool',
                ],
                'incoming_tags_disabled_by_default' => [
                    'name' => __('Tags: Turn off the `selectable` flag for new tags'),
                    'type' => 'boolean',
                    'description' => __('Enable this settings if new tags synced / added via incoming events from any source should not be selectable by users by default.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
            ],
            'Memory usage' => [
                'default_attribute_memory_coefficient' => [
                    'name' => __('Attribute memory coefficient'),
                    'type' => 'integer',
                    'description' => __('This values controls the internal fetcher\'s memory envelope when it comes to attributes. The number provided is the amount of attributes that can be loaded for each MB of PHP memory available in one shot. Consider lowering this number if your instance has a lot of attribute tags / attribute galaxies attached.'),
                    'default' => 80,
                    'test' => 'testForNumeric',
                ],
                'default_event_memory_divisor' => [
                    'name' => __('Event memory divisor'),
                    'type' => 'integer',
                    'description' => __('This value controls the divisor for attribute weighting when it comes to loading full events. Meaning that it will load coefficient / divisor number of attributes per MB of memory available. Consider raising this number if you have a lot of correlations or highly contextualised events (large number of event level galaxies/tags).'),
                    'default' => 3,
                    'test' => 'testForNumeric',
                ],
            ],
            'Session' => [
                'disable_auto_logout' => [
                    'name' => __('Automatic logout disabled'),
                    'type' => 'boolean',
                    'description' => __('In some cases, a heavily used MISP instance can generate unwanted blackhole errors due to a high number of requests hitting the server. Disable the auto logout functionality to ease the burden on the system.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
            ],
            'Settings' => [
                'server_settings_skip_backup_rotate' => [
                    'name' => __('Setting saving strategy'),
                    'type' => 'boolean',
                    'description' => __('Enable this setting to directly save the config.php file without first creating a temporary file and moving it to avoid concurency issues. Generally not recommended, but useful when for example other tools modify/maintain the config.php file.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
            ],
            'Correlation' => [
                'completely_disable_correlation' => [
                    'name' => __('Disable correlation engine'),
                    'type' => 'boolean',
                    'description' => __('*WARNING* This setting will completely disable the correlation on this instance and remove any existing saved correlations. Enabling this will trigger a full recorrelation of all data which is an extremely long and costly procedure. Only enable this if you know what you\'re doing.'),
                    'default' => false,
                    'test' => 'testBoolFalse',
                    'afterSave' => 'correlationAfterHook',
                ],
                'allow_disabling_correlation' => [
                    'name' => __('Allow disabling correlation for specific Events'),
                    'type' => 'boolean',
                    'description' => __('*WARNING* This setting will give event creators the possibility to disable the correlation of individual events / attributes that they have created.'),
                    'default' => false,
                    'test' => 'testBoolFalse',
                ],
                'enable_advanced_correlations' => [
                    'name' => __('Advanced correlations'),
                    'type' => 'boolean',
                    'description' => __('Enable some performance heavy correlations (currently CIDR correlation)'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'deadlock_avoidance' => [
                    'name' => __('Deadlock avoidance when saving correlations'),
                    'type' => 'boolean',
                    'description' => __('Only enable this if you have some tools using MISP with extreme high concurency. General performance will be lower as normal as certain transactional queries are avoided in favour of shorter table locks.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'max_correlations_per_event' => [
                    'name' => __('Number of maximum correlations per event'),
                    'type' => 'integer',
                    'description' => __('Sets the maximum number of correlations that can be fetched with a single event. For extreme edge cases this can prevent memory issues. The default value is 5k.'),
                    'default' => 5000,
                    'test' => 'testForNumeric',
                ],
                'ssdeep_correlation_threshold' => [
                    'name' => __('ssdeep correlation threshold'),
                    'type' => 'integer',
                    'description' => __('Set the ssdeep score at which to consider two ssdeep hashes as correlating [1-100]'),
                    'default' => 40,
                    'test' => function($value, $setting, $validator) {
                        $validator->range('value', [1, 100]);
                        return testValidator($value, $validator);
                    },
                    'beforeSave' => function($value, $setting, $validator) {
                        $validator->range('value', [1, 100]);
                        return testValidator($value, $validator);
                    },
                ],
            ],
            'Warninglists' => [
                'warning_for_all' => [
                    'name' => __('Show all warninglist hits'),
                    'type' => 'boolean',
                    'description' => __('Enable warning list triggers regardless of the IDS flag value'),
                    'default' => false,
                    'test' => 'testBool',
                ],
            ],
            'Attachments' => [
                'attachment_scan_module' => [
                    'name' => __('Attachment scan enrichment module'),
                    'type' => 'string',
                    'description' => __('Name of enrichment module that will be used for attachment malware scanning. This module must return av-signature or sb-signature object.'),
                    'default' => '',
                ],
                'attachment_scan_hash_only' => [
                    'name' => __('Only send attachment hash'),
                    'type' => 'boolean',
                    'description' => __('Send to attachment scan module just file hash. This can be useful if module sends attachment to remote service and you don\'t want to leak real data.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'attachment_scan_timeout' => [
                    'name' => __('Attachment scan timeout'),
                    'type' => 'integer',
                    'description' => __('How long to wait for scan results in seconds.'),
                    'default' => 30,
                    'test' => 'testForPositiveInteger',
                ],
                'download_attachments_on_load' => [
                    'name' => __('Automatically download attachments'),
                    'type' => 'boolean',
                    'description' => __('Always download attachments when loaded by a user in a browser. Disabling this setting will show the attachment content in the browser page.'),
                    'default' => true,
                    'test' => 'testBool',
                ],
            ],
            'Updates' => [
                'updateTimeThreshold' => [
                    'name' => __('Update re-try threshold'),
                    'type' => 'integer',
                    'description' => __('Sets the minimum time before being able to re-trigger an update if the previous one failed. (safe guard to avoid starting the same update multiple time)'),
                    'default' => 7200,
                    'test' => 'testForNumeric',
                ],
            ],
            'Sightings' => [
                'Sightings_sighting_db_enable' => [
                    'name' => __('Enable Sighting DB'),
                    'type' => 'boolean',
                    'description' => __('Enable SightingDB integration.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'Sightings_policy' => [
                    'name' => __('Access Policy'),
                    'type' => 'select',
                    'description' => __('This setting defines who will have access to seeing the reported sightings. The default setting is the event owner organisation alone (in addition to everyone seeing their own contribution) with the other options being Sighting reporters (meaning the event owner and any organisation that provided sighting data about the event) and Everyone (meaning anyone that has access to seeing the event / attribute).'),
                    'default' => 0,
                    'options' => [
                        0 => __('Event Owner Organisation'),
                        1 => __('Sighting reporters'),
                        2 => __('Everyone'),
                        3 => __('Event Owner + host org sightings'),
                    ],
                    'test' => 'testForSightingVisibility',
                ],
                'Sightings_anonymise' => [
                    'name' => __('Anonymise organisations'),
                    'type' => 'boolean',
                    'description' => __('Enabling the anonymisation of sightings will simply aggregate all sightings instead of showing the organisations that have reported a sighting. Users will be able to tell the number of sightings their organisation has submitted and the number of sightings for other organisations'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'Sightings_anonymise_as' => [
                    'name' => __('Anonymise organisations during synchronisation as'),
                    'type' => 'select',
                    'description' => __('When pushing sightings to another server, report all sightings from this instance as this organisation. This effectively hides all sightings from this instance behind a single organisation to the outside world. Sightings pulled from this instance follow the Sightings_policy above.'),
                    'default' => 0,
                    'options' => function () {
                        return [];
                        // return $this->loadLocalOrganisations();
                    },
                    'test' => 'testLocalOrg',
                ],
                'Sightings_range' => [
                    'name' => __('Date range for graphs (days)'),
                    'type' => 'integer',
                    'description' => __('Set the range in which sightings will be taken into account when generating graphs. For example a sighting with a sighted_date of 7 years ago might not be relevant anymore. Setting given in number of days, default is 365 days'),
                    'default' => 365,
                    'test' => 'testForNumeric',
                ],
            ],
        ],
        'Notifications' => [
            'disablerestalert' => [
                'name' => __('Prevent notifications for Event received via sync'),
                'type' => 'boolean',
                'description' => __('This setting controls whether notification e-mails will be sent when an event is created via the REST interface. It might be a good idea to disable this setting when first setting up a link to another instance to avoid spamming your users during the initial pull. Quick recap: True = Emails are NOT sent, False = Emails are sent on events published via sync / REST.'),
                'default' => true,
                'test' => 'testBool',
            ],
            'Block Event notifications based on Tag' => [
                'block_event_alert' => [
                    'name' => __('Prevent notifications for published Event containing a certain Tag'),
                    'type' => 'boolean',
                    'description' => __('Enable this setting to start blocking alert e-mails for events with a certain tag. Define the tag in MISP.block_event_alert_tag.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'block_event_alert_tag' => [
                    'name' => __('Prevent notification for Tag'),
                    'type' => 'string',
                    'description' => __('If the MISP.block_event_alert setting is set, alert e-mails for events tagged with the tag defined by this setting will be blocked.'),
                    'default' => 'no-alerts="true"',
                    'test' => 'testForEmpty',
                    'dependsOn' => 'block_event_alert',
                ],
            ],
            'Block Event notifications based on Organisation' => [
                'org_alert_threshold' => [
                    'name' => __('Prevent notifications for Event from a certain Organisation'),
                    'type' => 'integer',
                    'description' => __('Set a value to limit the number of email alerts that events can generate per creator organisation (for example, if an organisation pushes out 2000 events in one shot, only alert on the first 20).'),
                    'default' => 0,
                    'test' => 'testForNumeric',
                ],
            ],
            'Block Event notifications based on re-pubishing' => [
                'event_alert_republish_ban' => [
                    'name' => __('Prevent notifications for Event being re-published'),
                    'type' => 'boolean',
                    'description' => __('Enable this setting to start blocking alert e-mails for events that have already been published since a specified amount of time. This threshold is defined by MISP.event_alert_republish_ban_threshold'),
                    'default' => true,
                    'test' => 'testBool',
                ],
                'event_alert_republish_ban_threshold' => [
                    'name' => __('Re-publishing threshold blocking notifications'),
                    'type' => 'integer',
                    'description' => __('If the MISP.event_alert_republish_ban setting is set, this setting will control how long no alerting by email will be done. Expected format: integer, in minutes'),
                    'default' => 5,
                    'test' => 'testForNumeric',
                    'dependsOn' => 'event_alert_republish_ban',
                ],
                'event_alert_republish_ban_refresh_on_retry' => [
                    'name' => __('Refresh re-publishing ban on retry'),
                    'type' => 'boolean',
                    'description' => __('If the MISP.event_alert_republish_ban setting is set, this setting will control if a ban time should be reset if emails are tried to be sent during the ban.'),
                    'default' => true,
                    'test' => 'testBool',
                    'dependsOn' => 'event_alert_republish_ban',
                ],
            ],
            'Block Event notifications based on time' => [
                'block_old_event_alert' => [
                    'name' => __('Prevent notification for old Events'),
                    'type' => 'boolean',
                    'description' => __('Enable this setting to start blocking alert e-mails for old events. The exact timing of what constitutes an old event is defined by MISP.block_old_event_alert_age.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'block_old_event_alert_age' => [
                    'name' => __('Number of days for an Event to be consider "old" (timestamp field)'),
                    'type' => 'integer',
                    'description' => __('If the MISP.block_old_event_alert setting is set, this setting will control how old an event can be for it to be alerted on. The "timestamp" field of the event is used. Expected default: integer, in days'),
                    'test' => 'testForNumeric',
                    'dependsOn' => 'block_old_event_alert',
                ],
                'block_old_event_alert_by_date' => [
                    'name' => __('Number of days for an Event to be consider "old" (date field)'),
                    'type' => 'integer',
                    'description' => __('If the MISP.block_old_event_alert setting is set, this setting will control the threshold for the event.date field, indicating how old an event can be for it to be alerted on. The "date" field of the event is used. Expected format: integer, in days'),
                    'test' => 'testForNumeric',
                    'dependsOn' => 'block_old_event_alert',
                ],
            ],
        ],
        'Logging' => [
            'log_skip_db_logs_completely' => [
                'name' => __('Disable logging'),
                'type' => 'boolean',
                'description' => __('This functionality allows you to completely disable any logs from being saved in your SQL backend. This is HIGHLY advised against, you lose all the functionalities provided by the audit log subsystem along with the event history (as these are built based on the logs on the fly). Only enable this if you understand and accept the associated risks.'),
                'default' => false,
                'test' => 'testBoolFalse',
            ],
            'Audit Logs' => [
                'log_new_audit' => [
                    'name' => __('Enable audit log system'),
                    'type' => 'boolean',
                    'description' => __('Enable new audit log system.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'log_new_audit_compress' => [
                    'name' => __('Enable compression'),
                    'type' => 'boolean',
                    'description' => __('Compress log changes by brotli algorithm. This will reduce log database size.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
            ],
            'Paranoid Login' => [
                'log_paranoid' => [
                    'name' => __('Paranoid loging enabled'),
                    'type' => 'boolean',
                    'description' => __('If this functionality is enabled all page requests will be logged. Keep in mind this is extremely verbose and will become a burden to your database.'),
                    'default' => false,
                    'test' => 'testBoolFalse',
                ],
                'log_paranoid_skip_db' => [
                    'name' => __('Skip saving log entries in database'),
                    'type' => 'boolean',
                    'description' => __('You can decide to skip the logging of the paranoid logs to the database.'),
                    'default' => false,
                    'test' => 'testParanoidSkipDb',
                ],
                'log_paranoid_include_post_body' => [
                    'name' => __('Inclode POSTed body in the log entry'),
                    'type' => 'boolean',
                    'description' => __('If paranoid logging is enabled, include the POST body in the entries.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'sync_audit' => [
                    'name' => __('Synchronisation audit logs'),
                    'type' => 'boolean',
                    'description' => __('Enable this setting to create verbose logs of synced event data for debugging reasons. Logs are saved in your MISP directory\'s app/files/scripts/tmp/ directory.'),
                    'default' => false,
                    'test' => 'testBoolFalse',
                ],
            ],
            'API Logging' => [
                'log_auth' => [
                    'name' => __('Log successful API keys authentications'),
                    'type' => 'boolean',
                    'description' => __('If enabled, MISP will log all successful authentications using API keys. The requested URLs are also logged.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'do_not_log_authkeys' => [
                    'name' => __('Redact authorization keys from log entries'),
                    'type' => 'boolean',
                    'description' => __('If enabled, any authkey will be replaced by asterisks in Audit log.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
            ],
            'Client Logging' => [
                'log_each_individual_auth_fail' =>[
                    'name' => __('Log individual authentication failure'),
                    'type' => 'boolean',
                    'description' => __('By default API authentication failures that happen within the same hour for the same key are omitted and a single log entry is generated. This allows administrators to more easily keep track of attackers that try to brute force API authentication, by reducing the noise generated by expired API keys. On the other hand, this makes little sense for internal MISP instances where detecting the misconfiguration of tools becomes more interesting, so if you fall into the latter category, enable this feature.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'log_client_ip' => [
                    'name' => __('Log client IP address in log entries'),
                    'type' => 'boolean',
                    'description' => __('If enabled, all log entries will include the IP address of the user.'),
                    'default' => false,
                    'test' => 'testBool',
                    'beforeSave' => 'ipLogBeforeHook',
                ],
                'log_client_ip_header' => [
                    'name' => __('Client IP address header field'),
                    'type' => 'string',
                    'description' => __('If log_client_ip is enabled, you can customize which header field contains the client\'s IP address. This is generally used when you have a reverse proxy infront of your MISP instance.'),
                    'default' => 'REMOTE_ADDR',
                    'test' => 'testForEmpty',
                    'dependsOn' => 'log_client_ip'
                ],
                'log_user_ips' => [
                    'name' => __('Log client IP address in Redis'),
                    'type' => 'boolean',
                    'description' => __('Log user IPs on each request. 30 day retention for lookups by IP to get the last authenticated user ID for the given IP, whilst on the reverse, indefinitely stores all associated IPs for a user ID.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'log_user_ips_authkeys' => [
                    'name' => __('Log client API key usage in Redis'),
                    'type' => 'boolean',
                    'description' => __('Log user IP and key usage on each API request. All logs for given keys are deleted after one year when this key is not used.'),
                    'default' => false,
                    'test' => 'testBool',
                    'dependsOn' => 'log_user_ips',
                ],
            ]
        ],
        'Paths' => [
            'tmpdir' => [
                'name' => __('Temporary Directory'),
                'type' => 'string',
                'description' => __('Please indicate the temp directory you wish to use for certain functionalities in MISP. By default this is set to /tmp and will be used among others to store certain temporary files extracted from imports during the import process.'),
                'default' => '/tmp',
                'test' => 'testForPath',
                'cli_only' => 1
            ],
            'Attachments' => [
                'attachments_dir' => [
                    'name' => __('Attachments Directory'),
                    'type' => 'string',
                    'description' => __('Directory where attachments are stored. MISP will NOT migrate the existing data if you change this setting. The only safe way to change this setting is in config.php, when MISP is not running, and after having moved/copied the existing data to the new location. This directory must already exist and be writable and readable by the MISP application.'),
                    'default' =>  APP . '/files', # GUI display purpose only.
                    'test' => 'testForWritableDir',
                    'cli_only' => 1
                ],
            ],
            'Binaries' => [
                'python_bin' => [
                    'name' => __('Python binary path'),
                    'type' => 'string',
                    'description' => __('It is highly recommended to install all the python dependencies in a virtualenv. The recommended location is: %s/venv', ROOT),
                    'default' => false,
                    'test' => 'testForBinExec',
                    'beforeSave' => 'beforeHookBinExec',
                    'cli_only' => true,
                ],
            ],
            'Certificates' => [
                'ca_path' => [
                    'name' => __('Certificate Authority path'),
                    'type' => 'string',
                    'description' => __('MISP will default to the bundled mozilla certificate bundle shipped with the framework, which is rather stale. If you wish to use an alternate bundle, just set this setting using the path to the bundle to use. This setting can only be modified via the CLI.'),
                    'default' => APP . 'Lib/cakephp/lib/Cake/Config/cacert.pem',
                    'test' => 'testForCABundle',
                    'cli_only' => true,
                ],
            ],
            'Terms and Conditions' => [
                'terms_file' => [
                    'name' => __('Terms and Conditions filename'),
                    'type' => 'string',
                    'description' => __('The filename of the terms and conditions file. Make sure that the file is located in your MISP/app/files/terms directory'),
                    'default' => '',
                    'test' => 'testForTermsFile',
                ],
            ]
        ],
        'User Interface' => [
            'General' => [
                'custom_css' => [
                    'name' => __('Custom CSS filename'),
                    'type' => 'string',
                    'description' => __('If you would like to customise the css, simply drop a css file in the /var/www/MISP/webroot/css directory and enter the name here.'),
                    'default' => '',
                    'test' => 'testForStyleFile',
                ],
            ],
            'Events' => [
                'disable_threat_level' => [
                    'name' => __('Threat level disabled'),
                    'type' => 'boolean',
                    'description' => __('Disable displaying / modifications to the threat level altogether on the instance (deprecated field).'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'showorg' => [
                    'name' => __('Hide creator and owner organisations'),
                    'type' => 'boolean',
                    'description' => __('Setting this setting to \'false\' will hide all organisation names / logos.'),
                    'default' => true,
                    'test' => 'testBool',
                ],
                'showorgalternate' => [
                    'name' => __('Show owner organisation'),
                    'type' => 'boolean',
                    'description' => __('True enables the alternate org fields for the event index (source org and member org) instead of the traditional way of showing only an org field. This allows users to see if an event was uploaded by a member organisation on their MISP instance, or if it originated on an interconnected instance.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'full_tags_on_event_index' => [
                    'name' => __('Tag representation on Event index'),
                    'type' => 'select',
                    'description' => __('Show the full tag names on the event index.'),
                    'default' => 1,
                    'options' => [0 => 'Minimal tags', 1 => 'Full tags', 2 => 'Shortened tags'],
                    'test' => 'testForEmpty',
                ],
                'showCorrelationsOnIndex' => [
                    'name' => __('Show Correlation count on Event index'),
                    'type' => 'boolean',
                    'description' => __('When enabled, the number of correlations visible to the currently logged in user will be visible on the event index UI. This comes at a performance cost but can be very useful to see correlating events at a glance.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'showProposalsCountOnIndex' => [
                    'name' => __('Show Proposals count on Event index'),
                    'type' => 'boolean',
                    'description' => __('When enabled, the number of proposals for the events are shown on the index.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'showSightingsCountOnIndex' => [
                    'name' => __('Show Sightings count on Event index'),
                    'type' => 'boolean',
                    'description' => __('When enabled, the aggregate number of attribute sightings within the event becomes visible to the currently logged in user on the event index UI.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'showDiscussionsCountOnIndex' => [
                    'name' => __('Show Discussions count on Event index'),
                    'type' => 'boolean',
                    'description' => __('When enabled, the aggregate number of discussion posts for the event becomes visible to the currently logged in user on the event index UI.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'showEventReportCountOnIndex' => [
                    'name' => __('Show EventReports count on Event index'),
                    'type' => 'boolean',
                    'description' => __('When enabled, the aggregate number of event reports for the event becomes visible to the currently logged in user on the event index UI.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'event_view_filter_fields' => [
                    'name' => __('Event view quick filter fields'),
                    'type' => 'multi-select',
                    'description' => __('Specify which fields to filter on when you search on the event view. Default values are : "id, uuid, value, comment, type, category, Tag.name"'),
                    'default' => 'id, uuid, value, comment, type, category, Tag.name',
                    'options' => ['id', 'uuid', 'value', 'comment', 'type', 'category', 'Tag.name'],
                    'beforeSave' => function($value, $setting) {
                        if (empty($value)) {
                            return false;
                        }
                        if (is_array($value)) {
                            $setting['value'] = implode(', ', $value);
                        }
                        return true;
                    },
                ],
                'cveurl' => [
                    'name' => _('CVE Lookup URL'),
                    'type' => 'string',
                    'description' => __('Turn Vulnerability type attributes into links linking to the provided CVE lookup'),
                    'default' => 'https://cve.circl.lu/cve/',
                    'test' => 'testForEmpty',
                ],
                'cweurl' => [
                    'name' => _('CWE Lookup URL'),
                    'type' => 'string',
                    'description' => __('Turn Weakness type attributes into links linking to the provided CWE lookup'),
                    'default' => 'https://cve.circl.lu/cwe/',
                    'test' => 'testForEmpty',
                ],
            ],
            'Organisations' => [
                'hide_organisation_index_from_users' => [
                    'name' => __('Hide organisation index'),
                    'type' => 'boolean',
                    'description' => __('Enabling this setting will block the organisation index from being visible to anyone besides site administrators on the current instance. Keep in mind that users can still see organisations that produce data via events, proposals, event history log entries, etc.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'hide_organisations_in_sharing_groups' => [
                    'name' => __('Hide organisation listed in sharing groups'),
                    'type' => 'boolean',
                    'description' => __('Enabling this setting will block the organisation list from being visible in sharing group besides user with sharing group permission.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
            ],
            'Placeholders' => [
                'title_text' => [
                    'name' => __('Page title'),
                    'type' => 'string',
                    'description' => __('Used in the page title, after the name of the page'),
                    'default' => 'MISP',
                    'test' => 'testForEmpty',
                ],
                'home_logo' => [
                    'name' => __('Home logo (Top bar)'),
                    'type' => 'string',
                    'description' => __('If set, this setting allows you to display a logo as the home icon. Upload it as a custom image in the file management tool.'),
                    'default' => '',
                    'test' => 'testForCustomImage',
                ],
                'welcome_text_top' => array(
                    'name' => __('Top welcome text (login page)'),
                    'type' => 'string',
                    'description' => __('Used on the login page, before the MISP logo'),
                    'default' => '',
                    'test' => 'testForEmpty',
                ),
                'welcome_text_bottom' => array(
                    'name' => __('Bottom welcome text (login page)'),
                    'type' => 'string',
                    'description' => __('Used on the login page, after the MISP logo'),
                    'default' => '',
                    'test' => 'testForEmpty',
                ),
                'welcome_logo' => array(
                    'name' => __('Left welcome logo (login page)'),
                    'type' => 'string',
                    'description' => __('Used on the login page, to the left of the MISP logo, upload it as a custom image in the file management tool.'),
                    'default' => '',
                    'test' => 'testForCustomImage',
                ),
                'main_logo' => [
                    'name' => __('Main logo (login page)'),
                    'type' => 'string',
                    'description' => __('If set, the image specified here will replace the main MISP logo on the login screen. Upload it as a custom image in the file management tool.'),
                    'default' => '',
                    'test' => 'testForCustomImage',
                ],
                'welcome_logo2' => array(
                    'name' => __('Right welcome logo (login page)'),
                    'type' => 'string',
                    'description' => __('Used on the login page, to the right of the MISP logo, upload it as a custom image in the file management tool.'),
                    'default' => '',
                    'test' => 'testForCustomImage',
                ),
                'maintenance_message' => [
                    'name' => __('Maintenance message'),
                    'type' => 'string',
                    'description' => __('The message that users will see if the instance is not live.'),
                    'default' => __('Great things are happening! MISP is undergoing maintenance, but will return shortly. You can contact the administration at $email.'),
                    'test' => 'testForEmpty',
                ],
                'footermidleft' => [
                    'name' => __('Page footer left text'),
                    'type' => 'string',
                    'description' => __('Footer text prepending the "Powered by MISP" text.'),
                    'default' => '',
                    'test' => 'testForEmpty',
                ],
                'footermidright' => [
                    'name' => __('Page footer right text'),
                    'type' => 'string',
                    'description' => __('Footer text following the "Powered by MISP" text.'),
                    'default' => '',
                    'test' => 'testForEmpty',
                ],
                'footer_logo' => [
                    'name' => __('Page footer right logo'),
                    'type' => 'string',
                    'description' => __('If set, this setting allows you to display a logo on the right side of the footer. Upload it as a custom image in the file management tool.'),
                    'default' => '',
                    'test' => 'testForCustomImage',
                ],
            ],
            'Terms and Conditions' => [
                'terms_download' => [
                    'name' => __('Terms and conditions display'),
                    'type' => 'select',
                    'description' => __('Choose whether the terms and conditions should be displayed inline (false) or offered as a download (true)'),
                    'default' => 0,
                    'options' => [0 => __('Show terms and conditions inline'), 1 => __('Show download button only')],
                    'test' => 'testBool',
                ],
            ]
        ],
        'Mail' => [
            'disable_emailing' => [
                'name' => __('Emailing disabled'),
                'type' => 'boolean',
                'description' => __('You can disable all e-mailing using this setting. When this setting is turned on, no outgoing e-mails will be sent by MISP.'),
                'default' => false,
                'test' => 'testDisableEmail',
            ],
            'email' => [
                'name' => __('Email sender address'),
                'type' => 'string',
                'description' => __('The e-mail address that MISP should use for all notifications'),
                'default' => '',
                'test' => 'testForEmpty',
            ],
            'email_from_name' => [
                'name' => __('E-mail sender name'),
                'type' => 'string',
                'description' => __('The e-mail display name that MISP should use for all otifications.'),
                'default' => '',
                'test' => 'testForEmpty',
            ],
            'E-mails for Events' => [
                'extended_alert_subject' => [
                    'name' => __('Include Event description in e-mail subject'),
                    'type' => 'boolean',
                    'description' => __('Enabling this flag will allow the event description to be transmitted in the alert e-mail\'s subject. Be aware that this is not encrypted by GnuPG, so only enable it if you accept that part of the event description will be sent out in clear-text.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'event_alert_metadata_only' => [
                    'name' => __('Send Event metadata only'),
                    'description' => __('Send just event metadata (attributes and objects will be omitted) for event alert.'),
                    'default' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'publish_alerts_summary_only' => [
                    'name' => __('Summarise publish alert'),
                    'type' => 'boolean',
                    'description' => __('Only send a summary of the publish alert, rather than the full contents of the event.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'threatlevel_in_email_subject' => [
                    'name' => __('Include Event threat level'),
                    'type' => 'boolean',
                    'description' => __('Put the event threat level in the notification E-mail subject.'),
                    'default' => true,
                    'test' => 'testBool',
                ],
                'email_subject_tag' => [
                    'name' => __('E-mail subject Tag'),
                    'type' => 'string',
                    'description' => __('If this tag predicate is set on an event it\'s value will be sent in the E-mail subject. If the tag is not set the email_subject_TLP_string will be used.'),
                    'default' => 'tlp',
                    'test' => 'testForEmpty',
                ],
                'email_subject_TLP_string' => [
                    'name' => __('E-mail subject default Tag'),
                    'type' => 'string',
                    'description' => __('This is the TLP string for e-mails when email_subject_tag is not found.'),
                    'default' => 'tlp:amber',
                    'test' => 'testForEmpty',
                ],
                'email_subject_include_tag_name' => [
                    'name' => __('Email subject Tag show only tag value'),
                    'type' => 'boolean',
                    'description' => __('Include in name of the email_subject_tag in the subject. When false only the tag value is used.'),
                    'default' => true,
                    'test' => 'testBool',
                ],
            ],
            'E-mails for Users' => [
                'newUserText' => [
                    'name' => __('Account creation e-mail message'),
                    'type' => 'textarea',
                    'description' => __('The message sent to the user after account creation (has to be sent manually from the administration interface). Use \\n for line-breaks. The following variables will be automatically replaced in the text: $password = a new temporary password that MISP generates, $username = the user\'s e-mail address, $misp = the url of this instance, $org = the organisation that the instance belongs to, as set in MISP.org, $contact = the e-mail address used to contact the support team, as set in MISP.contact. For example, "the password for $username is $password" would appear to a user with the e-mail address user@misp.org as "the password for user@misp.org is hNamJae81".'),
                    'default' => 'Dear new MISP user,\n\nWe would hereby like to welcome you to the $org MISP community.\n\n Use the credentials below to log into MISP at $misp, where you will be prompted to manually change your password to something of your own choice.\n\nUsername: $username\nPassword: $password\n\nIf you have any questions, don\'t hesitate to contact us at: $contact.\n\nBest regards,\nYour $org MISP support team',
                    'test' => 'testPasswordResetText',
                ],
                'passwordResetText' => [
                    'name' => __('Password reset e-mail message'),
                    'type' => 'textarea',
                    'description' => __('The message sent to the users when a password reset is triggered. Use \\n for line-breaks. The following variables will be automatically replaced in the text: $password = a new temporary password that MISP generates, $username = the user\'s e-mail address, $misp = the url of this instance, $contact = the e-mail address used to contact the support team, as set in MISP.contact. For example, "the password for $username is $password" would appear to a user with the e-mail address user@misp.org as "the password for user@misp.org is hNamJae81".'),
                    'default' => 'Dear MISP user,\n\nA password reset has been triggered for your account. Use the below provided temporary password to log into MISP at $misp, where you will be prompted to manually change your password to something of your own choice.\n\nUsername: $username\nYour temporary password: $password\n\nIf you have any questions, don\'t hesitate to contact us at: $contact.\n\nBest regards,\nYour $org MISP support team',
                    'test' => 'testPasswordResetText',
                ],
            ],
        ],
        'Redis' => [
            'redis_host' => [
                'name' => __('Redis host'),
                'type' => 'string',
                'description' => __('The host running the redis server to be used for generic MISP tasks such as caching. This is not to be confused by the redis server used by the background processing.'),
                'default' => '127.0.0.1',
                'test' => 'testForEmpty',
            ],
            'redis_port' => [
                'name' => __('Redis port'),
                'type' => 'integer',
                'description' => __('The port used by the redis server to be used for generic MISP tasks such as caching. This is not to be confused by the redis server used by the background processing.'),
                'default' => 6379,
                'test' => 'testForNumeric',
            ],
            'redis_database' => [
                'name' => __('Redis database'),
                'type' => 'integer',
                'description' => __('The database on the redis server to be used for generic MISP tasks. If you run more than one MISP instance, please make sure to use a different database on each instance.'),
                'default' => 13,
                'test' => function($value, $setting, $validator) {
                    $validator->range('value', [0, 13]);
                    return testValidator($value, $validator);
                },
                'beforeSave' => function($value, $setting, $validator) {
                    $validator->range('value', [0, 13]);
                    return testValidator($value, $validator);
                },
            ],
            'redis_password' => [
                'name' => __('Redis password'),
                'type' => 'string',
                'description' => __('The password on the redis server (if any) to be used for generic MISP tasks.'),
                'default' => '',
                'redacted' => true
            ],
        ]
    ],
    'Encryption' => [
        'GnuPG' => [
            'GnuPG' => [
                'binary' => [
                    'name' => __('GnuPG binary path'),
                    'type' => 'string',
                    'description' => __('The location of the GnuPG executable. If you would like to use a different GnuPG executable than /usr/bin/gpg, you can set it here. If the default is fine, just keep the setting suggested by MISP.'),
                    'default' => '/usr/bin/gpg',
                    'test' => 'testForGPGBinary',
                    'cli_only' => 1
                ],
                'homedir' => [
                    'name' => __('GnuPG homedir'),
                    'type' => 'string',
                    'description' => __('The location of the GnuPG homedir.'),
                    'test' => 'testForEmpty',
                ],
                'onlyencrypted' => [
                    'name' => __('Prevent sending unencrypted e-mails to users not having a PGP key'),
                    'type' => 'boolean',
                    'description' => __('Allow (false) unencrypted e-mails to be sent to users that don\'t have a GnuPG key.'),
                    'default' => true,
                    'test' => 'testBool',
                ],
                'bodyonlyencrypted' => [
                    'name' => __('Prevent e-mails body to contain unencrypted data'),
                    'type' => 'boolean',
                    'description' => __('Allow (false) the body of unencrypted e-mails to contain details about the event.'),
                    'default' => true,
                    'test' => 'testBool',
                ],
                'sign' => [
                    'name' => __('Sign e-mails'),
                    'type' => 'boolean',
                    'description' => __('Enable the signing of GnuPG emails. By default, GnuPG emails are signed'),
                    'default' => true,
                    'test' => 'testBool',
                ],
                'email' => [
                    'name' => __('E-mail address of the GnuPG key'),
                    'type' => 'string',
                    'description' => __('The e-mail address that the instance\'s GnuPG key is tied to.'),
                    'test' => 'testForEmpty',
                    'dependsOn' => 'sign'
                ],
                'password' => [
                    'name' => __('Password of the GnuPG key'),
                    'type' => 'string',
                    'description' => __('The password (if it is set) of the GnuPG key of the instance.'),
                    'default' => '',
                    'test' => 'testForEmpty',
                    'redacted' => true
                ],
                'obscure_subject' => [
                    'name' => __('Obscure subject of encrypted e-mails'),
                    'type' => 'boolean',
                    'description' => __('When enabled, the subject in signed and encrypted e-mails will not be sent in unencrypted form.'),
                    'default' => true,
                    'test' => 'testBool',
                ],
            ]
        ],
        'S/MIME' => [
            'S/MIME' => [
                'enabled' => [
                    'name' => __('Enable S/MIME encryption'),
                    'type' => 'boolean',
                    'description' => __('Enable S/MIME encryption. The encryption posture of the GnuPG.onlyencrypted and GnuPG.bodyonlyencrypted settings are inherited if S/MIME is enabled.'),
                    'default' => true,
                    'test' => 'testBool',
                ],
                'email' => [
                    'name' => __('E-mail address of the S/MIME key'),
                    'type' => 'string',
                    'description' => __('The e-mail address that the instance\'s S/MIME key is tied to.'),
                    'default' => '',
                    'test' => 'testForEmpty',
                    'dependsOn' => 'enabled',
                ],
                'cert_public_sign' => [
                    'name' => __('Public signing certificate location'),
                    'type' => 'string',
                    'description' => __('The location of the public half of the signing certificate.'),
                    'default' => '/var/www/MISP/.smime/email@address.com.pem',
                    'test' => 'testForEmpty',
                    'dependsOn' => 'enabled',
                ],
                'key_sign' => [
                    'name' => __('Private signing certificate location'),
                    'type' => 'string',
                    'description' => __('The location of the private half of the signing certificate.'),
                    'default' => '/var/www/MISP/.smime/email@address.com.key',
                    'test' => 'testForEmpty',
                    'dependsOn' => 'enabled',
                ],
                'password' => [
                    'name' => __('Password of the S/MIME key'),
                    'type' => 'string',
                    'description' => __('The password (if it is set) of the S/MIME key of the instance.'),
                    'default' => '',
                    'test' => 'testForEmpty',
                    'redacted' => true,
                    'dependsOn' => 'enabled',
                ],
            ]
        ]
    ],
    'Proxy' => [
        'Proxy' => [
            'host' => [
                'name' => __('Host'),
                'description' => __('The hostname of an HTTP proxy for outgoing sync requests. Leave empty to not use a proxy.'),
                'default' => '',
                'test' => 'testForEmpty',
                'type' => 'string',
            ],
            'port' => [
                'name' => __('Port'),
                'description' => __('The TCP port for the HTTP proxy.'),
                'test' => 'testForNumeric',
                'type' => 'integer',
                'dependsOn' => 'host',
            ],
            'method' => [
                'name' => __('Authentication Method'),
                'description' => __('The authentication method for the HTTP proxy. Currently supported are Basic or Digest. Leave empty for no proxy authentication.'),
                'default' => '',
                'test' => 'testForEmpty',
                'type' => 'string',
                'dependsOn' => 'host',
            ],
            'user' => [
                'name' => __('Authentication user'),
                'description' => __('The authentication username for the HTTP proxy.'),
                'test' => 'testForEmpty',
                'type' => 'string',
                'dependsOn' => 'method',
            ],
            'password' => [
                'name' => __('Authentication password'),
                'description' => __('The authentication password for the HTTP proxy.'),
                'test' => 'testForEmpty',
                'type' => 'string',
                'dependsOn' => 'method',
                'redacted' => true,
            ],
        ],
    ],
    'Security' => [
        'General' => [
            'osuser' => [
                'name' => __('Server OS User'),
                'type' => 'string',
                'description' => __('The Unix user MISP (php) is running as'),
                'default' => 'www-data',
                'test' => 'testForEmpty',
            ],
            'csp_enforce' => [
                'name' => __('Enforce Content Security Policy (CSP)'),
                'type' => 'boolean',
                'description' => __('Enforce CSP. Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. When disabled, violations will be just logged.'),
                'default' => false,
                'test' => 'testBool',
            ],
            'force_https' => [
                'name' => __('Force HTTPS for insecure connections'),
                'type' => 'boolean',
                'description' => __('If enabled, MISP server will consider all requests as secure. This is usually useful when you run MISP behind reverse proxy that terminates HTTPS.'),
                'default' => false,
                'test' => 'testBool',
            ],
            'disable_browser_cache' => [
                'name' => __('Disable browser cache'),
                'type' => 'boolean',
                'description' => __('If enabled, HTTP headers that block browser cache will be send. Static files (like images or JavaScripts) will still be cached, but not generated pages.'),
                'default' => true,
                'test' => 'testBool',
            ],
            'check_sec_fetch_site_header' => [
                'name' => __('Enable Sec-Fetch-Site checking'),
                'type' => 'boolean',
                'description' => __('If enabled, any POST, PUT or AJAX request will be allow just when Sec-Fetch-Site header is not defined or contains "same-origin".'),
                'default' => true,
                'test' => 'testBool',
            ],
            'salt' => [
                'name' => __('Salt used for hashed passwords'),
                'type' => 'string',
                'description' => __('The salt used for the hashed passwords. You cannot reset this from the GUI, only manually from the settings.php file. Keep in mind, this will invalidate all passwords in the database.'),
                'test' => 'testSalt',
                'editable' => false,
                'redacted' => true
            ],
            'CORS' => [
                'allow_cors' => [
                    'name' => __('Enable CORS'),
                    'type' => 'boolean',
                    'description' => __('Allow cross-origin requests to this instance, matching origins given in Security.cors_origins. Set to false to totally disable'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'cors_origins' => [
                    'name' => __('CORS Origins'),
                    'type' => 'string',
                    'description' => __('Set the origins from which MISP will allow cross-origin requests. Useful for external integration. Comma seperate if you need more than one.'),
                    'test' => 'testForEmpty',
                    'dependsOn' => 'allow_cors',
                ],
            ],
        ],
        'Debug' => [
            'Debug' => [
                'debug' => [
                    'name' => __('Debug level'),
                    'type' => 'select',
                    'description' => __('The debug level of the instance, always use 0 for production instances.'),
                    'default' => 0,
                    'test' => 'testDebug',
                    'options' => [0 => 'Debug off', 1 => 'Debug on', 2 => 'Debug + SQL dump'],
                ],
                'site_admin_debug' => [
                    'name' => __('Debug level for site admins'),
                    'type' => 'boolean',
                    'description' => __('The debug level of the instance for site admins. This feature allows site admins to run debug mode on a live instance without exposing it to other users. The most verbose option of debug and site_admin_debug is used for site admins.'),
                    'default' => false,
                    'test' => 'testDebugAdmin',
                ],
            ]
        ],
        'Authorization Keys' => [
            'Advanced Authorization Key System' => [
                'advanced_authkeys' => [
                    'name' => __('Enable advanced authkey system'),
                    'type' => 'boolean',
                    'description' => __('Advanced authkeys will allow each user to create and manage a set of authkeys for themselves, each with individual expirations and comments. API keys are stored in a hashed state and can no longer be recovered from MISP. Users will be prompted to note down their key when creating a new authkey. You can generate a new set of API keys for all users on demand in the diagnostics page, or by triggering %s.', sprintf('<a href="%s/servers/serverSettings/diagnostics#advanced_authkey_update">%s</a>', 'base_url', __('the advanced upgrade'))),
                    'default' => true,
                    'test' => 'testBool',
                ],
                'advanced_authkeys_validity' => [
                    'name' => __('Default value for validity'),
                    'type' => 'integer',
                    'description' => __('Maximal key lifetime in days. Use can limit that validity even more. Just newly created keys will be affected. When not set, key validity is not limited.'),
                    'default' => '',
                    'test' => 'testForNumeric',
                    'dependsOn' => 'advanced_authkeys',
                ],
            ],
            'allow_unsafe_apikey_named_param' => [
                'name' => __('Accept API key in URL as named parameter'),
                'type' => 'boolean',
                'description' => __('Allows passing the API key via the named url parameter "apikey" - highly recommended not to enable this, but if you have some dodgy legacy tools that cannot pass the authorization header it can work as a workaround. Again, only use this as a last resort.'),
                'default' => false,
                'test' => 'testBoolFalse',
            ],
        ],
        'Session' => [
            'Session' => [
                'autoRegenerate' => [
                    'name' => __('Auto-regenerate sessions after several requests'),
                    'type' => 'boolean',
                    'description' => __('Set to true to automatically regenerate sessions after x number of requests. This might lead to the user getting de-authenticated and is frustrating in general, so only enable it if you really need to regenerate sessions. (Not recommended)'),
                    'default' => false,
                    'test' => 'testBoolFalse',
                ],
                'checkAgent' => [
                    'name' => __('Enable user agent checks'),
                    'type' => 'boolean',
                    'description' => __('Set to true to check for the user agent string in each request. This can lead to occasional logouts (not recommended).'),
                    'default' => false,
                    'test' => 'testBoolFalse',
                ],
                'defaults' => [
                    'name' => __('Default session storage'),
                    'type' => 'select',
                    'description' => __('The session type used by MISP. The default setting is php, which will use the session settings configured in php.ini for the session data (supported options: php, database). The recommended option is php and setting your PHP up to use redis sessions via your php.ini. Just add \'session.save_handler = redis\' and "session.save_path = \'tcp://localhost:6379\'" (replace the latter with your redis connection) to php.ini'),
                    'default' => 'php',
                    'test' => 'testForSessionDefaults',
                    'options' => ['php' => 'php', 'database' => 'database', 'cake' => 'cake', 'cache' => 'cache'],
                ],
                'timeout' => [
                    'name' => __('Session timeout (minute)'),
                    'type' => 'integer',
                    'description' => __('The timeout duration of sessions (in MINUTES). 0 does not mean infinite for the PHP session handler, instead sessions will invalidate immediately.'),
                    'default' => 600,
                    'test' => 'testForNumeric',
                ],
                'cookieTimeout' => [
                    'name' => __('Session cookie timeout (minute)'),
                    'type' => 'integer',
                    'description' => __('The expiration of the cookie (in MINUTES). The session timeout gets refreshed frequently, however the cookies do not. Generally it is recommended to have a much higher cookie_timeout than timeout.'),
                    'default' => 3600,
                    'test' => 'testForCookieTimeout',
                ],
                'authkey_keep_session' => [
                    'name' => __('Keep session between API requests'),
                    'type' => 'boolean',
                    'description' => __('When enabled, session is kept between API requests.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
            ],
        ],
        'Email OTP' => [
            'Email OTP' => [
                'email_otp_enabled' => [
                    'name' => __('Enable e-mail OTP'),
                    'type' => 'boolean',
                    'description' => __('Enable two step authentication with a OTP sent by email. Requires e-mailing to be enabled. Warning: You cannot use it in combination with external authentication plugins.'),
                    'default' => false,
                    'test' => 'testBool',
                    'beforeSave' => 'otpBeforeHook',
                ],
                'email_otp_length' => [
                    'name' => __('OTP code length'),
                    'type' => 'integer',
                    'description' => __('Define the length of the OTP code sent by email'),
                    'default' => '6',
                    'test' => 'testForNumeric',
                ],
                'email_otp_validity' => [
                    'name' => __('OTP validity time (minutes)'),
                    'type' => 'integer',
                    'description' => __('Define the validity (in minutes) of the OTP code sent by email'),
                    'default' => '5',
                    'test' => 'testForNumeric',
                ],
                'email_otp_text' => [
                    'name' => __('OTP message'),
                    'type' => 'textarea',
                    'description' => __('The message sent to the user when a new OTP is requested. Use \\n for line-breaks. The following variables will be automatically replaced in the text: $otp = the new OTP generated by MISP, $username = the user\'s e-mail address, $org the Organisation managing the instance, $misp = the url of this instance, $contact = the e-mail address used to contact the support team (as set in MISP.contact), $ip the IP used to complete the first step of the login and $validity the validity time in minutes.'),
                    'default' => 'Dear MISP user,\n\nYou have attempted to login to MISP ($misp) from $ip with username $username.\n\n Use the following OTP to log into MISP: $otp\n This code is valid for the next $validity minutes.\n\nIf you have any questions, don\'t hesitate to contact us at: $contact.\n\nBest regards,\nYour $org MISP support team',
                    'test' => 'testForEmpty',
                ],
                'email_otp_exceptions' => [
                    'name' => __('E-mail address OTP allowlist'),
                    'type' => 'textarea',
                    'description' => __('A comma separated list of emails for which the OTP is disabled. Note that if you remove someone from this list, the OTP will only be asked at next login.'),
                    'default' => '',
                    'test' => 'testForEmpty',
                ],
            ],
        ],
        'REST Client' => [
            'REST Client' => [
                'rest_client_enable_arbitrary_urls' => [
                    'name' => __('Allow arbitrary URLs'),
                    'type' => 'boolean',
                    'description' => __('Enable this setting if you wish for users to be able to query any arbitrary URL via the rest client. Keep in mind that queries are executed by the MISP server, so internal IPs in your MISP\'s network may be reachable.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'rest_client_baseurl' => [
                    'name' => __('Base URL'),
                    'type' => 'string',
                    'description' => __('If left empty, the baseurl of your MISP is used. However, in some instances (such as port-forwarded VM installations) this will not work. You can override the baseurl with a url through which your MISP can reach itself (typically https://127.0.0.1 would work).'),
                    'default' => '',
                ],
            ],
        ],
        'Syslog' => [
            'Syslog' => [
                'syslog' => [
                    'name' => __('Enable syslog'),
                    'type' => 'boolean',
                    'description' => __('Enable this setting to pass all audit log entries directly to syslog. Keep in mind, this is verbose and will include user, organisation, event data.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'syslog_to_stderr' => [
                    'name' => __('Write to stderr'),
                    'type' => 'boolean',
                    'description' => __('Write syslog messages also to standard error output.'),
                    'default' => true,
                    'test' => 'testBool',
                ],
                'syslog_ident' => [
                    'name' => __('Identifier to be added to each message'),
                    'type' => 'string',
                    'description' => __('Syslog message identifier.'),
                    'default' => '',
                    'test' => 'testForEmpty',
                ],
            ],
        ],
        'Password Policy' => [
            'Password Policy' => [
                'password_policy_length' => [
                    'name' => __('Password length requirement'),
                    'type' => 'integer',
                    'description' => __('Password length requirement. If it is not set or it is set to 0, then the default value is assumed (12).'),
                    'default' => '12',
                    'test' => 'testPasswordLength',
                ],
                'password_policy_complexity' => [
                    'name' => __('Password complexity policy'),
                    'type' => 'string',
                    'description' => __('Password complexity requirement. Leave it empty for the default setting (3 out of 4, with either a digit or a special char) or enter your own regex. Keep in mind that the length is checked in another key. Default (simple 3 out of 4 or minimum 16 characters): /^((?=.*\d)|(?=.*\W+))(?![\n])(?=.*[A-Z])(?=.*[a-z]).*$|.{16,}/'),
                    'default' => '/^((?=.*\d)|(?=.*\W+))(?![\n])(?=.*[A-Z])(?=.*[a-z]).*$|.{16,}/',
                    'test' => 'testPasswordRegex',
                ],
                'require_password_confirmation' => [
                    'name' => __('Require password confirmation'),
                    'type' => 'boolean',
                    'description' => __('Enabling this setting will require users to submit their current password on any edits to their profile (including a triggered password change). For administrators, the confirmation will be required when changing the profile of any user. Could potentially mitigate an attacker trying to change a compromised user\'s password in order to establish persistance, however, enabling this feature will be highly annoying to users.'),
                    'default' => true,
                    'test' => 'testBool',
                ],
            ],
        ],
        'Feeds' => [
            'Feeds' => [
                'disable_local_feed_access' => array(
                    'name' => __('Disable local feed'),
                    'type' => 'boolean',
                    'description' => __('Disabling this setting will allow the creation/modification of local feeds (as opposed to network feeds). Enabling this setting will restrict feed sources to be network based only. When disabled, keep in mind that a malicious site administrator could get access to any arbitrary file on the system that the apache user has access to. Make sure that proper safe-guards are in place.'),
                    'default' => false,
                    'test' => 'testBool',
                    'cli_only' => 1
                ),
            ],
        ],
        'Headers' => [
            'Headers' => [
                'username_in_response_header' => [
                    'name' => __('Include username in the HTTP response header'),
                    'type' => 'boolean',
                    'description' => __('When enabled, logged in username will be included in X-Username HTTP response header. This is useful for request logging on webserver/proxy side.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
            ],
        ],
        'External Authentication' => [
            'auth_enforced' => [
                'name' => __('Disable login authentication when external authentication is enabled'),
                'type' => 'boolean',
                'description' => __('This setting can be enabled if an external auth provider is used. When set to true, it will disable the default form authentication.'),
                'default' => false,
                'test' => 'testBool',
            ],
        ],
        'CustomAuth' => [
            'CustomAuth' => [
                'CustomAuth_enable' => [
                    'name' => __('Enable CustomAuth'),
                    'type' => 'boolean',
                    'description' => __('Enable this functionality if you would like to handle the authentication via an external tool and authenticate with MISP using a custom header.'),
                    'default' => false,
                    'test' => 'testBool',
                    'beforeSave' => 'customAuthBeforeHook'
                ],
                'CustomAuth_header' => [
                    'name' => __('CustomAuth Header'),
                    'type' => 'string',
                    'description' => __('Set the header that MISP should look for here. If left empty it will default to the Authorization header.'),
                    'default' => 'Authorization',
                    'test' => 'testForEmpty',
                ],
                'CustomAuth_use_header_namespace' => [
                    'name' => __('Enable header namespace'),
                    'type' => 'boolean',
                    'description' => __('Use a header namespace for the auth header - default setting is enabled'),
                    'default' => true,
                    'test' => 'testBool',
                ],
                'CustomAuth_header_namespace' => [
                    'name' => __('Header namespace'),
                    'type' => 'string',
                    'description' => __('The default header namespace for the auth header - default setting is HTTP_'),
                    'default' => 'HTTP_',
                    'test' => 'testForEmpty',
                    'dependsOn' => 'CustomAuth_use_header_namespace',
                ],
                'CustomAuth_required' => [
                    'name' => __('Turn off traditional login'),
                    'type' => 'boolean',
                    'description' => __('If this setting is enabled then the only way to authenticate will be using the custom header. Alternatively, you can run in mixed mode that will log users in via the header if found, otherwise users will be redirected to the normal login page.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'CustomAuth_only_allow_source' => [
                    'name' => __('Authentication source allowed URL'),
                    'type' => 'string',
                    'description' => __('If you are using an external tool to authenticate with MISP and would like to only allow the tool\'s url as a valid point of entry then set this field. '),
                    'default' => '',
                    'test' => 'testForEmpty',
                ],
                'CustomAuth_name' => [
                    'name' => __('Authentication method display name'),
                    'type' => 'string',
                    'description' => __('The name of the authentication method, this is cosmetic only and will be shown on the user creation page and logs.'),
                    'default' => 'External authentication',
                    'test' => 'testForEmpty',
                ],
                'CustomAuth_disable_logout' => [
                    'name' => __('Disable log out button'),
                    'type' => 'boolean',
                    'description' => __('Disable the logout button for users authenticate with the external auth mechanism.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'CustomAuth_custom_password_reset' =>[
                    'name' => __('Password reset custom URL'),
                    'type' => 'string',
                    'description' => __('Provide your custom authentication users with an external URL to the authentication system to reset their passwords.'),
                    'default' => '',
                    'test' => 'testForEmpty',
                ],
                'CustomAuth_custom_logout' => [
                    'name' => __('Logout custom URL'),
                    'type' => 'string',
                    'description' => __('Provide a custom logout URL for your users that will log them out using the authentication system you use.'),
                    'default' => '',
                    'test' => 'testForEmpty',
                ],
            ],
        ],
        'SecureAuth' => [
            'SecureAuth' => [
                'amount' => [
                    'name' => __('Bruteforce protection retry threshold'),
                    'type' => 'string',
                    'description' => __('The number of tries a user can try to login and fail before the bruteforce protection kicks in.'),
                    'default' => 5,
                    'test' => 'testForNumeric',
                ],
                'expire' => [
                    'name' => __('Bruteforce protection ban time (seconde)'),
                    'type' => 'string',
                    'description' => __('The duration (in seconds) of how long the user will be locked out when the allowed number of login attempts are exhausted.'),
                    'default' => 300,
                    'test' => 'testForNumeric',
                ],
            ],
        ],
    ],
    'Features' => [
        'Exports' => [
            'disable_cached_exports' => [
                'name' => __('Cached exports disabled'),
                'type' => 'boolean',
                'description' => __('Cached exports can take up a considerable amount of space and can be disabled instance wide using this setting. Disabling the cached exports is not recommended as it\'s a valuable feature, however, if your server is having free space issues it might make sense to take this step.'),
                'default' => false,
                'test' => 'testDisableCache',
                'afterSave' => 'disableCacheAfterHook',
            ],
            'cached_attachments' => [
                'name' => __('Allow attachments in cached export file'),
                'type' => 'boolean',
                'description' => __('Allow the export caches to include the encoded attachments.'),
                'default' => '',
                'test' => 'testBool',
            ],
        ],
        'Import' => [
            'take_ownership_xml_import' => array(
                'name' => __('Enable ownership override decision for manual Event import'),
                'type' => 'boolean',
                'description' => __('Allows users to take ownership of an event uploaded via the "Add MISP XML" button. This allows spoofing the creator of a manually imported event, also breaking possibly breaking the original intended releasability. Synchronising with an instance that has a different creator for the same event can lead to unwanted consequences.'),
                'default' => false,
                'test' => 'testBool',
            ),
        ],
        'Tagging' => [
            'tagging' => [
                'name' => __('Enable tagging'),
                'type' => 'boolean',
                'description' => __('Enable the tagging feature of MISP. This is highly recommended.'),
                'default' => true,
                'test' => 'testBool',
            ],
        ],
        'Delegation' => [
            'delegation' => [
                'name' => __('Enable delegation'),
                'type' => 'boolean',
                'description' => __('This feature allows users to create org only events and ask another organisation to take ownership of the event. This allows organisations to remain anonymous by asking a partner to publish an event for them.'),
                'default' => false,
                'test' => 'testBool',
            ],
        ],
        'Blocklisting' => [
            'enableEventBlocklisting' => [
                'name' => __('Event Blocklist enabled'),
                'type' => 'boolean',
                'description' => __('Since version 2.3.107 you can start blocklisting event UUIDs to prevent them from being pushed to your instance. This functionality will also happen silently whenever an event is deleted, preventing a deleted event from being pushed back from another instance.'),
                'default' => true,
                'test' => 'testBool'
            ],
            'enableOrgBlocklisting' => [
                'name' => __('Organisation Blocklist enabled'),
                'type' => 'boolean',
                'description' => __('Blocklisting organisation UUIDs to prevent the creation of any event created by the blocklisted organisation.'),
                'default' => true,
                'test' => 'testBool'
            ],
        ],
        'Users' => [
            'Monitoring' => [
                'user_monitoring_enabled' => [
                    'name' => __('Enable user monitoring'),
                    'type' => 'boolean',
                    'description' => __('Enables the functionality to monitor users - thereby enabling all logging functionalities for a single user. This functionality is intrusive and potentially heavy on the system - use it with care.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
            ],
            'User Management' => [
                'allow_self_registration' => [
                    'name' => __('Enable user self registration'),
                    'type' => 'boolean',
                    'description' => __('Enabling this setting will allow users to have access to the pre-auth registration form. This will create an inbox entry for administrators to review.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'self_registration_message' => [
                    'name' => __('User self registration message'),
                    'type' => 'textarea',
                    'description' => __('The message sent shown to anyone trying to self-register.'),
                    'default' => 'If you would like to send us a registration request, please fill out the form below. Make sure you fill out as much information as possible in order to ease the task of the administrators.',
                ],
                'disableUserSelfManagement' => [
                    'name' => __('Disable User self-management'),
                    'type' => 'boolean',
                    'description' => __('Turn the setting on to only allow Org and Site admins to edit a user\'s profile.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'disable_user_login_change' => [
                    'name' => __('Disable User email change'),
                    'type' => 'boolean',
                    'description' => __('When enabled only Site admins can change user email. This should be enabled if you manage user logins by external system.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'disable_user_password_change' => [
                    'name' => __('Disable User password change'),
                    'type' => 'boolean',
                    'description' => __('When enabled only Site admins can change user password. This should be enabled if you manage user passwords by external system.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'disable_user_add' => [
                    'name' => __('Disable User creation'),
                    'type' => 'boolean',
                    'description' => __('When enabled, Org Admins will not be able to add new users. This should be enabled if you manage users by external system.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
            ],
        ],
    ],
    'Plugins' => [
        'RPZ' => [
            'RPZ' => [
                'RPZ_policy' => [
                    'name' => __('Policy action'),
                    'type' => 'select',
                    'description' => __('The default policy action for the values added to the RPZ.'),
                    'default' => 1,
                    'test' => 'testForRPZBehaviour',
                    'options' => [0 => 'DROP', 1 => 'NXDOMAIN', 2 => 'NODATA', 3 => 'Local-Data', 4 => 'PASSTHRU', 5 => 'TCP-only'],
                ],
                'RPZ_walled_garden' => [
                    'name' => __('Walled garden'),
                    'type' => 'string',
                    'description' => __('The default walled garden used by the RPZ export if the Local-Data policy setting is picked for the export.'),
                    'default' => '127.0.0.1',
                    'test' => 'testForEmpty',
                ],
                'RPZ_serial' => [
                    'name' => __('Serial'),
                    'type' => 'string',
                    'description' => __('The serial in the SOA portion of the zone file. (numeric, best practice is yyyymmddrr where rr is the two digit sub-revision of the file. $date will automatically get converted to the current yyyymmdd, so $date00 is a valid setting). Setting it to $time will give you an unixtime-based serial (good then you need more than 99 revisions per day).'),
                    'default' => '$date00',
                    'test' => 'testForRPZSerial',
                ],
                'RPZ_refresh' => [
                    'name' => __('Refresh'),
                    'type' => 'string',
                    'description' => __('The refresh specified in the SOA portion of the zone file. (in seconds, or shorthand duration such as 15m)'),
                    'default' => '2h',
                    'test' => 'testForRPZDuration',
                ],
                'RPZ_retry' => [
                    'name' => __('Retry'),
                    'type' => 'string',
                    'description' => __('The retry specified in the SOA portion of the zone file. (in seconds, or shorthand duration such as 15m)'),
                    'default' => '30m',
                    'test' => 'testForRPZDuration',
                ],
                'RPZ_expiry' => [
                    'name' => __('Expiry'),
                    'type' => 'string',
                    'description' => __('The expiry specified in the SOA portion of the zone file. (in seconds, or shorthand duration such as 15m)'),
                    'default' => '30d',
                    'test' => 'testForRPZDuration',
                ],
                'RPZ_minimum_ttl' => [
                    'name' => __('Minimum TTL'),
                    'type' => 'string',
                    'description' => __('The minimum TTL specified in the SOA portion of the zone file. (in seconds, or shorthand duration such as 15m)'),
                    'default' => '1h',
                    'test' => 'testForRPZDuration',
                ],
                'RPZ_ttl' => [
                    'name' => __('TTL'),
                    'type' => 'string',
                    'description' => __('The TTL of the zone file. (in seconds, or shorthand duration such as 15m)'),
                    'default' => '1w',
                    'test' => 'testForRPZDuration',
                ],
                'RPZ_ns' => [
                    'name' => __('Namesever'),
                    'type' => 'string',
                    'description' => __('Nameserver'),
                    'default' => 'localhost.',
                    'test' => 'testForEmpty',
                ],
                'RPZ_ns_alt' => [
                    'name' => __('Alternate nameserver'),
                    'type' => 'string',
                    'description' => __('Alternate nameserver'),
                    'default' => '',
                    'test' => 'testForEmpty',
                ],
                'RPZ_email' => [
                    'name' => __('Email address'),
                    'type' => 'string',
                    'description' => __('The e-mail address specified in the SOA portion of the zone file.'),
                    'default' => 'root.localhost',
                    'test' => 'testForEmpty',
                ],
            ],
        ],
        'Kafka' => [
            'Kafka_enable' => [
                'name' => __('Enable Kafka'),
                'type' => 'boolean',
                'description' => __('Enables or disables the Kafka pub feature of MISP. Make sure that you install the requirements for the plugin to work. Refer to the installation instructions for more information.'),
                'default' => false,
                'test' => 'testBool',
            ],
            'Configuration' => [
                'Kafka_brokers' => [
                    'name' => __('Brokers'),
                    'type' => 'string',
                    'description' => __('A comma separated list of Kafka bootstrap brokers'),
                    'default' => 'kafka:9092',
                    'test' => 'testForEmpty',
                    'dependsOn' => 'Kafka_enable',
                ],
                'Kafka_rdkafka_config' => [
                    'name' => __('RDKafka ini file path'),
                    'type' => 'string',
                    'description' => __('A path to an ini file with configuration options to be passed to rdkafka. Section headers in the ini file will be ignored.'),
                    'default' => '/etc/rdkafka.ini',
                    'test' => 'testForEmpty',
                    'dependsOn' => 'Kafka_enable',
                ],
                'Kafka_include_attachments' => [
                    'name' => __('Include attachments'),
                    'type' => 'boolean',
                    'description' => __('Enable this setting to include the base64 encoded payloads of malware-samples/attachments in the output.'),
                    'default' => false,
                    'test' => 'testBool',
                    'dependsOn' => 'Kafka_enable',
                ],
            ],
            'Topics' => [
                'Kafka_event_notifications_enable' => [
                    'name' => __('Enable topic: Event'),
                    'type' => 'boolean',
                    'description' => __('Enables or disables the publishing of any event creations/edits/deletions.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'Kafka_event_notifications_topic' => [
                    'name' => __('Topic name: Event'),
                    'type' => 'string',
                    'description' => __('Topic for publishing event creations/edits/deletions.'),
                    'default' => 'misp_event',
                    'test' => 'testForEmpty',
                    'dependsOn' => 'Kafka_event_notifications_enable'
                ],
                'Kafka_event_publish_notifications_enable' => [
                    'name' => __('Enable topic: Event publishing'),
                    'type' => 'boolean',
                    'description' => __('If enabled it will publish to Kafka the event at the time that the event gets published in MISP. Event actions (creation or edit) will not be published to Kafka.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'Kafka_event_publish_notifications_topic' => [
                    'name' => __('Topic name: Event publishing'),
                    'type' => 'string',
                    'description' => __('Topic for publishing event information on publish.'),
                    'default' => 'misp_event_publish',
                    'test' => 'testForEmpty',
                    'dependsOn' => '',
                ],
                'Kafka_object_notifications_enable' => [
                    'name' => __('Enable topic: Object'),
                    'type' => 'boolean',
                    'description' => __('Enables or disables the publishing of any object creations/edits/deletions.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'Kafka_object_notifications_topic' => [
                    'name' => __('Topic name: Object'),
                    'type' => 'string',
                    'description' => __('Topic for publishing object creations/edits/deletions.'),
                    'default' => 'misp_object',
                    'test' => 'testForEmpty',
                    'dependsOn' => '',
                ],
                'Kafka_object_reference_notifications_enable' => [
                    'name' => __('Enable topic: Object Reference'),
                    'type' => 'boolean',
                    'description' => __('Enables or disables the publishing of any object reference creations/deletions.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'Kafka_object_reference_notifications_topic' => [
                    'name' => __('Topic name: Object Reference'),
                    'type' => 'string',
                    'description' => __('Topic for publishing object reference creations/deletions.'),
                    'default' => 'misp_object_reference',
                    'test' => 'testForEmpty',
                    'dependsOn' => '',
                ],
                'Kafka_attribute_notifications_enable' => [
                    'name' => __('Enable topic: Attribute'),
                    'type' => 'boolean',
                    'description' => __('Enables or disables the publishing of any attribute creations/edits/soft deletions.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'Kafka_attribute_notifications_topic' => [
                    'name' => __('Topic name: Attribute'),
                    'type' => 'string',
                    'description' => __('Topic for publishing attribute creations/edits/soft deletions.'),
                    'default' => 'misp_attribute',
                    'test' => 'testForEmpty',
                    'dependsOn' => '',
                ],
                'Kafka_shadow_attribute_notifications_enable' => [
                    'name' => __('Enable topic: Shadow Attribute'),
                    'type' => 'boolean',
                    'description' => __('Enables or disables the publishing of any proposal creations/edits/deletions.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'Kafka_shadow_attribute_notifications_topic' => [
                    'name' => __('Topic name: Shadow Attribute'),
                    'type' => 'string',
                    'description' => __('Topic for publishing proposal creations/edits/deletions.'),
                    'default' => 'misp_shadow_attribute',
                    'test' => 'testForEmpty',
                    'dependsOn' => 'Kafka_shadow_attribute_notifications_enable',
                ],
                'Kafka_tag_notifications_enable' => [
                    'name' => __('Enable topic: Tag'),
                    'type' => 'boolean',
                    'description' => __('Enables or disables the publishing of any tag creations/edits/deletions as well as tags being attached to / detached from various MISP elements.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'Kafka_tag_notifications_topic' => [
                    'name' => __('Topic name: Tag'),
                    'type' => 'string',
                    'description' => __('Topic for publishing tag creations/edits/deletions as well as tags being attached to / detached from various MISP elements.'),
                    'default' => 'misp_tag',
                    'test' => 'testForEmpty',
                    'dependsOn' => 'Kafka_tag_notifications_enable',
                ],
                'Kafka_sighting_notifications_enable' => [
                    'name' => __('Enable topic: Sighting'),
                    'type' => 'boolean',
                    'description' => __('Enables or disables the publishing of new sightings.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'Kafka_sighting_notifications_topic' => [
                    'name' => __('Topic name: Sighting'),
                    'type' => 'string',
                    'description' => __('Topic for publishing sightings.'),
                    'default' => 'misp_sighting',
                    'test' => 'testForEmpty',
                    'dependsOn' => 'Kafka_sighting_notifications_enable',
                ],
                'Kafka_user_notifications_enable' => [
                    'name' => __('Enable topic: User'),
                    'type' => 'boolean',
                    'description' => __('Enables or disables the publishing of new/modified users.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'Kafka_user_notifications_topic' => [
                    'name' => __('Topic name: User'),
                    'type' => 'string',
                    'description' => __('Topic for publishing new/modified users.'),
                    'default' => 'misp_user',
                    'test' => 'testForEmpty',
                    'dependsOn' => 'Kafka_user_notifications_enable',
                ],
                'Kafka_organisation_notifications_enable' => [
                    'name' => __('Enable topic: Organisation'),
                    'type' => 'boolean',
                    'description' => __('Enables or disables the publishing of new/modified organisations.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'Kafka_organisation_notifications_topic' => [
                    'name' => __('Topic name: Organisation'),
                    'type' => 'string',
                    'description' => __('Topic for publishing new/modified organisations.'),
                    'default' => 'misp_organisation',
                    'test' => 'testForEmpty',
                    'dependsOn' => 'Kafka_organisation_notifications_enable',
                ],
                'Kafka_audit_notifications_enable' => [
                    'name' => __('Enable topic: Audit'),
                    'type' => 'boolean',
                    'description' => __('Enables or disables the publishing of log entries. Keep in mind, this can get pretty verbose depending on your logging settings.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'Kafka_audit_notifications_topic' => [
                    'name' => __('Topic name: Audit'),
                    'type' => 'string',
                    'description' => __('Topic for publishing log entries.'),
                    'default' => 'misp_audit',
                    'test' => 'testForEmpty',
                    'dependsOn' => 'Kafka_audit_notifications_enable',
                ],
            ],
        ],
        'ZeroMQ' => [
            'ZeroMQ_enable' => [
                'name' => __('Enable ZeroMQ'),
                'type' => 'boolean',
                'description' => __('Enables or disables the pub/sub feature of MISP. Make sure that you install the requirements for the plugin to work. Refer to the installation instructions for more information.'),
                'default' => false,
                'test' => 'testBool',
            ],
            'Configuration' => [
                'ZeroMQ_host' => [
                    'name' => __('Host'),
                    'type' => 'string',
                    'description' => __('The host that the pub/sub feature will use.'),
                    'default' => '127.0.0.1',
                    'test' => 'testForEmpty',
                    'afterSave' => 'zmqAfterHook',
                    'dependsOn' => 'ZeroMQ_enable',
                ],
                'ZeroMQ_port' => [
                    'name' => __('Port'),
                    'type' => 'integer',
                    'description' => __('The port that the pub/sub feature will use.'),
                    'default' => 50000,
                    'test' => 'testForZMQPortNumber',
                    'afterSave' => 'zmqAfterHook',
                    'dependsOn' => 'ZeroMQ_enable',
                ],
                'ZeroMQ_username' => [
                    'name' => __('Username'),
                    'type' => 'string',
                    'description' => __('The username that client need to use to connect to ZeroMQ.'),
                    'default' => '',
                    'test' => 'testForEmpty',
                    'afterSave' => 'zmqAfterHook',
                    'dependsOn' => 'ZeroMQ_enable',
                ],
                'ZeroMQ_password' => [
                    'name' => __('Password'),
                    'type' => 'string',
                    'description' => __('The password that client need to use to connect to ZeroMQ.'),
                    'default' => '',
                    'test' => 'testForEmpty',
                    'afterSave' => 'zmqAfterHook',
                    'redacted' => true,
                    'dependsOn' => 'ZeroMQ_enable',
                ],
                'ZeroMQ_redis_host' => [
                    'name' => __('Redis Host'),
                    'type' => 'string',
                    'description' => __('Location of the Redis db used by MISP and the Python PUB script to queue data to be published.'),
                    'default' => 'localhost',
                    'test' => 'testForEmpty',
                    'afterHook' => 'zmqAfterHook',
                    'dependsOn' => 'ZeroMQ_enable',
                ],
                'ZeroMQ_redis_port' => [
                    'name' => __('Redis Port'),
                    'type' => 'integer',
                    'description' => __('The port that Redis is listening on.'),
                    'default' => 6379,
                    'test' => 'testForPortNumber',
                    'afterSave' => 'zmqAfterHook',
                    'dependsOn' => 'ZeroMQ_enable',
                ],
                'ZeroMQ_redis_password' => [
                    'name' => __('Redis Password'),
                    'type' => 'string',
                    'description' => __('The password, if set for Redis.'),
                    'default' => '',
                    'test' => 'testForEmpty',
                    'afterSave' => 'zmqAfterHook',
                    'dependsOn' => 'ZeroMQ_enable',
                ],
                'ZeroMQ_redis_database' => [
                    'name' => __('Redis Database'),
                    'type' => 'integer',
                    'description' => __('The database to be used for queuing messages for the pub/sub functionality.'),
                    'default' => 1,
                    'test' => 'testForRedisDatabase',
                    'afterSave' => 'zmqAfterHook',
                    'dependsOn' => 'ZeroMQ_enable',
                ],
                'ZeroMQ_redis_namespace' => [
                    'name' => __('Redis Namespace'),
                    'type' => 'string',
                    'description' => __('The namespace to be used for queuing messages for the pub/sub functionality.'),
                    'default' => 'mispq',
                    'test' => 'testForEmpty',
                    'afterSave' => 'zmqAfterHook',
                    'dependsOn' => 'ZeroMQ_enable',
                ],
                'ZeroMQ_include_attachments' => [
                    'name' => __('Include Attachments'),
                    'type' => 'boolean',
                    'description' => __('Enable this setting to include the base64 encoded payloads of malware-samples/attachments in the output.'),
                    'default' => false,
                    'test' => 'testBool',
                    'dependsOn' => 'ZeroMQ_enable',
                ],
            ],
            'Topics' => [
                'ZeroMQ_event_notifications_enable' => [
                    'name' => __('Enable topic: Event'),
                    'type' => 'boolean',
                    'description' => __('Enables or disables the publishing of any event creations/edits/deletions.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'ZeroMQ_object_notifications_enable' => [
                    'name' => __('Enable topic: Object'),
                    'type' => 'boolean',
                    'description' => __('Enables or disables the publishing of any object creations/edits/deletions.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'ZeroMQ_object_reference_notifications_enable' => [
                    'name' => __('Enable topic: Object Reference'),
                    'type' => 'boolean',
                    'description' => __('Enables or disables the publishing of any object reference creations/deletions.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'ZeroMQ_attribute_notifications_enable' => [
                    'name' => __('Enable topic: Attribute'),
                    'type' => 'boolean',
                    'description' => __('Enables or disables the publishing of any attribute creations/edits/soft deletions.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'ZeroMQ_tag_notifications_enable' => [
                    'name' => __('Enable topic: Tag'),
                    'type' => 'boolean',
                    'description' => __('Enables or disables the publishing of any tag creations/edits/deletions as well as tags being attached to / detached from various MISP elements.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'ZeroMQ_sighting_notifications_enable' => [
                    'name' => __('Enable topic: Sighting'),
                    'type' => 'boolean',
                    'description' => __('Enables or disables the publishing of new sightings to the ZMQ pubsub feed.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'ZeroMQ_user_notifications_enable' => [
                    'name' => __('Enable topic: User'),
                    'type' => 'boolean',
                    'description' => __('Enables or disables the publishing of new/modified users to the ZMQ pubsub feed.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'ZeroMQ_organisation_notifications_enable' => [
                    'name' => __('Enable topic: Organisation'),
                    'type' => 'boolean',
                    'description' => __('Enables or disables the publishing of new/modified organisations to the ZMQ pubsub feed.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'ZeroMQ_audit_notifications_enable' => [
                    'name' => __('Enable topic: Audit'),
                    'type' => 'boolean',
                    'description' => __('Enables or disables the publishing of log entries to the ZMQ pubsub feed. Keep in mind, this can get pretty verbose depending on your logging settings.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'ZeroMQ_warninglist_notifications_enable' => [
                    'name' => __('Enable topic: Warninglist'),
                    'type' => 'boolean',
                    'description' => __('Enables or disables the publishing of new/modified warninglist to the ZMQ pubsub feed.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
            ],
        ],
        'ElasticSearch' => [
            'ElasticSearch' => [
                'ElasticSearch_logging_enable' => [
                    'name' => __('Enable logging to ElasticSearch'),
                    'type' => 'boolean',
                    'description' => __('Enabled logging to an ElasticSearch instance'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'ElasticSearch_connection_string' => [
                    'name' => __('Connection URL'),
                    'type' => 'string',
                    'description' => __('The URL(s) at which to access ElasticSearch - comma separate if you want to have more than one.'),
                    'default' => '',
                    'test' => 'testForEmpty',
                ],
                'ElasticSearch_log_index' => [
                    'name' => __('Log index'),
                    'type' => 'string',
                    'description' => __('The index in which to place logs'),
                    'default' => '',
                    'test' => 'testForEmpty',
                ],
            ],
        ],
        'S3' => [
            'S3' => [
                'S3_enable' => [
                    'name' => __('Enable S3 storage'),
                    'type' => 'boolean',
                    'description' => __('Enables or disables uploading of malware samples to S3 rather than to disk (WARNING: Get permission from amazon first!)'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'S3_bucket_name' => [
                    'name' => __('Bucket name'),
                    'type' => 'string',
                    'description' => __('Bucket name to upload to'),
                    'default' => '',
                    'test' => 'testForEmpty',
                    'dependsOn' => 'S3_enabled',
                ],
                'S3_region' => [
                    'name' => __('Bucket region'),
                    'type' => 'string',
                    'description' => __('Region in which your S3 bucket resides'),
                    'default' => '',
                    'test' => 'testForEmpty',
                    'dependsOn' => 'S3_enabled',
                ],
                'S3_aws_access_key' => [
                    'name' => __('AWS Access Key'),
                    'type' => 'string',
                    'description' => __('AWS key to use when uploading samples (WARNING: It\' highly recommended that you use EC2 IAM roles if at all possible)'),
                    'default' => '',
                    'test' => 'testForEmpty',
                    'dependsOn' => 'S3_enabled',
                    'redacted' => true,
                ],
                'S3_aws_secret_key' => [
                    'name' => __('AWS Secret Key'),
                    'type' => 'string',
                    'description' => __('AWS secret key to use when uploading samples'),
                    'default' => '',
                    'test' => 'testForEmpty',
                    'dependsOn' => 'S3_enabled',
                    'redacted' => true,
                ],
            ],
        ],
        'Cortex' => [
            'Cortex' => [
                'Cortex_services_enable' => [
                    'name' => __('Enable Cortex service'),
                    'type' => 'boolean',
                    'description' => __('Enable/disable the Cortex services'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'Cortex_services_url' => [
                    'name' => __('Cortex service URL'),
                    'type' => 'string',
                    'description' => __('The url used to access Cortex. By default, it is accessible at http://cortex-url'),
                    'default' => 'http://127.0.0.1',
                    'test' => 'testForEmpty',
                ],
                'Cortex_services_port' => [
                    'name' => __('Cortex service port'),
                    'type' => 'integer',
                    'description' => __('The port used to access Cortex. By default, this is port 9000'),
                    'default' => 9000,
                    'test' => 'testForPortNumber',
                ],
                'Cortex_authkey' => [
                    'name' => __('Cortex service authorization key'),
                    'type' => 'string',
                    'description' => __('Set an authentication key to be passed to Cortex'),
                    'default' => '',
                    'test' => 'testForEmpty',
                ],
                'Cortex_timeout' => [
                    'name' => __('Cortex service timeout'),
                    'type' => 'integer',
                    'description' => __('Set a timeout for the Cortex services'),
                    'default' => 120,
                    'test' => 'testForEmpty',
                ],
                'Cortex_ssl_verify_peer' => [
                    'name' => __('Enable SSL verification'),
                    'type' => 'boolean',
                    'description' => __('Set to false to disable SSL verification. This is not recommended.'),
                    'default' => true,
                    'test' => 'testBool',
                ],
                'Cortex_ssl_verify_host' => [
                    'name' => __('Enable SSL hostname verification'),
                    'type' => 'boolean',
                    'description' => __('Set to false if you wish to ignore hostname match errors when validating certificates.'),
                    'default' => true,
                    'test' => 'testBool',
                ],
                'Cortex_ssl_allow_self_signed' => [
                    'name' => __('Allow SSL self signed certificate'),
                    'type' => 'boolean',
                    'description' => __('Set to true to enable self-signed certificates to be accepted. This requires Cortex_ssl_verify_peer to be enabled.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'Cortex_ssl_cafile' => [
                    'name' => __('SSL CA file path'),
                    'type' => 'string',
                    'description' => __('Set to the absolute path of the Certificate Authority file that you wish to use for verifying SSL certificates.'),
                    'default' => '',
                    'test' => 'testForEmpty',
                ],
            ],
        ],
        'CyCat' => [
            'CyCat' => [
                'CyCat_enable' => [
                    'name' => __('Enable CyCat lookups'),
                    'type' => 'boolean',
                    'description' => __('Enable lookups for additional relations via CyCat.'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'CyCat_url' => [
                    'name' => __('CyCat lookup URL'),
                    'type' => 'string',
                    'description' => __('URL to use for CyCat lookups, if enabled.'),
                    'default' => 'https://api.cycat.org',
                    'test' => 'testForEmpty',
                    'dependsOn' => 'CyCat_enable',
                ]
            ]
        ]
    ],
    'MISP Modules' => [
        'Enrichment' => [
            'Enrichment_services_enable' => [
                'name' => __('Enable enrichment service'),
                'type' => 'boolean',
                'description' => __('Enable/disable the enrichment services'),
                'default' => false,
                'test' => 'testBool',
            ],
            'Configuration' => [
                'Enrichment_hover_enable' => [
                    'name' => __('Hover enabled'),
                    'type' => 'boolean',
                    'description' => __('Enable/disable the hover over information retrieved from the enrichment modules'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'Enrichment_hover_timeout' => [
                    'name' => __('Hover timeout'),
                    'type' => 'integer',
                    'description' => __('Set a timeout for the hover services'),
                    'default' => 5,
                    'test' => 'testForEmpty',
                ],
                'Enrichment_hover_popover_only' => [
                    'name' => __('Popover only'),
                    'type' => 'boolean',
                    'description' => __('When enabled, users have to click on the magnifier icon to show the enrichment'),
                    'default' => false,
                    'test' => 'testBool',
                ],
                'Enrichment_services_url' => [
                    'name' => __('Enrichment service URL'),
                    'type' => 'string',
                    'description' => __('The url used to access the enrichment services. By default, it is accessible at http://127.0.0.1:6666'),
                    'default' => 'http://127.0.0.1',
                    'test' => 'testForEmpty',
                ],
                'Enrichment_services_port' => [
                    'name' => __('Enrichment service port'),
                    'type' => 'integer',
                    'description' => __('The port used to access the enrichment services. By default, it is accessible at 127.0.0.1:6666'),
                    'default' => 6666,
                    'test' => 'testForPortNumber',
                ],
                'Enrichment_timeout' => [
                    'name' => __('Enrichment service timeout'),
                    'type' => 'integer',
                    'description' => __('Set a timeout for the enrichment services'),
                    'default' => 10,
                    'test' => 'testForEmpty',
                    'dependsOn' => 'Enrichment_services_enable'
                ],
            ]
        ],
        'Import' => [
            'Import_services_enable' => [
                'name' => __('Enable import service'),
                'type' => 'boolean',
                'description' => __('Enable/disable the import services'),
                'default' => false,
                'test' => 'testBool',
            ],
            'Configuration' => [
                'Import_services_url' => [
                    'name' => __('Import service URL'),
                    'type' => 'string',
                    'description' => __('The url used to access the import services. By default, it is accessible at http://127.0.0.1:6666'),
                    'default' => 'http://127.0.0.1',
                    'test' => 'testForEmpty',
                    'dependsOn' => 'Import_services_enable'
                ],
                'Import_services_port' => [
                    'name' => __('Import service Port'),
                    'type' => 'integer',
                    'description' => __('The port used to access the import services. By default, it is accessible at 127.0.0.1:6666'),
                    'default' => 6666,
                    'test' => 'testForPortNumber',
                    'dependsOn' => 'Import_services_enable'
                ],
                'Import_timeout' => array(
                    'name' => __('Import service timeout'),
                    'description' => __('Set a timeout for the import services'),
                    'default' => 10,
                    'test' => 'testForEmpty',
                    'type' => 'integer'
                ),
            ]
        ],
        'Export' => [
            'Export_services_enable' => [
                'name' => __('Enable export service'),
                'type' => 'boolean',
                'description' => __('Enable/disable the export services'),
                'default' => false,
                'test' => 'testBool',
            ],
            'Configuration' => [
                'Export_services_url' => [
                    'name' => __('Export service URL'),
                    'type' => 'string',
                    'description' => __('The url used to access the export services. By default, it is accessible at http://127.0.0.1:6666'),
                    'default' => 'http://127.0.0.1',
                    'test' => 'testForEmpty',
                ],
                'Export_services_port' => [
                    'name' => __('Export service port'),
                    'type' => 'integer',
                    'description' => __('The port used to access the export services. By default, it is accessible at 127.0.0.1:6666'),
                    'default' => 6666,
                    'test' => 'testForPortNumber',
                ],
                'Export_timeout' => [
                    'name' => __('Export service timeout'),
                    'type' => 'integer',
                    'description' => __('Set a timeout for the export services'),
                    'default' => 10,
                    'test' => 'testForEmpty',
                ],
            ]
        ],
    ]
];
