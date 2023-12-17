<?php

namespace App\Model\Entity;

use App\Lib\Tools\BackgroundJobsTool;
use App\Lib\Tools\BetterSecurity;
use App\Lib\Tools\EncryptedValue;
use App\Lib\Tools\RedisTool;
use App\Model\Entity\AppModel;
use Cake\ORM\Locator\LocatorAwareTrait;
use Exception;

class Server extends AppModel
{
    use LocatorAwareTrait;

    public const SETTING_CRITICAL = 0,
        SETTING_RECOMMENDED = 1,
        SETTING_OPTIONAL = 2;

    public function &__get(string $field)
    {
        if ($field === 'serverSettings') {
            return $this->serverSettings = $this->generateServerSettings();
        } else if ($field === 'command_line_functions') {
            return $this->command_line_functions = $this->generateCommandLineFunctions();
        }
        return parent::__get($field);
    }

    /**
     * Generate just when required
     * @return array[]
     */
    private function generateServerSettings()
    {
        return [
            'MISP' => [
                'branch' => 1,
                'baseurl' => [
                    'level' => 0,
                    'description' => __('The base url of the application (in the format https://www.mymispinstance.com or https://myserver.com/misp). Several features depend on this setting being correctly set to function.'),
                    'value' => '',
                    'errorMessage' => __('The currently set baseurl does not match the URL through which you have accessed the page. Disregard this if you are accessing the page via an alternate URL (for example via IP address).'),
                    'test' => 'testBaseURL',
                    'type' => 'string',
                    'null' => true
                ],
                'external_baseurl' => [
                    'level' => 0,
                    'description' => __('The base url of the application (in the format https://www.mymispinstance.com) as visible externally/by other MISPs. MISP will encode this URL in sharing groups when including itself. If this value is not set, the baseurl is used as a fallback.'),
                    'value' => '',
                    'test' => 'testURL',
                    'type' => 'string',
                ],
                'live' => [
                    'level' => 0,
                    'description' => __('Unless set to true, the instance will only be accessible by site admins.'),
                    'value' => false,
                    'test' => 'testLive',
                    'type' => 'boolean',
                ],
                'language' => [
                    'level' => 0,
                    'description' => __('Select the language MISP should use. The default is english.'),
                    'value' => 'eng',
                    'test' => 'testLanguage',
                    'type' => 'string',
                    'optionsSource' => function () {
                        return $this->loadAvailableLanguages();
                    },
                    'afterHook' => 'cleanCacheFiles'
                ],
                'default_attribute_memory_coefficient' => [
                    'level' => 1,
                    'description' => __('This values controls the internal fetcher\'s memory envelope when it comes to attributes. The number provided is the amount of attributes that can be loaded for each MB of PHP memory available in one shot. Consider lowering this number if your instance has a lot of attribute tags / attribute galaxies attached.'),
                    'value' => 80,
                    'test' => 'testForNumeric',
                    'type' => 'numeric',
                    'null' => true
                ],
                'default_event_memory_divisor' => [
                    'level' => 1,
                    'description' => __('This value controls the divisor for attribute weighting when it comes to loading full events. Meaning that it will load coefficient / divisor number of attributes per MB of memory available. Consider raising this number if you have a lot of correlations or highly contextualised events (large number of event level galaxies/tags).'),
                    'value' => 3,
                    'test' => 'testForNumeric',
                    'type' => 'numeric',
                    'null' => true
                ],
                'disable_event_locks' => [
                    'level' => 1,
                    'description' => __('Disable the event locks that are executed periodically when a user browses an event view. It can be useful to leave event locks enabled to warn users that someone else is editing the same event, but generally it\'s extremely verbose and can cause issues in certain setups, so it\'s recommended to disable this.'),
                    'value' => false,
                    'test' => 'testBoolTrue',
                    'type' => 'boolean',
                    'null' => true
                ],
                'correlation_engine' => [
                    'level' => 0,
                    'description' => __('Choose which correlation engine to use. MISP defaults to the default engine, maintaining all data in the database whilst enforcing ACL rules on any non site-admin user. This is recommended for any MISP instnace with multiple organisations. If you are an endpoint MISP, consider switching to the much leaner and faster No ACL engine.'),
                    'value' => 'default',
                    'test' => 'testForCorrelationEngine',
                    'type' => 'string',
                    'null' => true,
                    'options' => [
                        'Default' => __('Default Correlation Engine'),
                        'NoAcl' => __('No ACL Engine')
                    ],
                ],
                'correlation_limit' => [
                    'level' => 0,
                    'description' => __('Set a value for the maximum number of correlations a value should have before MISP will refuse to correlate it (extremely over-correlating values are rarely useful from a correlation perspective).'),
                    'value' => 100,
                    'test' => 'testForNumeric',
                    'type' => 'numeric',
                    'null' => true
                ],
                'enable_advanced_correlations' => [
                    'level' => 0,
                    'description' => __('Enable some performance heavy correlations (currently CIDR correlation)'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'server_settings_skip_backup_rotate' => [
                    'level' => 1,
                    'description' => __('Enable this setting to directly save the config.php file without first creating a temporary file and moving it to avoid concurency issues. Generally not recommended, but useful when for example other tools modify/maintain the config.php file.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'python_bin' => [
                    'level' => 1,
                    'description' => __('It is highly recommended to install all the python dependencies in a virtualenv. The recommended location is: %s/venv', ROOT),
                    'value' => false,
                    'null' => false,
                    'test' => 'testForBinExec',
                    'beforeHook' => 'beforeHookBinExec',
                    'type' => 'string',
                    'cli_only' => 1
                ],
                'ca_path' => [
                    'level' => 1,
                    'description' => __('MISP will default to the bundled mozilla certificate bundle shipped with the framework, which is rather stale. If you wish to use an alternate bundle, just set this setting using the path to the bundle to use. This setting can only be modified via the CLI.'),
                    'value' => APP . 'Lib/cakephp/lib/Cake/Config/cacert.pem',
                    'null' => true,
                    'test' => 'testForCABundle',
                    'type' => 'string',
                    'cli_only' => 1
                ],
                'disable_auto_logout' => [
                    'level' => 1,
                    'description' => __('In some cases, a heavily used MISP instance can generate unwanted blackhole errors due to a high number of requests hitting the server. Disable the auto logout functionality to ease the burden on the system.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'ssdeep_correlation_threshold' => [
                    'level' => 1,
                    'description' => __('Set the ssdeep score at which to consider two ssdeep hashes as correlating [1-100]'),
                    'value' => 40,
                    'test' => 'testForEmpty',
                    'type' => 'numeric'
                ],
                'max_correlations_per_event' => [
                    'level' => 1,
                    'description' => __('Sets the maximum number of correlations that can be fetched with a single event. For extreme edge cases this can prevent memory issues. The default value is 5k.'),
                    'value' => 5000,
                    'test' => 'testForNumeric',
                    'type' => 'numeric',
                    'null' => true
                ],
                'maintenance_message' => [
                    'level' => 2,
                    'description' => __('The message that users will see if the instance is not live.'),
                    'value' => 'Great things are happening! MISP is undergoing maintenance, but will return shortly. You can contact the administration at $email.',
                    'errorMessage' => __('If this is not set the default value will be used.'),
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'name' => [
                    'level' => 3,
                    'description' => __('This setting is deprecated and can be safely removed.'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'version' => [
                    'level' => 3,
                    'description' => __('This setting is deprecated and can be safely removed.'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'disable_cached_exports' => [
                    'level' => 1,
                    'description' => __('Cached exports can take up a considerable amount of space and can be disabled instance wide using this setting. Disabling the cached exports is not recommended as it\'s a valuable feature, however, if your server is having free space issues it might make sense to take this step.'),
                    'value' => false,
                    'null' => true,
                    'test' => 'testDisableCache',
                    'type' => 'boolean',
                    'afterHook' => 'disableCacheAfterHook',
                ],
                'disable_threat_level' => [
                    'level' => 1,
                    'description' => __('Disable displaying / modifications to the threat level altogether on the instance (deprecated field).'),
                    'value' => false,
                    'null' => true,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'header' => [
                    'level' => 3,
                    'description' => __('This setting is deprecated and can be safely removed.'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'footermidleft' => [
                    'level' => 2,
                    'description' => __('Footer text prepending the "Powered by MISP" text.'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'footermidright' => [
                    'level' => 2,
                    'description' => __('Footer text following the "Powered by MISP" text.'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'footerpart1' => [
                    'level' => 3,
                    'description' => __('This setting is deprecated and can be safely removed.'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'footerpart2' => [
                    'level' => 3,
                    'description' => __('This setting is deprecated and can be safely removed.'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'footer' => [
                    'level' => 3,
                    'description' => __('This setting is deprecated and can be safely removed.'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'footerversion' => [
                    'level' => 3,
                    'description' => __('This setting is deprecated and can be safely removed.'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'footer_logo' => [
                    'level' => 2,
                    'description' => __('If set, this setting allows you to display a logo on the right side of the footer. Upload it as a custom image in the file management tool.'),
                    'value' => '',
                    'test' => 'testForCustomImage',
                    'type' => 'string',
                ],
                'home_logo' => [
                    'level' => 2,
                    'description' => __('If set, this setting allows you to display a logo as the home icon. Upload it as a custom image in the file management tool.'),
                    'value' => '',
                    'test' => 'testForCustomImage',
                    'type' => 'string',
                ],
                'main_logo' => [
                    'level' => 2,
                    'description' => __('If set, the image specified here will replace the main MISP logo on the login screen. Upload it as a custom image in the file management tool.'),
                    'value' => '',
                    'test' => 'testForCustomImage',
                    'type' => 'string',
                ],
                'org' => [
                    'level' => 1,
                    'description' => __('The organisation tag of the hosting organisation. This is used in the e-mail subjects.'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'host_org_id' => [
                    'level' => 0,
                    'description' => __('The hosting organisation of this instance. If this is not selected then replication instances cannot be added.'),
                    'value' => '0',
                    'test' => 'testLocalOrgStrict',
                    'type' => 'numeric',
                    'optionsSource' => function () {
                        return $this->loadLocalOrganisations(true);
                    },
                ],
                'uuid' => [
                    'level' => 0,
                    'description' => __('The MISP instance UUID. This UUID is used to identify this instance.'),
                    'value' => '0',
                    'errorMessage' => __('No valid UUID set'),
                    'test' => 'testUuid',
                    'type' => 'string'
                ],
                'logo' => [
                    'level' => 3,
                    'description' => __('This setting is deprecated and can be safely removed.'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'showorg' => [
                    'level' => 0,
                    'description' => __('Setting this setting to \'false\' will hide all organisation names / logos.'),
                    'value' => '',
                    'test' => 'testBool',
                    'type' => 'boolean',
                ],
                'threatlevel_in_email_subject' => [
                    'level' => 2,
                    'description' => __('Put the event threat level in the notification E-mail subject.'),
                    'value' => true,
                    'test' => 'testBool',
                    'type' => 'boolean',
                ],
                'email_subject_TLP_string' => [
                    'level' => 2,
                    'description' => __('This is the TLP string for e-mails when email_subject_tag is not found.'),
                    'value' => 'tlp:amber',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'email_subject_tag' => [
                    'level' => 2,
                    'description' => __('If this tag is set on an event it\'s value will be sent in the E-mail subject. If the tag is not set the email_subject_TLP_string will be used.'),
                    'value' => 'tlp',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'email_subject_include_tag_name' => [
                    'level' => 2,
                    'description' => __('Include in name of the email_subject_tag in the subject. When false only the tag value is used.'),
                    'value' => true,
                    'test' => 'testBool',
                    'type' => 'boolean',
                ],
                'email_from_name' => [
                    'level' => 2,
                    'description' => __('Notification e-mail sender name.'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'taxii_sync' => [
                    'level' => 3,
                    'description' => __('This setting is deprecated and can be safely removed.'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'taxii_client_path' => [
                    'level' => 3,
                    'description' => __('This setting is deprecated and can be safely removed.'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'background_jobs' => [
                    'level' => 1,
                    'description' => __('Enables the use of MISP\'s background processing.'),
                    'value' => '',
                    'test' => 'testBoolTrue',
                    'type' => 'boolean',
                ],
                'attachments_dir' => [
                    'level' => 2,
                    'description' => __('Directory where attachments are stored. MISP will NOT migrate the existing data if you change this setting. The only safe way to change this setting is in config.php, when MISP is not running, and after having moved/copied the existing data to the new location. This directory must already exist and be writable and readable by the MISP application.'),
                    'value' => APP . '/files', # GUI display purpose only.
                    'null' => false,
                    'test' => 'testForWritableDir',
                    'type' => 'string',
                    'cli_only' => 1
                ],
                'download_attachments_on_load' => [
                    'level' => 2,
                    'description' => __('Always download attachments when loaded by a user in a browser'),
                    'value' => true,
                    'test' => 'testBool',
                    'type' => 'boolean',
                ],
                'osuser' => [
                    'level' => 0,
                    'description' => __('The Unix user MISP (php) is running as'),
                    'value' => 'www-data',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'email' => [
                    'level' => 0,
                    'description' => __('The e-mail address that MISP should use for all notifications'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'disable_emailing' => [
                    'level' => 0,
                    'description' => __('You can disable all e-mailing using this setting. When enabled, no outgoing e-mails will be sent by MISP.'),
                    'value' => false,
                    'null' => true,
                    'test' => 'testDisableEmail',
                    'type' => 'boolean',
                ],
                'publish_alerts_summary_only' => [
                    'level' => 1,
                    'description' => __('This setting is deprecated. Please use `MISP.event_alert_metadata_only` instead.'),
                    'value' => false,
                    'null' => true,
                    'test' => 'testBool',
                    'type' => 'boolean',
                ],
                'contact' => [
                    'level' => 1,
                    'description' => __('The e-mail address that MISP should include as a contact address for the instance\'s support team.'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'dns' => [
                    'level' => 3,
                    'description' => __('This setting is deprecated and can be safely removed.'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'cveurl' => [
                    'level' => 1,
                    'description' => __('Turn Vulnerability type attributes into links linking to the provided CVE lookup'),
                    'value' => 'https://cve.circl.lu/cve/',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'cweurl' => [
                    'level' => 1,
                    'description' => __('Turn Weakness type attributes into links linking to the provided CWE lookup'),
                    'value' => 'https://cve.circl.lu/cwe/',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'disablerestalert' => [
                    'level' => 1,
                    'description' => __('This setting controls whether notification e-mails will be sent when an event is created via the REST interface. It might be a good idea to disable this setting when first setting up a link to another instance to avoid spamming your users during the initial pull. Quick recap: True = Emails are NOT sent, False = Emails are sent on events published via sync / REST.'),
                    'value' => true,
                    'test' => 'testBool',
                    'type' => 'boolean',
                ],
                'extended_alert_subject' => [
                    'level' => 1,
                    'description' => __('Enabling this flag will allow the event description to be transmitted in the alert e-mail\'s subject. Be aware that this is not encrypted by GnuPG, so only enable it if you accept that part of the event description will be sent out in clear-text.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'forceHTTPSforPreLoginRequestedURL' => [
                    'level' => self::SETTING_OPTIONAL,
                    'description' => __('If enabled, any requested URL before login will have their HTTP part replaced by HTTPS. This can be usefull if MISP is running behind a reverse proxy responsible for SSL and communicating unencrypted with MISP.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'event_alert_metadata_only' => [
                    'level' => self::SETTING_OPTIONAL,
                    'description' => __('Send just event metadata (attributes and objects will be omitted) for event alert.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'default_event_distribution' => [
                    'level' => 0,
                    'description' => __('The default distribution setting for events (0-3).'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                    'options' => [
                        '0' => __('Your organisation only'),
                        '1' => __('This community only'),
                        '2' => __('Connected communities'),
                        '3' => __('All communities')
                    ],
                ],
                'default_attribute_distribution' => [
                    'level' => 0,
                    'description' => __('The default distribution setting for attributes, set it to \'event\' if you would like the attributes to default to the event distribution level. (0-3 or "event")'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                    'options' => [
                        '0' => __('Your organisation only'),
                        '1' => __('This community only'),
                        '2' => __('Connected communities'),
                        '3' => __('All communities'),
                        'event' => __('Inherit from event')
                    ],
                ],
                'default_event_threat_level' => [
                    'level' => 1,
                    'description' => __('The default threat level setting when creating events.'),
                    'value' => 4,
                    'test' => 'testForEmpty',
                    'type' => 'string',
                    'options' => ['1' => 'High', '2' => 'Medium', '3' => 'Low', '4' => 'undefined'],
                ],
                'default_event_tag_collection' => [
                    'level' => 0,
                    'description' => __('The tag collection to be applied to all events created manually.'),
                    'value' => 0,
                    'test' => 'testTagCollections',
                    'type' => 'numeric',
                    'optionsSource' => function () {
                        return $this->loadTagCollections();
                    }
                ],
                'default_publish_alert' => [
                    'level' => 0,
                    'description' => __('The default setting for publish alerts when creating users.'),
                    'value' => true,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'tagging' => [
                    'level' => 1,
                    'description' => __('Enable the tagging feature of MISP. This is highly recommended.'),
                    'value' => '',
                    'test' => 'testBool',
                    'type' => 'boolean',
                ],
                'full_tags_on_event_index' => [
                    'level' => 2,
                    'description' => __('Show the full tag names on the event index.'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                    'options' => [0 => 'Minimal tags', 1 => 'Full tags', 2 => 'Shortened tags'],
                ],
                'disable_taxonomy_consistency_checks' => [
                    'level' => 0,
                    'description' => __('*WARNING* This will disable taxonomy tags conflict checks when browsing attributes and objects, does not impact checks when adding tags. It can dramatically increase the performance when loading events with lots of tagged attributes or objects.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'welcome_text_top' => [
                    'level' => 2,
                    'description' => __('Used on the login page, before the MISP logo'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'welcome_text_bottom' => [
                    'level' => 2,
                    'description' => __('Used on the login page, after the MISP logo'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'welcome_logo' => [
                    'level' => 2,
                    'description' => __('Used on the login page, to the left of the MISP logo, upload it as a custom image in the file management tool.'),
                    'value' => '',
                    'test' => 'testForCustomImage',
                    'type' => 'string',
                ],
                'welcome_logo2' => [
                    'level' => 2,
                    'description' => __('Used on the login page, to the right of the MISP logo, upload it as a custom image in the file management tool.'),
                    'value' => '',
                    'test' => 'testForCustomImage',
                    'type' => 'string',
                ],
                'title_text' => [
                    'level' => 2,
                    'description' => __('Used in the page title, after the name of the page'),
                    'value' => 'MISP',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'take_ownership_xml_import' => [
                    'level' => 2,
                    'description' => __('Allows users to take ownership of an event uploaded via the "Add MISP XML" button. This allows spoofing the creator of a manually imported event, also breaking possibly breaking the original intended releasability. Synchronising with an instance that has a different creator for the same event can lead to unwanted consequences.'),
                    'value' => '',
                    'test' => 'testBool',
                    'type' => 'boolean',
                ],
                'terms_download' => [
                    'level' => 2,
                    'description' => __('Choose whether the terms and conditions should be displayed inline (false) or offered as a download (true)'),
                    'value' => '',
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'terms_file' => [
                    'level' => 2,
                    'description' => __('The filename of the terms and conditions file. Make sure that the file is located in your MISP/app/files/terms directory'),
                    'value' => '',
                    'test' => 'testForTermsFile',
                    'type' => 'string'
                ],
                'showorgalternate' => [
                    'level' => 2,
                    'description' => __('True enables the alternate org fields for the event index (source org and member org) instead of the traditional way of showing only an org field. This allows users to see if an event was uploaded by a member organisation on their MISP instance, or if it originated on an interconnected instance.'),
                    'value' => '',
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'unpublishedprivate' => [
                    'level' => 2,
                    'description' => __('True will deny access to unpublished events to users outside the organization of the submitter except site admins.'),
                    'value' => '',
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'newUserText' => [
                    'level' => 1,
                    'bigField' => true,
                    'description' => __('The message sent to the user after account creation (has to be sent manually from the administration interface). Use \\n for line-breaks. The following variables will be automatically replaced in the text: $password = a new temporary password that MISP generates, $username = the user\'s e-mail address, $misp = the url of this instance, $org = the organisation that the instance belongs to, as set in MISP.org, $contact = the e-mail address used to contact the support team, as set in MISP.contact. For example, "the password for $username is $password" would appear to a user with the e-mail address user@misp.org as "the password for user@misp.org is hNamJae81".'),
                    'value' => 'Dear new MISP user,\n\nWe would hereby like to welcome you to the $org MISP community.\n\n Use the credentials below to log into MISP at $misp, where you will be prompted to manually change your password to something of your own choice.\n\nUsername: $username\nPassword: $password\n\nIf you have any questions, don\'t hesitate to contact us at: $contact.\n\nBest regards,\nYour $org MISP support team',
                    'test' => 'testPasswordResetText',
                    'type' => 'string'
                ],
                'passwordResetText' => [
                    'level' => 1,
                    'bigField' => true,
                    'description' => __('The message sent to the users when a password reset is triggered. Use \\n for line-breaks. The following variables will be automatically replaced in the text: $password = a new temporary password that MISP generates, $username = the user\'s e-mail address, $misp = the url of this instance, $contact = the e-mail address used to contact the support team, as set in MISP.contact. For example, "the password for $username is $password" would appear to a user with the e-mail address user@misp.org as "the password for user@misp.org is hNamJae81".'),
                    'value' => 'Dear MISP user,\n\nA password reset has been triggered for your account. Use the below provided temporary password to log into MISP at $misp, where you will be prompted to manually change your password to something of your own choice.\n\nUsername: $username\nYour temporary password: $password\n\nIf you have any questions, don\'t hesitate to contact us at: $contact.\n\nBest regards,\nYour $org MISP support team',
                    'test' => 'testPasswordResetText',
                    'type' => 'string'
                ],
                'enableEventBlocklisting' => [
                    'level' => 1,
                    'description' => __('Since version 2.3.107 you can start blocklisting event UUIDs to prevent them from being pushed to your instance. This functionality will also happen silently whenever an event is deleted, preventing a deleted event from being pushed back from another instance.'),
                    'value' => true,
                    'type' => 'boolean',
                    'test' => 'testBool'
                ],
                'enableOrgBlocklisting' => [
                    'level' => 1,
                    'description' => __('Blocklisting organisation UUIDs to prevent the creation of any event created by the blocklisted organisation.'),
                    'value' => true,
                    'type' => 'boolean',
                    'test' => 'testBool'
                ],
                'log_client_ip' => [
                    'level' => 1,
                    'description' => __('If enabled, all log entries will include the IP address of the user.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'beforeHook' => 'ipLogBeforeHook'
                ],
                'log_client_ip_header' => [
                    'level' => 1,
                    'description' => __('If log_client_ip is enabled, you can customize which header field contains the client\'s IP address. This is generally used when you have a reverse proxy in front of your MISP instance. Prepend the variable with "HTTP_", for example "HTTP_X_FORWARDED_FOR".'),
                    'value' => 'REMOTE_ADDR',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                    'null' => true,
                ],
                'store_api_access_time' => [
                    'level' => 1,
                    'description' => __('If enabled, MISP will capture the last API access time following a successful authentication using API keys, stored against a user under the last_api_access field.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                ],
                'log_auth' => [
                    'level' => 1,
                    'description' => __('If enabled, MISP will log all successful authentications using API keys. The requested URLs are also logged.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                ],
                'log_skip_db_logs_completely' => [
                    'level' => 0,
                    'description' => __('This functionality allows you to completely disable any logs from being saved in your SQL backend. This is HIGHLY advised against, you lose all the functionalities provided by the audit log subsystem along with the event history (as these are built based on the logs on the fly). Only enable this if you understand and accept the associated risks.'),
                    'value' => false,
                    'errorMessage' => __('Logging has now been disabled - your audit logs will not capture failed authentication attempts, your event history logs are not being populated and no system maintenance messages are being logged.'),
                    'test' => 'testBoolFalse',
                    'type' => 'boolean',
                    'null' => true
                ],
                'log_skip_access_logs_in_application_logs' => [
                    'level' => 0,
                    'description' => __('Skip adding the access log entries to the /logs/ application logs. This is **HIGHLY** recommended as your instance will be logging these entries twice otherwise, however, for compatibility reasons for auditing we maintain this behaviour until confirmed otherwise.'),
                    'value' => false,
                    'errorMessage' => __('Access logs are logged twice. This is generally not recommended, make sure you update your tooling.'),
                    'test' => 'testBoolTrue',
                    'type' => 'boolean',
                    'null' => true
                ],
                'log_paranoid' => [
                    'level' => 0,
                    'description' => __('If this functionality is enabled all page requests will be logged. Keep in mind this is extremely verbose and will become a burden to your database.'),
                    'value' => false,
                    'test' => 'testBoolFalse',
                    'type' => 'boolean',
                    'null' => true
                ],
                'log_paranoid_api' => [
                    'level' => 0,
                    'description' => __('If this functionality is enabled all API requests will be logged.'),
                    'value' => false,
                    'test' => 'testBoolFalse',
                    'type' => 'boolean',
                    'null' => true
                ],
                'log_paranoid_skip_db' => [
                    'level' => 0,
                    'description' => __('You can decide to skip the logging of the paranoid logs to the database. Logs will be just published to ZMQ or Kafka.'),
                    'value' => false,
                    'test' => 'testParanoidSkipDb',
                    'type' => 'boolean',
                    'null' => true
                ],
                'log_paranoid_include_post_body' => [
                    'level' => 0,
                    'description' => __('If paranoid logging is enabled, include the POST body in the entries.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'log_paranoid_include_sql_queries' => [
                    'level' => 0,
                    'description' => __('If paranoid logging is enabled, include the SQL queries in the entries.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'log_user_ips' => [
                    'level' => 0,
                    'description' => __('Log user IPs on each request. 30 day retention for lookups by IP to get the last authenticated user ID for the given IP, whilst on the reverse, indefinitely stores all associated IPs for a user ID.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'log_user_ips_authkeys' => [
                    'level' => self::SETTING_RECOMMENDED,
                    'description' => __('Log user IP and key usage on each API request. All logs for given keys are deleted after one year when this key is not used.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'log_new_audit' => [
                    'level' => self::SETTING_RECOMMENDED,
                    'description' => __('Enable new audit log system.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'log_new_audit_compress' => [
                    'level' => self::SETTING_OPTIONAL,
                    'description' => __('Compress log changes by brotli algorithm. This will reduce log database size.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'delegation' => [
                    'level' => 1,
                    'description' => __('This feature allows users to create org only events and ask another organisation to take ownership of the event. This allows organisations to remain anonymous by asking a partner to publish an event for them.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'discussion_disable' => [
                    'level' => 1,
                    'description' => __('Completely disable ability for user to add discussion to events.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'showCorrelationsOnIndex' => [
                    'level' => 1,
                    'description' => __('When enabled, the number of correlations visible to the currently logged in user will be visible on the event index UI. This comes at a performance cost but can be very useful to see correlating events at a glance.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'showProposalsCountOnIndex' => [
                    'level' => 1,
                    'description' => __('When enabled, the number of proposals for the events are shown on the index.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'showSightingsCountOnIndex' => [
                    'level' => 1,
                    'description' => __('When enabled, the aggregate number of attribute sightings within the event becomes visible to the currently logged in user on the event index UI.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'showDiscussionsCountOnIndex' => [
                    'level' => 1,
                    'description' => __('When enabled, the aggregate number of discussion posts for the event becomes visible to the currently logged in user on the event index UI.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'showEventReportCountOnIndex' => [
                    'level' => 1,
                    'description' => __('When enabled, the aggregate number of event reports for the event becomes visible to the currently logged in user on the event index UI.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'disableUserSelfManagement' => [
                    'level' => 1,
                    'description' => __('When enabled only Org and Site admins can edit a user\'s profile.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => false,
                ],
                'disable_user_login_change' => [
                    'level' => self::SETTING_RECOMMENDED,
                    'description' => __('When enabled only Site admins can change user email. This should be enabled if you manage user logins by external system.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => false,
                ],
                'disable_user_password_change' => [
                    'level' => self::SETTING_RECOMMENDED,
                    'description' => __('When enabled only Site admins can change user password. This should be enabled if you manage user passwords by external system.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => false,
                ],
                'disable_user_add' => [
                    'level' => self::SETTING_RECOMMENDED,
                    'description' => __('When enabled, Org Admins could not add new users. This should be enabled if you manage users by external system.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => false,
                ],
                'block_event_alert' => [
                    'level' => 1,
                    'description' => __('Enable this setting to start blocking alert e-mails for events with a certain tag. Define the tag in MISP.block_event_alert_tag.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => false,
                ],
                'block_event_alert_tag' => [
                    'level' => 1,
                    'description' => __('If the MISP.block_event_alert setting is set, alert e-mails for events tagged with the tag defined by this setting will be blocked.'),
                    'value' => 'no-alerts="true"',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                    'null' => false,
                ],
                'event_alert_republish_ban' => [
                    'level' => 1,
                    'description' => __('Enable this setting to start blocking alert e-mails for events that have already been published since a specified amount of time. This threshold is defined by MISP.event_alert_republish_ban_threshold'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => false,
                ],
                'event_alert_republish_ban_threshold' => [
                    'level' => 1,
                    'description' => __('If the MISP.event_alert_republish_ban setting is set, this setting will control how long no alerting by email will be done. Expected format: integer, in minutes'),
                    'value' => 5,
                    'test' => 'testForNumeric',
                    'type' => 'numeric',
                    'null' => false,
                ],
                'event_alert_republish_ban_refresh_on_retry' => [
                    'level' => 1,
                    'description' => __('If the MISP.event_alert_republish_ban setting is set, this setting will control if a ban time should be reset if emails are tried to be sent during the ban.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => false,
                ],
                'user_email_notification_ban' => [
                    'level' => 1,
                    'description' => __('Enable this setting to start blocking users to send too many e-mails notification since a specified amount of time. This threshold is defined by MISP.user_email_notification_ban_threshold'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => false,
                ],
                'user_email_notification_ban_time_threshold' => [
                    'level' => 1,
                    'description' => __('If the MISP.user_email_notification_ban setting is set, this setting will control how long no notification by email will be done. Expected format: integer, in minutes'),
                    'value' => 120,
                    'test' => 'testForNumeric',
                    'type' => 'numeric',
                    'null' => false,
                ],
                'user_email_notification_ban_amount_threshold' => [
                    'level' => 1,
                    'description' => __('If the MISP.user_email_notification_ban setting is set, this setting will control how many notification by email can be send for the timeframe defined in MISP.user_email_notification_ban_time_threshold. Expected format: integer'),
                    'value' => 10,
                    'test' => 'testForNumeric',
                    'type' => 'numeric',
                    'null' => false,
                ],
                'org_alert_threshold' => [
                    'level' => 1,
                    'description' => __('Set a value to limit the number of email alerts that events can generate per creator organisation (for example, if an organisation pushes out 2000 events in one shot, only alert on the first 20).'),
                    'value' => 0,
                    'test' => 'testForNumeric',
                    'type' => 'numeric',
                    'null' => true,
                ],
                'block_old_event_alert' => [
                    'level' => 1,
                    'description' => __('Enable this setting to start blocking alert e-mails for old events. The exact timing of what constitutes an old event is defined by MISP.block_old_event_alert_age.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => false,
                ],
                'block_old_event_alert_age' => [
                    'level' => 1,
                    'description' => __('If the MISP.block_old_event_alert setting is set, this setting will control how old an event can be for it to be alerted on. The "timestamp" field of the event is used. Expected format: integer, in days'),
                    'value' => false,
                    'test' => 'testForNumeric',
                    'type' => 'numeric',
                    'null' => false,
                ],
                'block_old_event_alert_by_date' => [
                    'level' => 1,
                    'description' => __('If the MISP.block_old_event_alert setting is set, this setting will control the threshold for the event.date field, indicating how old an event can be for it to be alerted on. The "date" field of the event is used. Expected format: integer, in days'),
                    'value' => false,
                    'test' => 'testForNumeric',
                    'type' => 'numeric',
                    'null' => false,
                ],
                'tmpdir' => [
                    'level' => 1,
                    'description' => __('Please indicate the temp directory you wish to use for certain functionalities in MISP. By default this is set to %s and will be used among others to store certain temporary files extracted from imports during the import process.', APP . 'tmp'),
                    'value' => APP . 'tmp',
                    'test' => 'testForPath',
                    'type' => 'string',
                    'null' => true,
                    'cli_only' => 1
                ],
                'custom_css' => [
                    'level' => 2,
                    'description' => __('If you would like to customise the CSS, simply drop a css file in the /var/www/MISP/app/webroot/css directory and enter the name here.'),
                    'value' => '',
                    'test' => 'testForStyleFile',
                    'type' => 'string',
                    'null' => true,
                ],
                'proposals_block_attributes' => [
                    'level' => 0,
                    'description' => __('Enable this setting to allow blocking attributes from to_ids sensitive exports if a proposal has been made to it to remove the IDS flag or to remove the attribute altogether. This is a powerful tool to deal with false-positives efficiently.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => false,
                ],
                'incoming_tags_disabled_by_default' => [
                    'level' => 1,
                    'description' => __('Enable this settings if new tags synced / added via incoming events from any source should not be selectable by users by default.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => false
                ],
                'completely_disable_correlation' => [
                    'level' => 0,
                    'description' => __('*WARNING* This setting will completely disable the correlation on this instance and remove any existing saved correlations. Enabling this will trigger a full recorrelation of all data which is an extremely long and costly procedure. Only enable this if you know what you\'re doing.'),
                    'value' => false,
                    'test' => 'testBoolFalse',
                    'type' => 'boolean',
                    'null' => true,
                    'afterHook' => 'correlationAfterHook',
                ],
                'allow_disabling_correlation' => [
                    'level' => 0,
                    'description' => __('*WARNING* This setting will give event creators the possibility to disable the correlation of individual events / attributes that they have created.'),
                    'value' => false,
                    'test' => 'testBoolFalse',
                    'type' => 'boolean',
                    'null' => true
                ],
                'redis_host' => [
                    'level' => 0,
                    'description' => __('The host running the redis server to be used for generic MISP tasks such as caching. This is not to be confused by the redis server used by the background processing.'),
                    'value' => '127.0.0.1',
                    'test' => 'testForEmpty',
                    'type' => 'string'
                ],
                'redis_port' => [
                    'level' => 0,
                    'description' => __('The port used by the redis server to be used for generic MISP tasks such as caching. This is not to be confused by the redis server used by the background processing.'),
                    'value' => 6379,
                    'test' => 'testForNumeric',
                    'type' => 'numeric'
                ],
                'redis_database' => [
                    'level' => 0,
                    'description' => __('The database on the redis server to be used for generic MISP tasks. If you run more than one MISP instance, please make sure to use a different database on each instance.'),
                    'value' => 13,
                    'test' => 'testForNumeric',
                    'type' => 'numeric'
                ],
                'redis_password' => [
                    'level' => 0,
                    'description' => __('The password on the redis server (if any) to be used for generic MISP tasks.'),
                    'value' => '',
                    'test' => null,
                    'type' => 'string',
                    'redacted' => true
                ],
                'redis_serializer' => [
                    'level' => self::SETTING_OPTIONAL,
                    'description' => __('Redis serializer method. WARNING: Changing this setting will drop some cached data.'),
                    'value' => 'JSON',
                    'test' => null,
                    'type' => 'string',
                    'null' => true,
                    'options' => [
                        'JSON' => 'JSON',
                        'igbinary' => 'igbinary',
                    ],
                    'afterHook' => function () {
                        $keysToDelete = ['taxonomies_cache:*', 'misp:warninglist_cache', 'misp:wlc:*', 'misp:event_lock:*', 'misp:event_index:*', 'misp:dashboard:*'];
                        RedisTool::deleteKeysByPattern(RedisTool::init(), $keysToDelete);
                        return true;
                    },
                ],
                'event_view_filter_fields' => [
                    'level' => 2,
                    'description' => __('Specify which fields to filter on when you search on the event view. Default values are : "id, uuid, value, comment, type, category, Tag.name"'),
                    'value' => 'id, uuid, value, comment, type, category, Tag.name',
                    'test' => null,
                    'type' => 'string',
                ],
                'manage_workers' => [
                    'level' => 2,
                    'description' => __('Set this to false if you would like to disable MISP managing its own worker processes (for example, if you are managing the workers with a systemd unit).'),
                    'value' => true,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'deadlock_avoidance' => [
                    'level' => 1,
                    'description' => __('Only enable this if you have some tools using MISP with extreme high concurency. General performance will be lower as normal as certain transactional queries are avoided in favour of shorter table locks.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'updateTimeThreshold' => [
                    'level' => 1,
                    'description' => __('Sets the minimum time before being able to re-trigger an update if the previous one failed. (safe guard to avoid starting the same update multiple time)'),
                    'value' => '7200',
                    'test' => 'testForNumeric',
                    'type' => 'numeric',
                    'null' => true
                ],
                'attribute_filters_block_only' => [
                    'level' => 1,
                    'description' => __('This is a performance tweak to change the behaviour of restSearch to use attribute filters solely for blocking. This means that a lookup on the event scope with for example the type field set will be ignored unless it\'s used to strip unwanted attributes from the results. If left disabled, passing [ip-src, ip-dst] for example will return any event with at least one ip-src or ip-dst attribute. This is generally not considered to be too useful and is a heavy burden on the database.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'attachment_scan_module' => [
                    'level' => self::SETTING_OPTIONAL,
                    'description' => __('Name of enrichment module that will be used for attachment malware scanning. This module must return av-signature or sb-signature object.'),
                    'value' => '',
                    'type' => 'string',
                    'null' => true,
                ],
                'attachment_scan_hash_only' => [
                    'level' => self::SETTING_OPTIONAL,
                    'description' => __('Send to attachment scan module just file hash. This can be useful if module sends attachment to remote service and you don\'t want to leak real data.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true,
                ],
                'attachment_scan_timeout' => [
                    'level' => self::SETTING_OPTIONAL,
                    'description' => __('How long to wait for scan results in seconds.'),
                    'value' => 30,
                    'test' => 'testForPositiveInteger',
                    'type' => 'numeric',
                    'null' => true,
                ],
                'warning_for_all' => [
                    'level' => self::SETTING_RECOMMENDED,
                    'description' => __('Enable warning list triggers regardless of the IDS flag value.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'system_setting_db' => [
                    'level' => self::SETTING_RECOMMENDED,
                    'description' => __('Enable storing setting in database.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true,
                    'cli_only' => true,
                ],
                'menu_custom_right_link' => [
                    'level' => self::SETTING_OPTIONAL,
                    'description' => __('Custom right menu URL.'),
                    'value' => null,
                    'type' => 'string',
                    'null' => true,
                ],
                'menu_custom_right_link_html' => [
                    'level' => self::SETTING_OPTIONAL,
                    'description' => __('Custom right menu text (it is possible to use HTML).'),
                    'value' => null,
                    'type' => 'string',
                    'null' => true,
                ],
                'enable_synchronisation_filtering_on_type' => [
                    'level' => self::SETTING_OPTIONAL,
                    'description' => __('Allows server synchronisation connections to be filtered on Attribute type or Object name. Warning: This feature can potentially cause your synchronisation partners to receive incomplete versions of the events you are propagating on behalf of others. This means that even if they would be receiving the unfiltered version through another instance, your filtered version might be the one they receive on a first-come-first-serve basis.'),
                    'value' => false,
                    'test' => 'testBoolFalse',
                    'type' => 'boolean',
                    'null' => true,
                ],
                'download_gpg_from_homedir' => [
                    'level' => self::SETTING_OPTIONAL,
                    'description' => __('Fetch GPG instance key from GPG homedir.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true,
                    'cli_only' => true,
                ],
                'enable_clusters_mirroring_from_attributes_to_event' => [
                    'level' => self::SETTING_OPTIONAL,
                    'description' => __('Add a checkbox when attaching a cluster to an Attribute which, when checked, will also create the same clusters on the attribute\'s event.'),
                    'value' => false,
                    'test' => 'testBoolFalse',
                    'type' => 'boolean',
                    'null' => true,
                ],
                'thumbnail_in_redis' => [
                    'level' => self::SETTING_OPTIONAL,
                    'description' => __('Store image thumbnails in Redis instead of file system.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true,
                ],
                'self_update' => [
                    'level' => self::SETTING_CRITICAL,
                    'description' => __('Enable the GUI button for MISP self-update on the Diagnostics page.'),
                    'value' => true,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true,
                    'cli_only' => true,
                ],
                'online_version_check' => [
                    'level' => self::SETTING_CRITICAL,
                    'description' => __('Enable the online MISP version check when loading the Diagnostics page.'),
                    'value' => true,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true,
                    'cli_only' => true,
                ],
            ],
            'GnuPG' => [
                'branch' => 1,
                'binary' => [
                    'level' => 2,
                    'description' => __('The location of the GnuPG executable. If you would like to use a different GnuPG executable than /usr/bin/gpg, you can set it here. If the default is fine, just keep the setting suggested by MISP.'),
                    'value' => '/usr/bin/gpg',
                    'test' => 'testForGPGBinary',
                    'type' => 'string',
                    'cli_only' => 1
                ],
                'onlyencrypted' => [
                    'level' => 0,
                    'description' => __('Allow (false) unencrypted e-mails to be sent to users that don\'t have a GnuPG key.'),
                    'value' => '',
                    'test' => 'testBool',
                    'type' => 'boolean',
                ],
                'bodyonlyencrypted' => [
                    'level' => 2,
                    'description' => __('Allow (false) the body of unencrypted e-mails to contain details about the event.'),
                    'value' => '',
                    'test' => 'testBool',
                    'type' => 'boolean',
                ],
                'sign' => [
                    'level' => 2,
                    'description' => __('Enable the signing of GnuPG emails. By default, GnuPG emails are signed'),
                    'value' => true,
                    'test' => 'testBool',
                    'type' => 'boolean',
                ],
                'email' => [
                    'level' => 0,
                    'description' => __('The e-mail address that the instance\'s GnuPG key is tied to.'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'password' => [
                    'level' => 1,
                    'description' => __('The password (if it is set) of the GnuPG key of the instance.'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                    'redacted' => true
                ],
                'homedir' => [
                    'level' => 0,
                    'description' => __('The location of the GnuPG homedir.'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'obscure_subject' => [
                    'level' => 2,
                    'description' => __('When enabled, the subject in signed and encrypted e-mails will not be sent in unencrypted form.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                ],
                'key_fetching_disabled' => [
                    'level' => self::SETTING_OPTIONAL,
                    'description' => __('When disabled, user could not fetch his PGP key from CIRCL key server. Key fetching requires internet connection.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                ],
            ],
            'SMIME' => [
                'branch' => 1,
                'enabled' => [
                    'level' => 2,
                    'description' => __('Enable S/MIME encryption. The encryption posture of the GnuPG.onlyencrypted and GnuPG.bodyonlyencrypted settings are inherited if S/MIME is enabled.'),
                    'value' => '',
                    'test' => 'testBool',
                    'type' => 'boolean',
                ],
                'email' => [
                    'level' => 2,
                    'description' => __('The e-mail address that the instance\'s S/MIME key is tied to.'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'cert_public_sign' => [
                    'level' => 2,
                    'description' => __('The location of the public half of the signing certificate.'),
                    'value' => '/var/www/MISP/.smime/email@address.com.pem',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'key_sign' => [
                    'level' => 2,
                    'description' => __('The location of the private half of the signing certificate.'),
                    'value' => '/var/www/MISP/.smime/email@address.com.key',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'password' => [
                    'level' => 2,
                    'description' => __('The password (if it is set) of the S/MIME key of the instance.'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                    'redacted' => true
                ],
            ],
            'Proxy' => [
                'branch' => 1,
                'host' => [
                    'level' => 2,
                    'description' => __('The hostname of an HTTP proxy for outgoing sync requests. Leave empty to not use a proxy.'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'port' => [
                    'level' => 2,
                    'description' => __('The TCP port for the HTTP proxy.'),
                    'value' => '',
                    'test' => 'testForNumeric',
                    'type' => 'numeric',
                ],
                'method' => [
                    'level' => 2,
                    'description' => __('The authentication method for the HTTP proxy. Currently supported are Basic or Digest. Leave empty for no proxy authentication.'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'user' => [
                    'level' => 2,
                    'description' => __('The authentication username for the HTTP proxy.'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'password' => [
                    'level' => 2,
                    'description' => __('The authentication password for the HTTP proxy.'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                    'redacted' => true
                ],
            ],
            'Security' => [
                'branch' => 1,
                'disable_form_security' => [
                    'level' => 0,
                    'description' => __('Disabling this setting will remove all form tampering protection. Do not set this setting pretty much ever. You were warned.'),
                    'value' => false,
                    'errorMessage' => 'This setting leaves your users open to CSRF attacks. Please consider disabling this setting.',
                    'test' => 'testBoolFalse',
                    'type' => 'boolean',
                    'null' => true
                ],
                'csp_enforce' => [
                    'level' => self::SETTING_CRITICAL,
                    'description' => __('Enforce CSP. Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. When disabled, violations will be just logged.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                ],
                'salt' => [
                    'level' => 0,
                    'description' => __('The salt used for the hashed passwords. You cannot reset this from the GUI, only manually from the settings.php file. Keep in mind, this will invalidate all passwords in the database.'),
                    'value' => '',
                    'test' => 'testSalt',
                    'type' => 'string',
                    'editable' => false,
                    'redacted' => true
                ],
                'log_each_individual_auth_fail' => [
                    'level' => 1,
                    'description' => __('By default API authentication failures that happen within the same hour for the same key are omitted and a single log entry is generated. This allows administrators to more easily keep track of attackers that try to brute force API authentication, by reducing the noise generated by expired API keys. On the other hand, this makes little sense for internal MISP instances where detecting the misconfiguration of tools becomes more interesting, so if you fall into the latter category, enable this feature.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                ],
                'advanced_authkeys' => [
                    'level' => 0,
                    'description' => __('Advanced authkeys will allow each user to create and manage a set of authkeys for themselves, each with individual expirations and comments. API keys are stored in a hashed state and can no longer be recovered from MISP. Users will be prompted to note down their key when creating a new authkey. You can generate a new set of API keys for all users on demand in the diagnostics page, or by triggering %s.', sprintf('<a href="%s/servers/serverSettings/diagnostics#advanced_authkey_update">%s</a>', $this->baseurl, __('the advanced upgrade'))),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                ],
                'advanced_authkeys_validity' => [
                    'level' => self::SETTING_OPTIONAL,
                    'description' => __('Maximal key lifetime in days. Use can limit that validity even more. Just newly created keys will be affected. When not set, key validity is not limited.'),
                    'value' => '',
                    'type' => 'numeric',
                    'test' => 'testForNumeric',
                    'null' => true,
                ],
                'authkey_keep_session' => [
                    'level' => self::SETTING_OPTIONAL,
                    'description' => __('When enabled, session is kept between API requests.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true,
                ],
                'auth_enforced' => [
                    'level' => self::SETTING_OPTIONAL,
                    'description' => __('This optionally can be enabled if an external auth provider is used. When set to true, it will disable the default form authentication.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                ],
                'rest_client_enable_arbitrary_urls' => [
                    'level' => 0,
                    'description' => __('Enable this setting if you wish for users to be able to query any arbitrary URL via the rest client. Keep in mind that queries are executed by the MISP server, so internal IPs in your MISP\'s network may be reachable.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true,
                    'cli_only' => 1
                ],
                'rest_client_baseurl' => [
                    'level' => 1,
                    'description' => __('If left empty, the baseurl of your MISP is used. However, in some instances (such as port-forwarded VM installations) this will not work. You can override the baseurl with a url through which your MISP can reach itself (typically https://127.0.0.1 would work).'),
                    'value' => false,
                    'test' => null,
                    'type' => 'string'
                ],
                'syslog' => [
                    'level' => 0,
                    'description' => __('Enable this setting to pass all audit log entries directly to syslog. Keep in mind, this is verbose and will include user, organisation, event data.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'syslog_to_stderr' => [
                    'level' => self::SETTING_OPTIONAL,
                    'description' => __('Write syslog messages also to standard error output.'),
                    'value' => true,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'syslog_ident' => [
                    'level' => self::SETTING_OPTIONAL,
                    'description' => __('Syslog message identifier.'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                    'null' => true
                ],
                'do_not_log_authkeys' => [
                    'level' => 0,
                    'description' => __('If enabled, any authkey will be replaced by asterisks in Audit log.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'mandate_ip_allowlist_advanced_authkeys' => [
                    'level' => 2,
                    'description' => __('If enabled, setting an ip allowlist will be mandatory when adding or editing an advanced authkey.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'disable_browser_cache' => [
                    'level' => 0,
                    'description' => __('If enabled, HTTP headers that block browser cache will be send. Static files (like images or JavaScripts) will still be cached, but not generated pages.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true,
                ],
                'check_sec_fetch_site_header' => [
                    'level' => 0,
                    'description' => __('If enabled, any POST, PUT or AJAX request will be allow just when Sec-Fetch-Site header is not defined or contains "same-origin".'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true,
                ],
                'force_https' => [
                    'level' => self::SETTING_OPTIONAL,
                    'description' => __('If enabled, MISP server will consider all requests as secure. This is usually useful when you run MISP behind reverse proxy that terminates HTTPS.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true,
                ],
                'otp_required' => [
                    'level' => 2,
                    'description' => __('Require authentication with OTP. Users that do not have (T/H)OTP configured will be forced to create a token at first login. You cannot use it in combination with external authentication plugins.'),
                    'value' => false,
                    'test' => 'testBool',
                    'beforeHook' => 'otpBeforeHook',
                    'type' => 'boolean',
                    'null' => true
                ],
                'otp_issuer' => [
                    'level' => 2,
                    'description' => __('If OTP is enabled, set the issuer string to an arbitrary value. Otherwise, MISP will default to "[MISP.org] MISP".'),
                    'value' => false,
                    'test' => 'testForEmpty',
                    'type' => 'string',
                    'null' => true
                ],
                'email_otp_enabled' => [
                    'level' => 2,
                    'description' => __('Enable two step authentication with a OTP sent by email. Requires e-mailing to be enabled. Warning: You cannot use it in combination with external authentication plugins.'),
                    'value' => false,
                    'test' => 'testBool',
                    'beforeHook' => 'email_otpBeforeHook',
                    'type' => 'boolean',
                    'null' => true
                ],
                'email_otp_length' => [
                    'level' => 2,
                    'description' => __('Define the length of the OTP code sent by email'),
                    'value' => '6',
                    'type' => 'numeric',
                    'test' => 'testForNumeric',
                    'null' => true,
                ],
                'email_otp_validity' => [
                    'level' => 2,
                    'description' => __('Define the validity (in minutes) of the OTP code sent by email'),
                    'value' => '5',
                    'type' => 'numeric',
                    'test' => 'testForNumeric',
                    'null' => true,
                ],
                'email_otp_text' => [
                    'level' => 2,
                    'bigField' => true,
                    'description' => __('The message sent to the user when a new OTP is requested. Use \\n for line-breaks. The following variables will be automatically replaced in the text: $otp = the new OTP generated by MISP, $username = the user\'s e-mail address, $org the Organisation managing the instance, $misp = the url of this instance, $contact = the e-mail address used to contact the support team (as set in MISP.contact), $ip the IP used to complete the first step of the login and $validity the validity time in minutes.'),
                    'value' => 'Dear MISP user,\n\nYou have attempted to login to MISP ($misp) from $ip with username $username.\n\n Use the following OTP to log into MISP: $otp\n This code is valid for the next $validity minutes.\n\nIf you have any questions, don\'t hesitate to contact us at: $contact.\n\nBest regards,\nYour $org MISP support team',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                    'null' => true,
                ],
                'email_otp_exceptions' => [
                    'level' => 2,
                    'bigField' => true,
                    'description' => __('A comma separated list of emails for which the OTP is disabled. Note that if you remove someone from this list, the OTP will only be asked at next login.'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                    'null' => true,
                ],
                'allow_self_registration' => [
                    'level' => 1,
                    'description' => __('Enabling this setting will allow users to have access to the pre-auth registration form. This will create an inbox entry for administrators to review.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'allow_password_forgotten' => [
                    'level' => 1,
                    'description' => __('Enabling this setting will allow users to request automated password reset tokens via mail and initiate a reset themselves. Users with no encryption keys will not be able to use this feature.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'self_registration_message' => [
                    'level' => 1,
                    'bigField' => true,
                    'description' => __('The message sent shown to anyone trying to self-register.'),
                    'value' => 'If you would like to send us a registration request, please fill out the form below. Make sure you fill out as much information as possible in order to ease the task of the administrators.',
                    'test' => false,
                    'type' => 'string'
                ],
                'password_policy_length' => [
                    'level' => 2,
                    'description' => __('Password length requirement. If it is not set or it is set to 0, then the default value is assumed (12).'),
                    'value' => '12',
                    'test' => 'testPasswordLength',
                    'type' => 'numeric',
                ],
                'password_policy_complexity' => [
                    'level' => 2,
                    'description' => __('Password complexity requirement. Leave it empty for the default setting (3 out of 4, with either a digit or a special char) or enter your own regex. Keep in mind that the length is checked in another key. Default (simple 3 out of 4 or minimum 16 characters): /^((?=.*\d)|(?=.*\W+))(?![\n])(?=.*[A-Z])(?=.*[a-z]).*$|.{16,}/'),
                    'value' => '/^((?=.*\d)|(?=.*\W+))(?![\n])(?=.*[A-Z])(?=.*[a-z]).*$|.{16,}/',
                    'test' => 'testPasswordRegex',
                    'type' => 'string',
                ],
                'require_password_confirmation' => [
                    'level' => 1,
                    'description' => __('Enabling this setting will require users to submit their current password on any edits to their profile (including a triggered password change). For administrators, the confirmation will be required when changing the profile of any user. Could potentially mitigate an attacker trying to change a compromised user\'s password in order to establish persistance, however, enabling this feature will be highly annoying to users.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'sanitise_attribute_on_delete' => [
                    'level' => 1,
                    'description' => __('Enabling this setting will sanitise the contents of an attribute on a soft delete'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'hide_organisation_index_from_users' => [
                    'level' => 1,
                    'description' => __('Enabling this setting will block the organisation index from being visible to anyone besides site administrators on the current instance. Keep in mind that users can still see organisations that produce data via events, proposals, event history log entries, etc.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'hide_organisations_in_sharing_groups' => [
                    'level' => self::SETTING_RECOMMENDED,
                    'description' => __('Enabling this setting will block the organisation list from being visible in sharing group besides user with sharing group permission.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'disable_local_feed_access' => [
                    'level' => 0,
                    'description' => __('Disabling this setting will allow the creation/modification of local feeds (as opposed to network feeds). Enabling this setting will restrict feed sources to be network based only. When disabled, keep in mind that a malicious site administrator could get access to any arbitrary file on the system that the apache user has access to. Make sure that proper safe-guards are in place. This setting can only be modified via the CLI.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true,
                    'cli_only' => 1
                ],
                'allow_unsafe_apikey_named_param' => [
                    'level' => 0,
                    'description' => __('Allows passing the API key via the named url parameter "apikey" - highly recommended not to enable this, but if you have some dodgy legacy tools that cannot pass the authorization header it can work as a workaround. Again, only use this as a last resort.'),
                    'value' => false,
                    'errorMessage' => __('You have enabled the passing of API keys via URL parameters. This is highly recommended against, do you really want to reveal APIkeys in your logs?...'),
                    'test' => 'testBoolFalse',
                    'type' => 'boolean',
                    'null' => true
                ],
                'allow_cors' => [
                    'level' => 1,
                    'description' => __('Allow cross-origin requests to this instance, matching origins given in Security.cors_origins. Set to false to totally disable'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'cors_origins' => [
                    'level' => 1,
                    'description' => __('Set the origins from which MISP will allow cross-origin requests. Useful for external integration. Comma seperate if you need more than one.'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                    'null' => true
                ],
                'sync_audit' => [
                    'level' => 1,
                    'description' => __('Enable this setting to create verbose logs of synced event data for debugging reasons. Logs are saved in your MISP directory\'s app/files/scripts/tmp/ directory.'),
                    'value' => false,
                    'test' => 'testBoolFalse',
                    'type' => 'boolean',
                    'null' => true
                ],
                'user_monitoring_enabled' => [
                    'level' => 1,
                    'description' => __('Enables the functionality to monitor users - thereby enabling all logging functionalities for a single user. This functionality is intrusive and potentially heavy on the system - use it with care.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'username_in_response_header' => [
                    'level' => self::SETTING_OPTIONAL,
                    'description' => __('When enabled, logged in username will be included in X-Username HTTP response header. This is useful for request logging on webserver/proxy side.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'encryption_key' => [
                    'level' => self::SETTING_OPTIONAL,
                    'description' => __('Encryption key used to store sensitive data (like authkeys) in database encrypted. If empty, data are stored unencrypted. Requires PHP 7.1 or newer.'),
                    'value' => '',
                    'test' => function ($value) {
                        if (strlen($value) < 32) {
                            return __('Encryption key must be at least 32 chars long.');
                        }
                        return true;
                    },
                    // $table->behaviors()->has('EncryptedFields');
                    'afterHook' => function ($setting, $new, $old) {
                        // LATER change code to automatically search for xxTables with EncryptedFieldsBehalvior and re-encrypte all the keys using changeKey($old) of the Behavior
                        // although at first sight this is complex and requires filesystem listings
                        /** @var SystemSetting $systemSetting */
                        $systemSetting = $this->fetchTable('SystemSettings');
                        $systemSetting->changeKey($old);

                        /** Server */
                        $this->changeKey($old);

                        /** @var Cerebrate $cerebrate */
                        $cerebrate = $this->fetchTable('Cerebrates');
                        $cerebrate->changeKey($old);
                        return true;
                    },
                    'type' => 'string',
                    'null' => true,
                    'cli_only' => true,
                    'redacted' => true,
                ],
                'min_tls_version' => [
                    'level' => self::SETTING_OPTIONAL,
                    'description' => __('Minimal required TLS version when connecting to external resources.'),
                    'value' => '',
                    'type' => 'string',
                    'null' => true,
                    'options' => [
                        '' => __('All versions'),
                        'tlsv1_0' => 'TLSv1.0',
                        'tlsv1_1' => 'TLSv1.1',
                        'tlsv1_2' => 'TLSv1.2',
                        'tlsv1_3' => 'TLSv1.3',
                    ],
                ],
                'enable_svg_logos' => [
                    'level' => self::SETTING_OPTIONAL,
                    'description' => __('When enabled, organisations logos in svg format are allowed.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'disable_instance_file_uploads' => [
                    'level' => self::SETTING_RECOMMENDED,
                    'description' => __('When enabled, the "Manage files" menu is disabled on the server settings. You can still copy files via ssh to the appropriate location and link them using MISP.settings.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true,
                    'cli_only' => true
                ],
                'disclose_user_emails' => [
                    'level' => 0,
                    'description' => __('Enable this setting to allow for the user e-mail addresses to be shown to non site-admin users. Keep in mind that in broad communities this can be abused.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
            ],
            'SecureAuth' => [
                'branch' => 1,
                'amount' => [
                    'level' => 0,
                    'description' => __('The number of tries a user can try to login and fail before the bruteforce protection kicks in.'),
                    'value' => '',
                    'test' => 'testForNumeric',
                    'type' => 'numeric',
                ],
                'expire' => [
                    'level' => 0,
                    'description' => __('The duration (in seconds) of how long the user will be locked out when the allowed number of login attempts are exhausted.'),
                    'value' => '',
                    'test' => 'testForNumeric',
                    'type' => 'numeric',
                ],
            ],
            'Session' => [
                'branch' => 1,
                'autoRegenerate' => [
                    'level' => 0,
                    'description' => __('Set to true to automatically regenerate sessions after x number of requests. This might lead to the user getting de-authenticated and is frustrating in general, so only enable it if you really need to regenerate sessions. (Not recommended)'),
                    'value' => false,
                    'test' => 'testBoolFalse',
                    'type' => 'boolean',
                ],
                'checkAgent' => [
                    'level' => 0,
                    'description' => __('Set to true to check for the user agent string in each request. This can lead to occasional logouts (not recommended).'),
                    'value' => false,
                    'test' => 'testBoolFalse',
                    'type' => 'boolean',
                ],
                'defaults' => [
                    'level' => 0,
                    'description' => __('The session type used by MISP. The default setting is php, which will use the session settings configured in php.ini for the session data (supported options: php, database). The recommended option is php and setting your PHP up to use redis sessions via your php.ini. Just add \'session.save_handler = redis\' and "session.save_path = \'tcp://localhost:6379\'" (replace the latter with your redis connection) to '),
                    'value' => '',
                    'test' => 'testForSessionDefaults',
                    'type' => 'string',
                    'options' => ['php' => 'php', 'database' => 'database', 'cake' => 'cake', 'cache' => 'cache'],
                ],
                'timeout' => [
                    'level' => 0,
                    'description' => __('The timeout duration of sessions (in MINUTES). 0 does not mean infinite for the PHP session handler, instead sessions will invalidate immediately.'),
                    'value' => '',
                    'test' => 'testForNumeric',
                    'type' => 'numeric'
                ],
                'cookieTimeout' => [
                    'level' => 0,
                    'description' => __('The expiration of the cookie (in MINUTES). The session timeout gets refreshed frequently, however the cookies do not. Generally it is recommended to have a much higher cookie_timeout than timeout.'),
                    'value' => '',
                    'test' => 'testForCookieTimeout',
                    'type' => 'numeric'
                ]
            ],
            'Plugin' => [
                'branch' => 1,
                'RPZ_policy' => [
                    'level' => 2,
                    'description' => __('The default policy action for the values added to the RPZ.'),
                    'value' => 1,
                    'test' => 'testForRPZBehaviour',
                    'type' => 'numeric',
                    'options' => [0 => 'DROP', 1 => 'NXDOMAIN', 2 => 'NODATA', 3 => 'Local-Data', 4 => 'PASSTHRU', 5 => 'TCP-only'],
                ],
                'RPZ_walled_garden' => [
                    'level' => 2,
                    'description' => __('The default walled garden used by the RPZ export if the Local-Data policy setting is picked for the export.'),
                    'value' => '127.0.0.1',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'RPZ_serial' => [
                    'level' => 2,
                    'description' => __('The serial in the SOA portion of the zone file. (numeric, best practice is yyyymmddrr where rr is the two digit sub-revision of the file. $date will automatically get converted to the current yyyymmdd, so $date00 is a valid setting). Setting it to $time will give you an unixtime-based serial (good then you need more than 99 revisions per day).'),
                    'value' => '$date00',
                    'test' => 'testForRPZSerial',
                    'type' => 'string',
                ],
                'RPZ_refresh' => [
                    'level' => 2,
                    'description' => __('The refresh specified in the SOA portion of the zone file. (in seconds, or shorthand duration such as 15m)'),
                    'value' => '2h',
                    'test' => 'testForRPZDuration',
                    'type' => 'string',
                ],
                'RPZ_retry' => [
                    'level' => 2,
                    'description' => __('The retry specified in the SOA portion of the zone file. (in seconds, or shorthand duration such as 15m)'),
                    'value' => '30m',
                    'test' => 'testForRPZDuration',
                    'type' => 'string',
                ],
                'RPZ_expiry' => [
                    'level' => 2,
                    'description' => __('The expiry specified in the SOA portion of the zone file. (in seconds, or shorthand duration such as 15m)'),
                    'value' => '30d',
                    'test' => 'testForRPZDuration',
                    'type' => 'string',
                ],
                'RPZ_minimum_ttl' => [
                    'level' => 2,
                    'description' => __('The minimum TTL specified in the SOA portion of the zone file. (in seconds, or shorthand duration such as 15m)'),
                    'value' => '1h',
                    'test' => 'testForRPZDuration',
                    'type' => 'string',
                ],
                'RPZ_ttl' => [
                    'level' => 2,
                    'description' => __('The TTL of the zone file. (in seconds, or shorthand duration such as 15m)'),
                    'value' => '1w',
                    'test' => 'testForRPZDuration',
                    'type' => 'string',
                ],
                'RPZ_ns' => [
                    'level' => 2,
                    'description' => __('Nameserver'),
                    'value' => 'localhost.',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'RPZ_ns_alt' => [
                    'level' => 2,
                    'description' => __('Alternate nameserver'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'RPZ_email' => [
                    'level' => 2,
                    'description' => __('The e-mail address specified in the SOA portion of the zone file.'),
                    'value' => 'root.localhost',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'Kafka_enable' => [
                    'level' => 2,
                    'description' => __('Enables or disables the Kafka pub feature of MISP. Make sure that you install the requirements for the plugin to work. Refer to the installation instructions for more information.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                ],
                'Kafka_brokers' => [
                    'level' => 2,
                    'description' => __('A comma separated list of Kafka bootstrap brokers'),
                    'value' => 'kafka:9092',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'Kafka_rdkafka_config' => [
                    'level' => 2,
                    'description' => __('A path to an ini file with configuration options to be passed to rdkafka. Section headers in the ini file will be ignored.'),
                    'value' => '/etc/rdkafka.ini',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'Kafka_include_attachments' => [
                    'level' => 2,
                    'description' => __('Enable this setting to include the base64 encoded payloads of malware-samples/attachments in the output.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'Kafka_event_notifications_enable' => [
                    'level' => 2,
                    'description' => __('Enables or disables the publishing of any event creations/edits/deletions.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'Kafka_event_notifications_topic' => [
                    'level' => 2,
                    'description' => __('Topic for publishing event creations/edits/deletions.'),
                    'value' => 'misp_event',
                    'test' => 'testForEmpty',
                    'type' => 'string'
                ],
                'Kafka_event_publish_notifications_enable' => [
                    'level' => 2,
                    'description' => __('If enabled it will publish to Kafka the event at the time that the event gets published in MISP. Event actions (creation or edit) will not be published to Kafka.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'Kafka_event_publish_notifications_topic' => [
                    'level' => 2,
                    'description' => __('Topic for publishing event information on publish.'),
                    'value' => 'misp_event_publish',
                    'test' => 'testForEmpty',
                    'type' => 'string'
                ],
                'Kafka_object_notifications_enable' => [
                    'level' => 2,
                    'description' => __('Enables or disables the publishing of any object creations/edits/deletions.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'Kafka_object_notifications_topic' => [
                    'level' => 2,
                    'description' => __('Topic for publishing object creations/edits/deletions.'),
                    'value' => 'misp_object',
                    'test' => 'testForEmpty',
                    'type' => 'string'
                ],
                'Kafka_object_reference_notifications_enable' => [
                    'level' => 2,
                    'description' => __('Enables or disables the publishing of any object reference creations/deletions.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'Kafka_object_reference_notifications_topic' => [
                    'level' => 2,
                    'description' => __('Topic for publishing object reference creations/deletions.'),
                    'value' => 'misp_object_reference',
                    'test' => 'testForEmpty',
                    'type' => 'string'
                ],
                'Kafka_attribute_notifications_enable' => [
                    'level' => 2,
                    'description' => __('Enables or disables the publishing of any attribute creations/edits/soft deletions.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'Kafka_attribute_notifications_topic' => [
                    'level' => 2,
                    'description' => __('Topic for publishing attribute creations/edits/soft deletions.'),
                    'value' => 'misp_attribute',
                    'test' => 'testForEmpty',
                    'type' => 'string'
                ],
                'Kafka_shadow_attribute_notifications_enable' => [
                    'level' => 2,
                    'description' => __('Enables or disables the publishing of any proposal creations/edits/deletions.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'Kafka_shadow_attribute_notifications_topic' => [
                    'level' => 2,
                    'description' => __('Topic for publishing proposal creations/edits/deletions.'),
                    'value' => 'misp_shadow_attribute',
                    'test' => 'testForEmpty',
                    'type' => 'string'
                ],
                'Kafka_tag_notifications_enable' => [
                    'level' => 2,
                    'description' => __('Enables or disables the publishing of any tag creations/edits/deletions as well as tags being attached to / detached from various MISP elements.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'Kafka_tag_notifications_topic' => [
                    'level' => 2,
                    'description' => __('Topic for publishing tag creations/edits/deletions as well as tags being attached to / detached from various MISP elements.'),
                    'value' => 'misp_tag',
                    'test' => 'testForEmpty',
                    'type' => 'string'
                ],
                'Kafka_sighting_notifications_enable' => [
                    'level' => 2,
                    'description' => __('Enables or disables the publishing of new sightings.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'Kafka_sighting_notifications_topic' => [
                    'level' => 2,
                    'description' => __('Topic for publishing sightings.'),
                    'value' => 'misp_sighting',
                    'test' => 'testForEmpty',
                    'type' => 'string'
                ],
                'Kafka_user_notifications_enable' => [
                    'level' => 2,
                    'description' => __('Enables or disables the publishing of new/modified users.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'Kafka_user_notifications_topic' => [
                    'level' => 2,
                    'description' => __('Topic for publishing new/modified users.'),
                    'value' => 'misp_user',
                    'test' => 'testForEmpty',
                    'type' => 'string'
                ],
                'Kafka_organisation_notifications_enable' => [
                    'level' => 2,
                    'description' => __('Enables or disables the publishing of new/modified organisations.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'Kafka_organisation_notifications_topic' => [
                    'level' => 2,
                    'description' => __('Topic for publishing new/modified organisations.'),
                    'value' => 'misp_organisation',
                    'test' => 'testForEmpty',
                    'type' => 'string'
                ],
                'Kafka_audit_notifications_enable' => [
                    'level' => 2,
                    'description' => __('Enables or disables the publishing of log entries. Keep in mind, this can get pretty verbose depending on your logging settings.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'Kafka_audit_notifications_topic' => [
                    'level' => 2,
                    'description' => __('Topic for publishing log entries.'),
                    'value' => 'misp_audit',
                    'test' => 'testForEmpty',
                    'type' => 'string'
                ],
                'ZeroMQ_enable' => [
                    'level' => 2,
                    'description' => __('Enables or disables the pub/sub feature of MISP. Make sure that you install the requirements for the plugin to work. Refer to the installation instructions for more information.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'afterHook' => 'zmqAfterHook',
                ],
                'ZeroMQ_host' => [
                    'level' => 2,
                    'description' => __('The host that the pub/sub feature will use.'),
                    'value' => '127.0.0.1',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                    'afterHook' => 'zmqAfterHook',
                ],
                'ZeroMQ_port' => [
                    'level' => 2,
                    'description' => __('The port that the pub/sub feature will use.'),
                    'value' => 50000,
                    'test' => 'testForZMQPortNumber',
                    'type' => 'numeric',
                    'afterHook' => 'zmqAfterHook',
                ],
                'ZeroMQ_username' => [
                    'level' => 2,
                    'description' => __('The username that client need to use to connect to ZeroMQ.'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                    'afterHook' => 'zmqAfterHook',
                ],
                'ZeroMQ_password' => [
                    'level' => 2,
                    'description' => __('The password that client need to use to connect to ZeroMQ.'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                    'afterHook' => 'zmqAfterHook',
                    'redacted' => true
                ],
                'ZeroMQ_redis_host' => [
                    'level' => 2,
                    'description' => __('Location of the Redis db used by MISP and the Python PUB script to queue data to be published.'),
                    'value' => 'localhost',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                    'afterHook' => 'zmqAfterHook',
                ],
                'ZeroMQ_redis_port' => [
                    'level' => 2,
                    'description' => __('The port that Redis is listening on.'),
                    'value' => 6379,
                    'test' => 'testForPortNumber',
                    'type' => 'numeric',
                    'afterHook' => 'zmqAfterHook',
                ],
                'ZeroMQ_redis_password' => [
                    'level' => 2,
                    'description' => __('The password, if set for Redis.'),
                    'value' => '',
                    'type' => 'string',
                    'afterHook' => 'zmqAfterHook',
                    'redacted' => true
                ],
                'ZeroMQ_redis_database' => [
                    'level' => 2,
                    'description' => __('The database to be used for queuing messages for the pub/sub functionality.'),
                    'value' => 1,
                    'test' => 'testForEmpty',
                    'type' => 'string',
                    'afterHook' => 'zmqAfterHook',
                ],
                'ZeroMQ_redis_namespace' => [
                    'level' => 2,
                    'description' => __('The namespace to be used for queuing messages for the pub/sub functionality.'),
                    'value' => 'mispq',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                    'afterHook' => 'zmqAfterHook',
                ],
                'ZeroMQ_include_attachments' => [
                    'level' => 2,
                    'description' => __('Enable this setting to include the base64 encoded payloads of malware-samples/attachments in the output.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'ZeroMQ_event_notifications_enable' => [
                    'level' => 2,
                    'description' => __('Enables or disables the publishing of any event creations/edits/deletions.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'ZeroMQ_object_notifications_enable' => [
                    'level' => 2,
                    'description' => __('Enables or disables the publishing of any object creations/edits/deletions.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'ZeroMQ_object_reference_notifications_enable' => [
                    'level' => 2,
                    'description' => __('Enables or disables the publishing of any object reference creations/deletions.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'ZeroMQ_attribute_notifications_enable' => [
                    'level' => 2,
                    'description' => __('Enables or disables the publishing of any attribute creations/edits/soft deletions.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'ZeroMQ_tag_notifications_enable' => [
                    'level' => 2,
                    'description' => __('Enables or disables the publishing of any tag creations/edits/deletions as well as tags being attached to / detached from various MISP elements.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'ZeroMQ_sighting_notifications_enable' => [
                    'level' => 2,
                    'description' => __('Enables or disables the publishing of new sightings to the ZMQ pubsub feed.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'ZeroMQ_user_notifications_enable' => [
                    'level' => 2,
                    'description' => __('Enables or disables the publishing of new/modified users to the ZMQ pubsub feed.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'ZeroMQ_organisation_notifications_enable' => [
                    'level' => 2,
                    'description' => __('Enables or disables the publishing of new/modified organisations to the ZMQ pubsub feed.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'ZeroMQ_audit_notifications_enable' => [
                    'level' => 2,
                    'description' => __('Enables or disables the publishing of log entries to the ZMQ pubsub feed. Keep in mind, this can get pretty verbose depending on your logging settings.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'ZeroMQ_warninglist_notifications_enable' => [
                    'level' => 2,
                    'description' => __('Enables or disables the publishing of new/modified warninglist to the ZMQ pubsub feed.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'ElasticSearch_logging_enable' => [
                    'level' => 2,
                    'description' => __('Enabled logging to an ElasticSearch instance'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'ElasticSearch_connection_string' => [
                    'level' => 2,
                    'description' => __('The URL(s) at which to access ElasticSearch - comma separate if you want to have more than one.'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string'
                ],
                'ElasticSearch_log_index' => [
                    'level' => 2,
                    'description' => __('The index in which to place logs'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string'
                ],
                'S3_enable' => [
                    'level' => 2,
                    'description' => __('Enables or disables uploading of malware samples to S3 rather than to disk (WARNING: Get permission from amazon first!)'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'S3_aws_compatible' => [
                    'level' => 2,
                    'description' => __('Use external AWS compatible system such as MinIO'),
                    'value' => false,
                    'errorMessage' => '',
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'S3_aws_ca' => [
                    'level' => 2,
                    'description' => __('AWS TLS CA, set to empty to use CURL internal trusted certificates or path for custom trusted CA'),
                    'value' => '',
                    'errorMessage' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string'
                ],
                'S3_aws_validate_ca' => [
                    'level' => 2,
                    'description' => __('Validate CA'),
                    'value' => true,
                    'errorMessage' => '',
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'S3_aws_endpoint' => [
                    'level' => 2,
                    'description' => __('Uses external AWS compatible endpoint such as MinIO'),
                    'value' => '',
                    'errorMessage' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string'
                ],
                'S3_bucket_name' => [
                    'level' => 2,
                    'description' => __('Bucket name to upload to, please make sure that the bucket exists. We will not create the bucket for you'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string'
                ],
                'S3_region' => [
                    'level' => 2,
                    'description' => __('Region in which your S3 bucket resides'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string'
                ],
                'S3_aws_access_key' => [
                    'level' => 2,
                    'description' => __('AWS key to use when uploading samples (WARNING: It\' highly recommended that you use EC2 IAM roles if at all possible)'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string'
                ],
                'S3_aws_secret_key' => [
                    'level' => 2,
                    'description' => __('AWS secret key to use when uploading samples'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string'
                ],
                'Sightings_policy' => [
                    'level' => 1,
                    'description' => __('This setting defines who will have access to seeing the reported sightings. The default setting is the event owner organisation alone (in addition to everyone seeing their own contribution) with the other options being Sighting reporters (meaning the event owner and any organisation that provided sighting data about the event) and Everyone (meaning anyone that has access to seeing the event / attribute).'),
                    'value' => 0,
                    'type' => 'numeric',
                    'options' => [
                        0 => __('Event Owner Organisation'),
                        1 => __('Sighting reporters'),
                        2 => __('Everyone'),
                        3 => __('Event Owner + host org sightings'),
                    ],
                ],
                'Sightings_anonymise' => [
                    'level' => 1,
                    'description' => __('Enabling the anonymisation of sightings will simply aggregate all sightings instead of showing the organisations that have reported a sighting. Users will be able to tell the number of sightings their organisation has submitted and the number of sightings for other organisations'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                ],
                'Sightings_anonymise_as' => [
                    'level' => 1,
                    'description' => __('When pushing sightings to another server, report all sightings from this instance as this organisation. This effectively hides all sightings from this instance behind a single organisation to the outside world. Sightings pulled from this instance follow the Sightings_policy above.'),
                    'value' => '0',
                    'test' => 'testLocalOrg',
                    'type' => 'numeric',
                    'optionsSource' => function () {
                        return $this->loadLocalOrganisations();
                    },
                ],
                'Sightings_range' => [
                    'level' => 1,
                    'description' => __('Set the range in which sightings will be taken into account when generating graphs. For example a sighting with a sighted_date of 7 years ago might not be relevant anymore. Setting given in number of days, default is 365 days'),
                    'value' => 365,
                    'test' => 'testForNumeric',
                    'type' => 'numeric'
                ],
                'Sightings_sighting_db_enable' => [
                    'level' => 1,
                    'description' => __('Enable SightingDB integration.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'Sightings_enable_realtime_publish' => [
                    'level' => 1,
                    'description' => __('By default, sightings will not be immediately pushed to connected instances, as this can have a heavy impact on the performance of sighting attributes. Enable realtime publishing to trigger the publishing of sightings immediately as they are added.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'CustomAuth_enable' => [
                    'level' => 2,
                    'description' => __('Enable this functionality if you would like to handle the authentication via an external tool and authenticate with MISP using a custom header.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true,
                    'beforeHook' => 'customAuthBeforeHook'
                ],
                'CustomAuth_header' => [
                    'level' => 2,
                    'description' => __('Set the header that MISP should look for here. If left empty it will default to the Authorization header.'),
                    'value' => 'AUTHORIZATION',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                    'null' => true
                ],
                'CustomAuth_use_header_namespace' => [
                    'level' => 2,
                    'description' => __('Use a header namespace for the auth header - default setting is enabled'),
                    'value' => true,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'CustomAuth_header_namespace' => [
                    'level' => 2,
                    'description' => __('The default header namespace for the auth header - default setting is HTTP_'),
                    'value' => 'HTTP_',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                    'null' => true
                ],
                'CustomAuth_required' => [
                    'level' => 2,
                    'description' => __('If this setting is enabled then the only way to authenticate will be using the custom header. Alternatively, you can run in mixed mode that will log users in via the header if found, otherwise users will be redirected to the normal login page.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'CustomAuth_only_allow_source' => [
                    'level' => 2,
                    'description' => __('If you are using an external tool to authenticate with MISP and would like to only allow the tool\'s url as a valid point of entry then set this field. '),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                    'null' => true
                ],
                'CustomAuth_name' => [
                    'level' => 2,
                    'description' => __('The name of the authentication method, this is cosmetic only and will be shown on the user creation page and logs.'),
                    'value' => 'External authentication',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                    'null' => true
                ],
                'CustomAuth_disable_logout' => [
                    'level' => 2,
                    'description' => __('Disable the logout button for users authenticate with the external auth mechanism.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'Enrichment_services_enable' => [
                    'level' => 0,
                    'description' => __('Enable/disable the enrichment services'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'Enrichment_timeout' => [
                    'level' => 1,
                    'description' => __('Set a timeout for the enrichment services'),
                    'value' => 10,
                    'test' => 'testForEmpty',
                    'type' => 'numeric'
                ],
                'Import_services_enable' => [
                    'level' => 0,
                    'description' => __('Enable/disable the import services'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'Import_timeout' => [
                    'level' => 1,
                    'description' => __('Set a timeout for the import services'),
                    'value' => 10,
                    'test' => 'testForEmpty',
                    'type' => 'numeric'
                ],
                'Import_services_url' => [
                    'level' => 1,
                    'description' => __('The url used to access the import services. By default, it is accessible at http://127.0.0.1:6666'),
                    'value' => 'http://127.0.0.1',
                    'test' => 'testForEmpty',
                    'type' => 'string'
                ],
                'Import_services_port' => [
                    'level' => 1,
                    'description' => __('The port used to access the import services. By default, it is accessible at 127.0.0.1:6666'),
                    'value' => '6666',
                    'test' => 'testForPortNumber',
                    'type' => 'numeric'
                ],
                'Export_services_url' => [
                    'level' => 1,
                    'description' => __('The url used to access the export services. By default, it is accessible at http://127.0.0.1:6666'),
                    'value' => 'http://127.0.0.1',
                    'test' => 'testForEmpty',
                    'type' => 'string'
                ],
                'Export_services_port' => [
                    'level' => 1,
                    'description' => __('The port used to access the export services. By default, it is accessible at 127.0.0.1:6666'),
                    'value' => '6666',
                    'test' => 'testForPortNumber',
                    'type' => 'numeric'
                ],
                'Export_services_enable' => [
                    'level' => 0,
                    'description' => __('Enable/disable the export services'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'Export_timeout' => [
                    'level' => 1,
                    'description' => __('Set a timeout for the export services'),
                    'value' => 10,
                    'test' => 'testForEmpty',
                    'type' => 'numeric'
                ],
                'Action_services_url' => [
                    'level' => 1,
                    'description' => __('The url used to access the action services. By default, it is accessible at http://127.0.0.1:6666'),
                    'value' => 'http://127.0.0.1',
                    'test' => 'testForEmpty',
                    'type' => 'string'
                ],
                'Action_services_port' => [
                    'level' => 1,
                    'description' => __('The port used to access the action services. By default, it is accessible at 127.0.0.1:6666'),
                    'value' => '6666',
                    'test' => 'testForPortNumber',
                    'type' => 'numeric'
                ],
                'Action_services_enable' => [
                    'level' => 0,
                    'description' => __('Enable/disable the action services'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'Action_timeout' => [
                    'level' => 1,
                    'description' => __('Set a timeout for the action services'),
                    'value' => 10,
                    'test' => 'testForEmpty',
                    'type' => 'numeric'
                ],
                'Enrichment_hover_enable' => [
                    'level' => 0,
                    'description' => __('Enable/disable the hover over information retrieved from the enrichment modules'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'Enrichment_hover_popover_only' => [
                    'level' => 0,
                    'description' => __('When enabled, users have to click on the magnifier icon to show the enrichment'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'Enrichment_hover_timeout' => [
                    'level' => 1,
                    'description' => __('Set a timeout for the hover services'),
                    'value' => 5,
                    'test' => 'testForEmpty',
                    'type' => 'numeric'
                ],
                'Enrichment_services_url' => [
                    'level' => 1,
                    'description' => __('The url used to access the enrichment services. By default, it is accessible at http://127.0.0.1:6666'),
                    'value' => 'http://127.0.0.1',
                    'test' => 'testForEmpty',
                    'type' => 'string'
                ],
                'Enrichment_services_port' => [
                    'level' => 1,
                    'description' => __('The port used to access the enrichment services. By default, it is accessible at 127.0.0.1:6666'),
                    'value' => 6666,
                    'test' => 'testForPortNumber',
                    'type' => 'numeric'
                ],
                'Workflow_enable' => [
                    'level' => 1,
                    'description' => __('Enable/disable workflow feature. [experimental]'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'Workflow_debug_url' => [
                    'level' => 1,
                    'description' => __('Set the debug URL where info about workflow execution will be POSTed'),
                    'value' => 'http://127.0.0.1:27051',
                    'test' => 'testForEmpty',
                    'type' => 'string'
                ],
                'Cortex_services_url' => [
                    'level' => 1,
                    'description' => __('The url used to access Cortex. By default, it is accessible at http://cortex-url'),
                    'value' => 'http://127.0.0.1',
                    'test' => 'testForEmpty',
                    'type' => 'string'
                ],
                'Cortex_services_port' => [
                    'level' => 1,
                    'description' => __('The port used to access Cortex. By default, this is port 9000'),
                    'value' => 9000,
                    'test' => 'testForPortNumber',
                    'type' => 'numeric'
                ],
                'Cortex_services_enable' => [
                    'level' => 0,
                    'description' => __('Enable/disable the Cortex services'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'Cortex_authkey' => [
                    'level' => 1,
                    'description' => __('Set an authentication key to be passed to Cortex'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                    'null' => true
                ],
                'Cortex_timeout' => [
                    'level' => 1,
                    'description' => __('Set a timeout for the Cortex services'),
                    'value' => 120,
                    'test' => 'testForEmpty',
                    'type' => 'numeric'
                ],
                'Cortex_ssl_verify_peer' => [
                    'level' => 1,
                    'description' => __('Set to false to disable SSL verification. This is not recommended.'),
                    'value' => true,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'Cortex_ssl_verify_host' => [
                    'level' => 1,
                    'description' => __('Set to false if you wish to ignore hostname match errors when validating certificates.'),
                    'value' => true,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'Cortex_ssl_allow_self_signed' => [
                    'level' => 1,
                    'description' => __('Set to true to enable self-signed certificates to be accepted. This requires Cortex_ssl_verify_peer to be enabled.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'Cortex_ssl_cafile' => [
                    'level' => 1,
                    'description' => __('Set to the absolute path of the Certificate Authority file that you wish to use for verifying SSL certificates.'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                    'null' => true
                ],
                'CustomAuth_custom_password_reset' => [
                    'level' => 2,
                    'description' => __('Provide your custom authentication users with an external URL to the authentication system to reset their passwords.'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                    'null' => true
                ],
                'CustomAuth_custom_logout' => [
                    'level' => 2,
                    'description' => __('Provide a custom logout URL for your users that will log them out using the authentication system you use.'),
                    'value' => '',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                    'null' => true
                ],
                'CyCat_enable' => [
                    'level' => 1,
                    'description' => __('Enable lookups for additional relations via CyCat.'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean',
                    'null' => true
                ],
                'CyCat_url' => [
                    'level' => 2,
                    'description' => __('URL to use for CyCat lookups, if enabled.'),
                    'value' => 'https://api.cycat.org',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                    'null' => true
                ]
            ],
            'SimpleBackgroundJobs' => [
                'branch' => 1,
                'enabled' => [
                    'level' => self::SETTING_CRITICAL,
                    'description' => __('Enables or disables background jobs with Supervisor backend. <span class="red bold">Please read %s before setting this to `true`.</span>', '<a href="https://github.com/MISP/MISP/blob/2.4/docs/background-jobs-migration-guide.md" target="_blank">' . __('this guide') . '</a>'),
                    'value' => false,
                    'test' => 'testBool',
                    'type' => 'boolean'
                ],
                'redis_host' => [
                    'level' => self::SETTING_CRITICAL,
                    'description' => __('The host running the redis server to be used for background jobs.'),
                    'value' => '127.0.0.1',
                    'test' => 'testForEmpty',
                    'type' => 'string'
                ],
                'redis_port' => [
                    'level' => self::SETTING_CRITICAL,
                    'description' => __('The port used by the redis server to be used for background jobs.'),
                    'value' => 6379,
                    'test' => 'testForNumeric',
                    'type' => 'numeric'
                ],
                'redis_database' => [
                    'level' => self::SETTING_CRITICAL,
                    'description' => __('The database on the redis server to be used for background jobs. If you run more than one MISP instance, please make sure to use a different database or redis_namespace on each instance.'),
                    'value' => 1,
                    'test' => 'testForNumeric',
                    'type' => 'numeric'
                ],
                'redis_password' => [
                    'level' => self::SETTING_CRITICAL,
                    'description' => __('The password on the redis server (if any) to be used for background jobs.'),
                    'value' => '',
                    'test' => null,
                    'type' => 'string',
                    'redacted' => true
                ],
                'redis_namespace' => [
                    'level' => self::SETTING_CRITICAL,
                    'description' => __('The namespace to be used for the background jobs related keys.'),
                    'value' => 'background_jobs',
                    'test' => null,
                    'type' => 'string'
                ],
                'redis_serializer' => [
                    'level' => self::SETTING_OPTIONAL,
                    'description' => __('Redis serializer method. WARNING: Changing this setting in production will break your jobs.'),
                    'value' => 'JSON',
                    'test' => null,
                    'type' => 'string',
                    'null' => true,
                    'options' => [
                        'JSON' => 'JSON',
                        'igbinary' => 'igbinary',
                    ],
                    'afterHook' => function () {
                        BackgroundJobsTool::getInstance()->restartWorkers();
                        return true;
                    },
                ],
                'max_job_history_ttl' => [
                    'level' => self::SETTING_CRITICAL,
                    'description' => __('The time in seconds the job statuses history will be kept.'),
                    'value' => 86400,
                    'test' => 'testForNumeric',
                    'type' => 'numeric'
                ],
                'supervisor_host' => [
                    'level' => self::SETTING_CRITICAL,
                    'description' => __('The host where the Supervisor XML-RPC API is running.'),
                    'value' => 'localhost',
                    'test' => 'testForEmpty',
                    'type' => 'string'
                ],
                'supervisor_port' => [
                    'level' => self::SETTING_CRITICAL,
                    'description' => __('The port where the Supervisor XML-RPC API is running.'),
                    'value' => 9001,
                    'test' => 'testForNumeric',
                    'type' => 'numeric'
                ],
                'supervisor_user' => [
                    'level' => self::SETTING_CRITICAL,
                    'description' => __('The user of the Supervisor XML-RPC API.'),
                    'value' => 'supervisor',
                    'test' => null,
                    'type' => 'string'
                ],
                'supervisor_password' => [
                    'level' => self::SETTING_CRITICAL,
                    'description' => __('The password of the Supervisor XML-RPC API.'),
                    'value' => '',
                    'test' => null,
                    'type' => 'string',
                    'redacted' => true
                ],
            ],
            'debug' => [
                'level' => 0,
                'description' => __('The debug level of the instance, always use 0 for production instances.'),
                'value' => '',
                'test' => 'testDebug',
                'type' => 'numeric',
                'options' => [0 => 'Debug off', 1 => 'Debug on', 2 => 'Debug + SQL dump'],
            ],
            'site_admin_debug' => [
                'level' => 0,
                'description' => __('The debug level of the instance for site admins. This feature allows site admins to run debug mode on a live instance without exposing it to other users. The most verbose option of debug and site_admin_debug is used for site admins.'),
                'value' => '',
                'test' => 'testDebugAdmin',
                'type' => 'boolean',
                'null' => true
            ],
            'LinOTPAuth' => [
                'branch' => 1,
                'enabled' => [
                    'level' => 2,
                    'description' => __('Enable / Disable LinOTP'),
                    'value' => true,
                    'type' => 'boolean',
                ],
                'baseUrl' => [
                    'level' => 2,
                    'description' => __('The default LinOTP URL.'),
                    'value' => 'https://<your-linotp-baseUrl>',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'realm' => [
                    'level' => 2,
                    'description' => __('The LinOTP realm to authenticate against.'),
                    'value' => 'lino',
                    'test' => 'testForEmpty',
                    'type' => 'string',
                ],
                'verifyssl' => [
                    'level' => 2,
                    'description' => __('Set to false to skip SSL/TLS verify'),
                    'value' => true,
                    'test' => 'testBoolTrue',
                    'type' => 'boolean',
                ],
                'mixedauth' => [
                    'level' => 2,
                    'description' => __('Set to true to enforce OTP usage'),
                    'value' => false,
                    'test' => 'testBoolFalse',
                    'type' => 'boolean',
                ],
            ],
        ];
    }


    private function generateCommandLineFunctions()
    {
        return [
            'console_admin_tasks' => [
                'data' => [
                    'Get setting' => 'MISP/app/Console/cake Admin getSetting [setting|all]',
                    'Set setting' => 'MISP/app/Console/cake Admin setSetting [setting] [value]',
                    'Get authkey' => 'MISP/app/Console/cake Admin getAuthkey [user_email]',
                    'Change authkey' => 'MISP/app/Console/cake Admin change_authkey [user_email] [authkey]',
                    'Set baseurl' => 'MISP/app/Console/cake Admin setSetting MISP.baseurl [baseurl]',
                    'Change password' => 'MISP/app/Console/cake User change_pw [email] [new_password] [--no_password_change]',
                    'Clear Bruteforce entries' => 'MISP/app/Console/cake Admin clearBruteforce [user_email]',
                    'Clean caches' => 'MISP/app/Console/cake Admin cleanCaches',
                    'Set database version' => 'MISP/app/Console/cake Admin setDatabaseVersion [version]',
                    'Run database update' => 'MISP/app/Console/cake Admin updateDatabase',
                    'Run updates' => 'MISP/app/Console/cake Admin runUpdates',
                    'Update all JSON structures' => 'MISP/app/Console/cake Admin updateJSON',
                    'Update Galaxy definitions' => 'MISP/app/Console/cake Admin updateGalaxies',
                    'Update taxonomy definitions' => 'MISP/app/Console/cake Admin updateTaxonomies',
                    'Update object templates' => 'MISP/app/Console/cake Admin updateObjectTemplates [user_id]',
                    'Update Warninglists' => 'MISP/app/Console/cake Admin updateWarningLists',
                    'Update Noticelists' => 'MISP/app/Console/cake Admin updateNoticeLists',
                    'Set default role' => 'MISP/app/Console/cake Admin setDefaultRole [role_id]',
                    'Get IPs for user ID' => 'MISP/app/Console/cake Admin UserIP [user_id]',
                    'Get user ID for user IP' => 'MISP/app/Console/cake Admin IPUser [ip]',
                    'Generate correlation' => 'MISP/app/Console/cake Admin jobGenerateCorrelation [job_id]',
                    'Truncate correlation table' => 'MISP/app/Console/cake Admin truncateTable [user_id] [correlation_engine_name] [job_id]',
                    'Purge correlation' => 'MISP/app/Console/cake Admin jobPurgeCorrelation [job_id]',
                    'Generate shadow attribute correlation' => 'MISP/app/Console/cake Admin jobGenerateShadowAttributeCorrelation [job_id]',
                    'Update MISP' => 'MISP/app/Console/cake Admin updateMISP',
                    'Update after pull' => 'MISP/app/Console/cake Admin updateAfterPull [submodule_name] [job_id] [user_id]',
                    'Job upgrade' => 'MISP/app/Console/cake Admin jobUpgrade24 [job_id] [user_id]',
                    'Prune update logs' => 'MISP/app/Console/cake Admin prune_update_logs [job_id] [user_id]',
                    'Recover since last successful update' => 'MISP/app/Console/cake Admin recoverSinceLastSuccessfulUpdate',
                    'Reset sync authkeys' => 'MISP/app/Console/cake Admin resetSyncAuthkeys [user_id]',
                    'Purge feed events' => 'MISP/app/Console/cake Admin purgeFeedEvents [user_id] [feed_id]',
                    'Dump current database schema' => 'MISP/app/Console/cake Admin dumpCurrentDatabaseSchema',
                    'Scan attachment' => 'MISP/app/Console/cake Admin scanAttachment [input] [attribute_id] [job_id]',
                    'Clean excluded correlations' => 'MISP/app/Console/cake Admin cleanExcludedCorrelations [job_id]',
                ],
                'description' => __('Certain administrative tasks are exposed to the API, these help with maintaining and configuring MISP in an automated way / via external tools.'),
                'header' => __('Administering MISP via the CLI')
            ],
            'console_automation_tasks' => [
                'data' => [
                    'PullAll' => 'MISP/app/Console/cake Server pullAll [user_id] [full|update]',
                    'Pull' => 'MISP/app/Console/cake Server pull [user_id] [server_id] [full|update]',
                    'PushAll' => 'MISP/app/Console/cake Server pushAll [user_id]',
                    'Push' => 'MISP/app/Console/cake Server push [user_id] [server_id]',
                    'Cache server' => 'MISP/app/Console/cake server cacheServer [user_id] [server_id]',
                    'Cache all servers' => 'MISP/app/Console/cake server cacheServerAll [user_id]',
                    'List all feeds' => 'MISP/app/Console/cake Server listFeeds [json|table]',
                    'View feed' => 'MISP/app/Console/cake Server viewFeed [feed_id] [json|table]',
                    'Toggle feed fetching' => 'MISP/app/Console/cake Server toggleFeed [feed_id]',
                    'Toggle feed caching' => 'MISP/app/Console/cake Server toggleFeedCaching [feed_id]',
                    'Load default feed configurations' => 'MISP/app/Console/cake Server loadDefaultFeeds [feed_id]',
                    'Cache feeds for quick lookups' => 'MISP/app/Console/cake Server cacheFeed [user_id] [feed_id|all|csv|text|misp]',
                    'Fetch feeds as local data' => 'MISP/app/Console/cake Server fetchFeed [user_id] [feed_id|all|csv|text|misp]',
                    'Run enrichment' => 'MISP/app/Console/cake Event enrichment [user_id] [event_id] [json_encoded_module_list]',
                    'Test' => 'MISP/app/Console/cake Server test [server_id]',
                    'List' => 'MISP/app/Console/cake Server list',
                    'Enqueue pull' => 'MISP/app/Console/cake Server enqueuePull [timestamp] [user_id] [task_id]',
                    'Enqueue push' => 'MISP/app/Console/cake Server enqueuePush [timestamp] [task_id] [user_id]',
                    'Enqueue feed fetch' => 'MISP/app/Console/cake Server enqueueFeedFetch [timestamp] [user_id] [task_id]',
                    'Enqueue feed cache' => 'MISP/app/Console/cake Server enqueueFeedCache [timestamp] [user_id] [task_id]',
                    'Update sharing groups based on blueprints' => 'MISP/app/Console/cake Server executeSGBlueprint [blueprint_id|all|attached|detached]'
                ],
                'description' => __('If you would like to automate tasks such as caching feeds or pulling from server instances, you can do it using the following command line tools. Simply execute the given commands via the command line / create cron jobs easily out of them.'),
                'header' => __('Automating certain console tasks')
            ],
            'event_management_tasks' => [
                'data' => [
                    'Publish event' => 'MISP/app/Console/cake Event publish [event_id] [pass_along] [job_id] [user_id]',
                    'Publish sightings' => 'MISP/app/Console/cake Event publish_sightings [event_id] [pass_along] [job_id] [user_id]',
                    'Publish Galaxy clusters' => 'MISP/app/Console/cake Event publish_galaxy_clusters [cluster_id] [job_id] [user_id] [pass_along]',
                    'Cache event' => 'MISP/app/Console/cake Event cache [user_id] [event_id] [export_type]',
                    'Cache bro' => 'MISP/app/Console/cake Event cachebro [user_id] [event_id]',
                    'Recover event' => 'MISP/app/Console/cake Event recoverEvent [job_id] [event_id]',
                    'Alert email' => 'MISP/app/Console/cake Event alertemail [user_id] [job_id] [event_id] [old_publish]',
                    'Contact email' => 'MISP/app/Console/cake Event contactemail [event_id] [message] [all] [user_id] [process_id]',
                    'Posts email' => 'MISP/app/Console/cake Event postsemail [user_id] [post_id] [event_id] [title] [message] [process_id]',
                    'Enqueue caching' => 'MISP/app/Console/cake Event enqueueCaching [timestamp]',
                    'Do publish' => 'MISP/app/Console/cake Event doPublish [event_id]',
                    'Run enrichment' => 'MISP/app/Console/cake Event enrichment [user_id] [event_id] [json_encoded_module_list]',
                    'Process free text' => 'MISP/app/Console/cake Event processfreetext [input]',
                    'Process module result' => 'MISP/app/Console/cake Event processmoduleresult [input]',
                ],
                'description' => __('The events can be managed via the CLI in addition to the UI / API management tools'),
                'header' => __('Managing the events')
            ],
            'worker_management_tasks' => [
                'data' => [
                    'Get list of workers' => 'MISP/app/Console/cake Admin getWorkers [all|dead]',
                    'Start a worker' => 'MISP/app/Console/cake Admin startWorker [queue_name]',
                    'Restart a worker' => 'MISP/app/Console/cake Admin restartWorker [worker_pid]',
                    'Restart all workers' => 'MISP/app/Console/cake Admin restartWorkers',
                    'Kill a worker' => 'MISP/app/Console/cake Admin killWorker [worker_pid]',
                ],
                'description' => __('The background workers can be managed via the CLI in addition to the UI / API management tools'),
                'header' => __('Managing the background workers')
            ]
        ];
    }

    private function loadLocalOrganisations($strict = false)
    {
        static $localOrgs;

        if ($localOrgs === null) {
            $localOrgs = $this->Organisation->find(
                'list',
                [
                    'conditions' => ['local' => 1],
                    'recursive' => -1,
                    'fields' => ['Organisation.id', 'Organisation.name']
                ]
            );
        }

        if (!$strict) {
            return array_replace([0 => __('No organisation selected.')], $localOrgs);
        }

        return $localOrgs;
    }

    public function loadAvailableLanguages()
    {
        $dirs = glob(APP . 'Locale/*', GLOB_ONLYDIR);
        $languages = ['eng' => 'eng'];
        foreach ($dirs as $dir) {
            $dir = str_replace(APP . 'Locale' . DS, '', $dir);
            $languages[$dir] = $dir;
        }
        return $languages;
    }

    public function loadTagCollections()
    {
        $this->TagCollection = $this->fetchTable('TagCollections');
        $user = ['Role' => ['perm_site_admin' => 1]];
        $tagCollections = $this->TagCollection->fetchTagCollection($user);
        $options = [0 => 'None'];
        foreach ($tagCollections as $tagCollection) {
            $options[intval($tagCollection['TagCollection']['id'])] = $tagCollection['TagCollection']['name'];
        }
        return $options;
    }

}
