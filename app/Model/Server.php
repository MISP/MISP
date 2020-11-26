<?php
App::uses('AppModel', 'Model');
App::uses('GpgTool', 'Tools');

class Server extends AppModel
{
    const SETTING_CRITICAL = 0,
        SETTING_RECOMMENDED = 1,
        SETTING_OPTIONAL = 2;

    public $name = 'Server';

    public $actsAs = array('SysLogLogable.SysLogLogable' => array(
            'userModel' => 'User',
            'userKey' => 'user_id',
            'change' => 'full'
        ),
        'Trim',
        'Containable'
    );

    public $belongsTo = array(
        'Organisation' => array(
            'className' => 'Organisation',
            'foreignKey' => 'org_id',
        ),
        'RemoteOrg' => array(
            'className' => 'Organisation',
            'foreignKey' => 'remote_org_id',
        )
    );

    public $hasMany = array(
        'SharingGroupServer' => array(
            'className' => 'SharingGroupServer',
            'foreignKey' => 'server_id',
            'dependent'=> true,
        ),
        'User' => array(
            'className' => 'User',
            'foreignKey' => 'server_id',
        ),
    );

    public $displayField = 'url';

    public $validate = array(
        'url' => array(
            'url' => array(
                'rule' => array('url'),
                'message' => 'Please enter a valid base-url.'
            )
        ),
        'authkey' => array(
            'rule' => array('validateAuthkey')
        ),
        'name' => array(
            'rule' => array('notBlank'),
            'allowEmpty' => false,
            'required' => true
        ),
        'org_id' => array(
            'numeric' => array(
                'rule' => array('valueIsID'),
                'allowEmpty' => false,
                'required' => true,
            ),
        ),
        'push' => array(
            'boolean' => array(
                'rule' => array('boolean'),
                //'message' => 'Your custom message here',
                'allowEmpty' => true,
                'required' => false,
                //'last' => false, // Stop validation after this rule
                //'on' => 'create', // Limit validation to 'create' or 'update' operations
            ),
        ),
        'pull' => array(
            'boolean' => array(
                'rule' => array('boolean'),
                //'message' => 'Your custom message here',
                'allowEmpty' => true,
                //'required' => false,
                //'last' => false, // Stop validation after this rule
                //'on' => 'create', // Limit validation to 'create' or 'update' operations
            ),
        ),
        'push_sightings' => array(
            'boolean' => array(
                'rule' => array('boolean'),
                //'message' => 'Your custom message here',
                'allowEmpty' => true,
                'required' => false,
                //'last' => false, // Stop validation after this rule
                //'on' => 'create', // Limit validation to 'create' or 'update' operations
            ),
        ),
        'lastpushedid' => array(
            'numeric' => array(
                'rule' => array('numeric'),
                //'message' => 'Your custom message here',
                'allowEmpty' => true,
                'required' => false,
                //'last' => false, // Stop validation after this rule
                //'on' => 'create', // Limit validation to 'create' or 'update' operations
            ),
        ),
        'lastpulledid' => array(
            'numeric' => array(
                'rule' => array('numeric'),
                //'message' => 'Your custom message here',
                'allowEmpty' => true,
                'required' => false,
                //'last' => false, // Stop validation after this rule
                //'on' => 'create', // Limit validation to 'create' or 'update' operations
            ),
        ),
    );

    public $syncTestErrorCodes = array();

    public function __construct($id = false, $table = null, $ds = null)
    {
        parent::__construct($id, $table, $ds);

        $this->syncTestErrorCodes = array(
            2 => __('Server unreachable'),
            3 => __('Unexpected error'),
            4 => __('Authentication failed'),
            5 => __('Password change required'),
            6 => __('Terms not accepted')
        );

        $this->command_line_functions = array(
            'console_admin_tasks' => array(
                'data' => array(
                    'Get setting' => 'MISP/app/Console/cake Admin getSetting [setting]',
                    'Set setting' => 'MISP/app/Console/cake Admin setSetting [setting] [value]',
                    'Get authkey' => 'MISP/app/Console/cake Admin getAuthkey [email]',
                    'Set baseurl' => 'MISP/app/Console/cake Baseurl [baseurl]',
                    'Change password' => 'MISP/app/Console/cake Password [email] [new_password] [--override_password_change]',
                    'Clear Bruteforce Entries' => 'MISP/app/Console/cake Admin clearBruteforce [user_email]',
                    'Run database update' => 'MISP/app/Console/cake Admin updateDatabase',
                    'Update all JSON structures' => 'MISP/app/Console/cake Admin updateJSON',
                    'Update Galaxy definitions' => 'MISP/app/Console/cake Admin updateGalaxies',
                    'Update taxonomy definitions' => 'MISP/app/Console/cake Admin updateTaxonomies',
                    'Update object templates' => 'MISP/app/Console/cake Admin updateObjectTemplates',
                    'Update Warninglists' => 'MISP/app/Console/cake Admin updateWarningLists',
                    'Update Noticelists' => 'MISP/app/Console/cake Admin updateNoticeLists',
                    'Set default role' => 'MISP/app/Console/cake Admin setDefaultRole [role_id]',
                    'Get IPs for user ID' => 'MISP/app/Console/cake Admin UserIP [user_id]',
                    'Get user ID for user IP' => 'MISP/app/Console/cake Admin IPUser [ip]',
                ),
                'description' => __('Certain administrative tasks are exposed to the API, these help with maintaining and configuring MISP in an automated way / via external tools.'),
                'header' => __('Administering MISP via the CLI')
            ),
            'console_automation_tasks' => array(
                'data' => array(
                    'PullAll' => 'MISP/app/Console/cake Server pullAll [user_id] [full|update]',
                    'Pull' => 'MISP/app/Console/cake Server pull [user_id] [server_id] [full|update]',
                    'Push' => 'MISP/app/Console/cake Server push [user_id] [server_id]',
                    'Cache feeds for quick lookups' => 'MISP/app/Console/cake Server cacheFeed [user_id] [feed_id|all|csv|text|misp]',
                    'Fetch feeds as local data' => 'MISP/app/Console/cake Server fetchFeed [user_id] [feed_id|all|csv|text|misp]',
                    'Run enrichment' => 'MISP/app/Console/cake Event enrichment [user_id] [event_id] [json_encoded_module_list]',
                    'Test' => 'MISP/app/Console/cake Server test [server_id]',
                    'List' => 'MISP/app/Console/cake Server list'
                ),
                'description' => __('If you would like to automate tasks such as caching feeds or pulling from server instances, you can do it using the following command line tools. Simply execute the given commands via the command line / create cron jobs easily out of them.'),
                'header' => __('Automating certain console tasks')
            ),
            'worker_management_tasks' => array(
                'data' => array(
                    'Get list of workers' => 'MISP/app/Console/cake Admin getWorkers [all|dead]',
                    'Start a worker' => 'MISP/app/Console/cake Admin startWorker [queue_name]',
                    'Restart a worker' => 'MISP/app/Console/cake Admin restartWorker [worker_pid]',
                    'Kill a worker' => 'MISP/app/Console/cake Admin killWorker [worker_pid]',
                ),
                'description' => __('The background workers can be managed via the CLI in addition to the UI / API management tools'),
                'header' => __('Managing the background workers')
            )
        );

        $this->serverSettings = array(
                'MISP' => array(
                        'branch' => 1,
                        'baseurl' => array(
                                'level' => 0,
                                'description' => __('The base url of the application (in the format https://www.mymispinstance.com or https://myserver.com/misp). Several features depend on this setting being correctly set to function.'),
                                'value' => '',
                                'errorMessage' => __('The currenty set baseurl does not match the URL through which you have accessed the page. Disregard this if you are accessing the page via an alternate URL (for example via IP address).'),
                                'test' => 'testBaseURL',
                                'type' => 'string',
                        ),
                        'external_baseurl' => array(
                                'level' => 0,
                                'description' => __('The base url of the application (in the format https://www.mymispinstance.com) as visible externally/by other MISPs. MISP will encode this URL in sharing groups when including itself. If this value is not set, the baseurl is used as a fallback.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testURL',
                                'type' => 'string',
                        ),
                        'live' => array(
                                'level' => 0,
                                'description' => __('Unless set to true, the instance will only be accessible by site admins.'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testLive',
                                'type' => 'boolean',
                        ),
                        'language' => array(
                                'level' => 0,
                                'description' => __('Select the language MISP should use. The default is english.'),
                                'value' => 'eng',
                                'errorMessage' => '',
                                'test' => 'testLanguage',
                                'type' => 'string',
                                'optionsSource' => 'AvailableLanguages',
                                'afterHook' => 'cleanCacheFiles'
                        ),
                        'default_attribute_memory_coefficient' => array(
                                'level' => 1,
                                'description' => __('This values controls the internal fetcher\'s memory envelope when it comes to attributes. The number provided is the amount of attributes that can be loaded for each MB of PHP memory available in one shot. Consider lowering this number if your instance has a lot of attribute tags / attribute galaxies attached.'),
                                'value' => 80,
                                'errorMessage' => '',
                                'test' => 'testForNumeric',
                                'type' => 'numeric',
                                'null' => true
                        ),
                        'default_event_memory_divisor' => array(
                                'level' => 1,
                                'description' => __('This value controls the divisor for attribute weighting when it comes to loading full events. Meaning that it will load coefficient / divisor number of attributes per MB of memory available. Consider raising this number if you have a lot of correlations or highly contextualised events (large number of event level galaxies/tags).'),
                                'value' => 3,
                                'errorMessage' => '',
                                'test' => 'testForNumeric',
                                'type' => 'numeric',
                                'null' => true
                        ),
                        'enable_advanced_correlations' => array(
                                'level' => 0,
                                'description' => __('Enable some performance heavy correlations (currently CIDR correlation)'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                                'null' => true
                        ),
                        'server_settings_skip_backup_rotate' => array(
                            'level' => 1,
                            'description' => __('Enable this setting to directly save the config.php file without first creating a temporary file and moving it to avoid concurency issues. Generally not recommended, but useful when for example other tools modify/maintain the config.php file.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean',
                            'null' => true
                        ),
                        'python_bin' => array(
                                'level' => 1,
                                'description' => __('It is highly recommended to install all the python dependencies in a virtualenv. The recommended location is: %s/venv', ROOT),
                                'value' => false,
                                'errorMessage' => '',
                                'null' => false,
                                'test' => 'testForBinExec',
                                'beforeHook' => 'beforeHookBinExec',
                                'type' => 'string',
                                'cli_only' => 1
                        ),
                        'ca_path' => array(
                                'level' => 1,
                                'description' => __('MISP will default to the bundled mozilla certificate bundle shipped with the framework, which is rather stale. If you wish to use an alternate bundle, just set this setting using the path to the bundle to use. This setting can only be modified via the CLI.'),
                                'value' => APP . 'Lib/cakephp/lib/Cake/Config/cacert.pem',
                                'errorMessage' => '',
                                'null' => true,
                                'test' => 'testForCABundle',
                                'type' => 'string',
                                'cli_only' => 1
                        ),
                        'disable_auto_logout' => array(
                                'level' => 1,
                                'description' => __('In some cases, a heavily used MISP instance can generate unwanted blackhole errors due to a high number of requests hitting the server. Disable the auto logout functionality to ease the burden on the system.'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                                'null' => true
                        ),
                        'ssdeep_correlation_threshold' => array(
                            'level' => 1,
                            'description' => __('Set the ssdeep score at which to consider two ssdeep hashes as correlating [1-100]'),
                            'value' => 40,
                            'errorMessage' => '',
                            'test' => 'testForEmpty',
                            'type' => 'numeric'
                        ),
                        'max_correlations_per_event' => array(
                                'level' => 1,
                                'description' => __('Sets the maximum number of correlations that can be fetched with a single event. For extreme edge cases this can prevent memory issues. The default value is 5k.'),
                                'value' => 5000,
                                'errorMessage' => '',
                                'test' => 'testForNumeric',
                                'type' => 'numeric',
                                'null' => true
                        ),
                        'maintenance_message' => array(
                                'level' => 2,
                                'description' => __('The message that users will see if the instance is not live.'),
                                'value' => 'Great things are happening! MISP is undergoing maintenance, but will return shortly. You can contact the administration at $email.',
                                'errorMessage' => __('If this is not set the default value will be used.'),
                                'test' => 'testForEmpty',
                                'type' => 'string',
                        ),
                        'name' => array(
                                'level' => 3,
                                'description' => __('This setting is deprecated and can be safely removed.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                        ),
                        'version' => array(
                                'level' => 3,
                                'description' => __('This setting is deprecated and can be safely removed.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                        ),
                        'disable_cached_exports' => array(
                                'level' => 1,
                                'description' => __('Cached exports can take up a considerable amount of space and can be disabled instance wide using this setting. Disabling the cached exports is not recommended as it\'s a valuable feature, however, if your server is having free space issues it might make sense to take this step.'),
                                'value' => false,
                                'null' => true,
                                'errorMessage' => '',
                                'test' => 'testDisableCache',
                                'type' => 'boolean',
                                'afterHook' => 'disableCacheAfterHook',
                        ),
                        'disable_threat_level' => array(
                                'level' => 1,
                                'description' => __('Disable displaying / modifications to the threat level altogether on the instance (deprecated field).'),
                                'value' => false,
                                'null' => true,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean'
                        ),
                        'header' => array(
                                'level' => 3,
                                'description' => __('This setting is deprecated and can be safely removed.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                        ),
                        'footermidleft' => array(
                                'level' => 2,
                                'description' => __('Footer text prepending the "Powered by MISP" text.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                        ),
                        'footermidright' => array(
                                'level' => 2,
                                'description' => __('Footer text following the "Powered by MISP" text.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                        ),
                        'footerpart1' => array(
                                'level' => 3,
                                'description' => __('This setting is deprecated and can be safely removed.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                        ),
                        'footerpart2' => array(
                                'level' => 3,
                                'description' => __('This setting is deprecated and can be safely removed.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                        ),
                        'footer' => array(
                                'level' => 3,
                                'description' => __('This setting is deprecated and can be safely removed.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                        ),
                        'footerversion' => array(
                                'level' => 3,
                                'description' => __('This setting is deprecated and can be safely removed.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                        ),
                        'footer_logo' => array(
                                'level' => 2 ,
                                'description' => __('If set, this setting allows you to display a logo on the right side of the footer. Upload it as a custom image in the file management tool.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForCustomImage',
                                'type' => 'string',
                        ),
                        'home_logo' => array(
                                'level' => 2 ,
                                'description' => __('If set, this setting allows you to display a logo as the home icon. Upload it as a custom image in the file management tool.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForCustomImage',
                                'type' => 'string',
                        ),
                        'main_logo' => array(
                                'level' => 2 ,
                                'description' => __('If set, the image specified here will replace the main MISP logo on the login screen. Upload it as a custom image in the file management tool.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForCustomImage',
                                'type' => 'string',
                        ),
                        'org' => array(
                                'level' => 1,
                                'description' => __('The organisation tag of the hosting organisation. This is used in the e-mail subjects.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                        ),
                        'host_org_id' => array(
                                'level' => 0,
                                'description' => __('The hosting organisation of this instance. If this is not selected then replication instances cannot be added.'),
                                'value' => '0',
                                'errorMessage' => '',
                                'test' => 'testLocalOrg',
                                'type' => 'numeric',
                                'optionsSource' => 'LocalOrgs',
                        ),
                        'uuid' => array(
                                'level' => 0,
                                'description' => __('The MISP instance UUID. This UUID is used to identify this instance.'),
                                'value' => '0',
                                'errorMessage' => __('No valid UUID set'),
                                'test' => 'testUuid',
                                'type' => 'string'
                        ),
                        'logo' => array(
                                'level' => 3,
                                'description' => __('This setting is deprecated and can be safely removed.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                        ),
                        'showorg' => array(
                                'level' => 0,
                                'description' => __('Setting this setting to \'false\' will hide all organisation names / logos.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                        ),
                        'threatlevel_in_email_subject' => array(
                                'level' => 2,
                                'description' => __('Put the event threat level in the notification E-mail subject.'),
                                'value' => true,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                            ),
                        'email_subject_TLP_string' => array(
                                'level' => 2,
                                'description' => __('This is the TLP string for e-mails when email_subject_tag is not found.'),
                                'value' => 'tlp:amber',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                            ),
                        'email_subject_tag' => array(
                                'level' => 2,
                                'description' => __('If this tag is set on an event it\'s value will be sent in the E-mail subject. If the tag is not set the email_subject_TLP_string will be used.'),
                                'value' => 'tlp',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                            ),
                        'email_subject_include_tag_name' => array(
                                'level' => 2,
                                'description' => __('Include in name of the email_subject_tag in the subject. When false only the tag value is used.'),
                                'value' => true,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                            ),
                        'taxii_sync' => array(
                                'level' => 3,
                                'description' => __('This setting is deprecated and can be safely removed.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                        ),
                        'taxii_client_path' => array(
                                'level' => 3,
                                'description' => __('This setting is deprecated and can be safely removed.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                        ),
                        'background_jobs' => array(
                                'level' => 1,
                                'description' => __('Enables the use of MISP\'s background processing.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testBoolTrue',
                                'type' => 'boolean',
                        ),
                        'attachments_dir' => array(
                                'level' => 2,
                                'description' => __('Directory where attachments are stored. MISP will NOT migrate the existing data if you change this setting. The only safe way to change this setting is in config.php, when MISP is not running, and after having moved/copied the existing data to the new location. This directory must already exist and be writable and readable by the MISP application.'),
                                'value' =>  APP . '/files', # GUI display purpose only.
                                'errorMessage' => '',
                                'null' => false,
                                'test' => 'testForWritableDir',
                                'type' => 'string',
                                'cli_only' => 1
                        ),
                        'cached_attachments' => array(
                                'level' => 1,
                                'description' => __('Allow the XML caches to include the encoded attachments.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                        ),
                        'download_attachments_on_load' => array(
                            'level' => 2,
                            'description' => __('Always download attachments when loaded by a user in a browser'),
                            'value' => true,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean',
                        ),
                        'osuser' => array(
                                'level' => 0,
                                'description' => __('The Unix user MISP (php) is running as'),
                                'value' => 'www-data',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                        ),
                        'email' => array(
                                'level' => 0,
                                'description' => __('The e-mail address that MISP should use for all notifications'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                        ),
                        'disable_emailing' => array(
                                'level' => 0,
                                'description' => __('You can disable all e-mailing using this setting. When enabled, no outgoing e-mails will be sent by MISP.'),
                                'value' => false,
                                'errorMessage' => '',
                                'null' => true,
                                'test' => 'testDisableEmail',
                                'type' => 'boolean',
                        ),
                        'contact' => array(
                                'level' => 1,
                                'description' => __('The e-mail address that MISP should include as a contact address for the instance\'s support team.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                        ),
                        'dns' => array(
                                'level' => 3,
                                'description' => __('This setting is deprecated and can be safely removed.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                        ),
                        'cveurl' => array(
                                'level' => 1,
                                'description' => __('Turn Vulnerability type attributes into links linking to the provided CVE lookup'),
                                'value' => 'http://cve.circl.lu/cve/',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                        ),
                        'cweurl' => array(
                                'level' => 1,
                                'description' => __('Turn Weakness type attributes into links linking to the provided CWE lookup'),
                                'value' => 'http://cve.circl.lu/cwe/',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                        ),
                        'disablerestalert' => array(
                                'level' => 1,
                                'description' => __('This setting controls whether notification e-mails will be sent when an event is created via the REST interface. It might be a good idea to disable this setting when first setting up a link to another instance to avoid spamming your users during the initial pull. Quick recap: True = Emails are NOT sent, False = Emails are sent on events published via sync / REST.'),
                                'value' => true,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                        ),
                        'extended_alert_subject' => array(
                                'level' => 1,
                                'description' => __('enabling this flag will allow the event description to be transmitted in the alert e-mail\'s subject. Be aware that this is not encrypted by GnuPG, so only enable it if you accept that part of the event description will be sent out in clear-text.'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean'
                        ),
                        'default_event_distribution' => array(
                                'level' => 0,
                                'description' => __('The default distribution setting for events (0-3).'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                                'options' => array('0' => 'Your organisation only', '1' => 'This community only', '2' => 'Connected communities', '3' => 'All communities'),
                        ),
                        'default_attribute_distribution' => array(
                                'level' => 0,
                                'description' => __('The default distribution setting for attributes, set it to \'event\' if you would like the attributes to default to the event distribution level. (0-3 or "event")'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                                'options' => array('0' => 'Your organisation only', '1' => 'This community only', '2' => 'Connected communities', '3' => 'All communities', 'event' => 'Inherit from event'),
                        ),
                        'default_event_threat_level' => array(
                                'level' => 1,
                                'description' => __('The default threat level setting when creating events.'),
                                'value' => 4,
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                                'options' => array('1' => 'High', '2' => 'Medium', '3' => 'Low', '4' => 'undefined'),
                        ),
                        'default_event_tag_collection' => array(
                            'level' => 0,
                            'description' => __('The tag collection to be applied to all events created manually.'),
                            'value' => 0,
                            'errorMessage' => '',
                            'test' => 'testTagCollections',
                            'type' => 'numeric',
                            'optionsSource' => 'TagCollections',
                        ),
                        'default_publish_alert' => array(
                                'level' => 0,
                                'description' => __('The default setting for publish alerts when creating users.'),
                                'value' => true,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                                'null' => true
                        ),
                        'tagging' => array(
                                'level' => 1,
                                'description' => __('Enable the tagging feature of MISP. This is highly recommended.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                        ),
                        'full_tags_on_event_index' => array(
                                'level' => 2,
                                'description' => __('Show the full tag names on the event index.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                                'options' => array(0 => 'Minimal tags', 1 => 'Full tags', 2 => 'Shortened tags'),
                        ),
                        'welcome_text_top' => array(
                                'level' => 2,
                                'description' => __('Used on the login page, before the MISP logo'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                        ),
                        'welcome_text_bottom' => array(
                                'level' => 2,
                                'description' => __('Used on the login page, after the MISP logo'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                        ),
                        'welcome_logo' => array(
                                'level' => 2,
                                'description' => __('Used on the login page, to the left of the MISP logo, upload it as a custom image in the file management tool.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForCustomImage',
                                'type' => 'string',
                        ),
                        'welcome_logo2' => array(
                                'level' => 2,
                                'description' => __('Used on the login page, to the right of the MISP logo, upload it as a custom image in the file management tool.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForCustomImage',
                                'type' => 'string',
                        ),
                        'title_text' => array(
                            'level' => 2,
                            'description' => __('Used in the page title, after the name of the page'),
                            'value' => 'MISP',
                            'errorMessage' => '',
                            'test' => 'testForEmpty',
                            'type' => 'string',
                        ),
                        'take_ownership_xml_import' => array(
                                'level' => 2,
                                'description' => __('Allows users to take ownership of an event uploaded via the "Add MISP XML" button. This allows spoofing the creator of a manually imported event, also breaking possibly breaking the original intended releasability. Synchronising with an instance that has a different creator for the same event can lead to unwanted consequences.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                        ),
                        'terms_download' => array(
                                'level' => 2,
                                'description' => __('Choose whether the terms and conditions should be displayed inline (false) or offered as a download (true)'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean'
                        ),
                        'terms_file' => array(
                                'level' => 2,
                                'description' => __('The filename of the terms and conditions file. Make sure that the file is located in your MISP/app/files/terms directory'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForTermsFile',
                                'type' => 'string'
                        ),
                        'showorgalternate' => array(
                                'level' => 2,
                                'description' => __('True enables the alternate org fields for the event index (source org and member org) instead of the traditional way of showing only an org field. This allows users to see if an event was uploaded by a member organisation on their MISP instance, or if it originated on an interconnected instance.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean'
                        ),
                        'unpublishedprivate' => array(
                                'level' => 2,
                                'description' => __('True will deny access to unpublished events to users outside the organization of the submitter except site admins.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean'
                        ),
                        'newUserText' => array(
                                'level' => 1,
                                'bigField' => true,
                                'description' => __('The message sent to the user after account creation (has to be sent manually from the administration interface). Use \\n for line-breaks. The following variables will be automatically replaced in the text: $password = a new temporary password that MISP generates, $username = the user\'s e-mail address, $misp = the url of this instance, $org = the organisation that the instance belongs to, as set in MISP.org, $contact = the e-mail address used to contact the support team, as set in MISP.contact. For example, "the password for $username is $password" would appear to a user with the e-mail address user@misp.org as "the password for user@misp.org is hNamJae81".'),
                                'value' => 'Dear new MISP user,\n\nWe would hereby like to welcome you to the $org MISP community.\n\n Use the credentials below to log into MISP at $misp, where you will be prompted to manually change your password to something of your own choice.\n\nUsername: $username\nPassword: $password\n\nIf you have any questions, don\'t hesitate to contact us at: $contact.\n\nBest regards,\nYour $org MISP support team',
                                'errorMessage' => '',
                                'test' => 'testPasswordResetText',
                                'type' => 'string'
                        ),
                        'passwordResetText' => array(
                                'level' => 1,
                                'bigField' => true,
                                'description' => __('The message sent to the users when a password reset is triggered. Use \\n for line-breaks. The following variables will be automatically replaced in the text: $password = a new temporary password that MISP generates, $username = the user\'s e-mail address, $misp = the url of this instance, $contact = the e-mail address used to contact the support team, as set in MISP.contact. For example, "the password for $username is $password" would appear to a user with the e-mail address user@misp.org as "the password for user@misp.org is hNamJae81".'),
                                'value' => 'Dear MISP user,\n\nA password reset has been triggered for your account. Use the below provided temporary password to log into MISP at $misp, where you will be prompted to manually change your password to something of your own choice.\n\nUsername: $username\nYour temporary password: $password\n\nIf you have any questions, don\'t hesitate to contact us at: $contact.\n\nBest regards,\nYour $org MISP support team',
                                'errorMessage' => '',
                                'test' => 'testPasswordResetText',
                                'type' => 'string'
                        ),
                        'enableEventBlocklisting' => array(
                                'level' => 1,
                                'description' => __('Since version 2.3.107 you can start blocklisting event UUIDs to prevent them from being pushed to your instance. This functionality will also happen silently whenever an event is deleted, preventing a deleted event from being pushed back from another instance.'),
                                'value' => true,
                                'type' => 'boolean',
                                'test' => 'testBool'
                        ),
                        'enableOrgBlocklisting' => array(
                                'level' => 1,
                                'description' => __('Blocklisting organisation UUIDs to prevent the creation of any event created by the blocklisted organisation.'),
                                'value' => true,
                                'type' => 'boolean',
                                'test' => 'testBool'
                        ),
                        'log_client_ip' => array(
                                'level' => 1,
                                'description' => __('If enabled, all log entries will include the IP address of the user.'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                                'beforeHook' => 'ipLogBeforeHook'
                        ),
                        'log_client_ip_header' => array(
                            'level' => 1,
                            'description' => __('If log_client_ip is enabled, you can customize which header field contains the client\'s IP address. This is generally used when you have a reverse proxy infront of your MISP instance.'),
                            'value' => 'REMOTE_ADDR',
                            'errorMessage' => '',
                            'test' => 'testForEmpty',
                            'type' => 'string',
                            'null' => true,
                        ),
                        'log_auth' => array(
                                'level' => 1,
                                'description' => __('If enabled, MISP will log all successful authentications using API keys. The requested URLs are also logged.'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                        ),
                        'log_skip_db_logs_completely' => array(
                            'level' => 0,
                            'description' => __('This functionality allows you to completely disable any logs from being saved in your SQL backend. This is HIGHLY advised against, you lose all the functionalities provided by the audit log subsystem along with the event history (as these are built based on the logs on the fly). Only enable this if you understand and accept the associated risks.'),
                            'value' => false,
                            'errorMessage' => __('Logging has now been disabled - your audit logs will not capture failed authentication attempts, your event history logs are not being populated and no system maintenance messages are being logged.'),
                            'test' => 'testBoolFalse',
                            'type' => 'boolean',
                            'null' => true
                        ),
                        'log_paranoid' => array(
                                'level' => 0,
                                'description' => __('If this functionality is enabled all page requests will be logged. Keep in mind this is extremely verbose and will become a burden to your database.'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testBoolFalse',
                                'type' => 'boolean',
                                'null' => true
                        ),
                        'log_paranoid_skip_db' => array(
                                'level' => 0,
                                'description' => __('You can decide to skip the logging of the paranoid logs to the database.'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testParanoidSkipDb',
                                'type' => 'boolean',
                                'null' => true
                        ),
                        'log_paranoid_include_post_body' => array(
                                'level' => 0,
                                'description' => __('If paranoid logging is enabled, include the POST body in the entries.'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                                'null' => true
                        ),
                        'log_user_ips' => array(
                                'level' => 0,
                                'description' => __('Log user IPs on each request. 30 day retention for lookups by IP to get the last authenticated user ID for the given IP, whilst on the reverse, indefinitely stores all associated IPs for a user ID.'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                                'null' => true
                        ),
                        'delegation' => array(
                                'level' => 1,
                                'description' => __('This feature allows users to create org only events and ask another organisation to take ownership of the event. This allows organisations to remain anonymous by asking a partner to publish an event for them.'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                                'null' => true
                        ),
                        'showCorrelationsOnIndex' => array(
                                'level' => 1,
                                'description' => __('When enabled, the number of correlations visible to the currently logged in user will be visible on the event index UI. This comes at a performance cost but can be very useful to see correlating events at a glance.'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                                'null' => true
                        ),
                        'showProposalsCountOnIndex' => array(
                                'level' => 1,
                                'description' => __('When enabled, the number of proposals for the events are shown on the index.'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                                'null' => true
                        ),
                        'showSightingsCountOnIndex' => array(
                                'level' => 1,
                                'description' => __('When enabled, the aggregate number of attribute sightings within the event becomes visible to the currently logged in user on the event index UI.'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                                'null' => true
                        ),
                        'showDiscussionsCountOnIndex' => array(
                                'level' => 1,
                                'description' => __('When enabled, the aggregate number of discussion posts for the event becomes visible to the currently logged in user on the event index UI.'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                                'null' => true
                        ),
                        'disableUserSelfManagement' => array(
                                'level' => 1,
                                'description' => __('When enabled only Org and Site admins can edit a user\'s profile.'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                                'null' => false,
                        ),
                    'disable_user_login_change' => array(
                        'level' => self::SETTING_RECOMMENDED,
                        'description' => __('When enabled only Site admins can change user email. This should be enabled if you manage user logins by external system.'),
                        'value' => false,
                        'errorMessage' => '',
                        'test' => 'testBool',
                        'type' => 'boolean',
                        'null' => false,
                    ),
                    'disable_user_password_change' => array(
                        'level' => self::SETTING_RECOMMENDED,
                        'description' => __('When enabled only Site admins can change user password. This should be enabled if you manage user passwords by external system.'),
                        'value' => false,
                        'errorMessage' => '',
                        'test' => 'testBool',
                        'type' => 'boolean',
                        'null' => false,
                    ),
                    'disable_user_add' => array(
                        'level' => self::SETTING_RECOMMENDED,
                        'description' => __('When enabled, Org Admins could not add new users. This should be enabled if you manage users by external system.'),
                        'value' => false,
                        'errorMessage' => '',
                        'test' => 'testBool',
                        'type' => 'boolean',
                        'null' => false,
                    ),
                        'block_event_alert' => array(
                                'level' => 1,
                                'description' => __('Enable this setting to start blocking alert e-mails for events with a certain tag. Define the tag in MISP.block_event_alert_tag.'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                                'null' => false,
                        ),
                        'block_event_alert_tag' => array(
                                'level' => 1,
                                'description' => __('If the MISP.block_event_alert setting is set, alert e-mails for events tagged with the tag defined by this setting will be blocked.'),
                                'value' => 'no-alerts="true"',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                                'null' => false,
                        ),
                        'org_alert_threshold' => array(
                                'level' => 1,
                                'description' => __('Set a value to limit the number of email alerts that events can generate per creator organisation (for example, if an organisation pushes out 2000 events in one shot, only alert on the first 20).'),
                                'value' => 0,
                                'errorMessage' => '',
                                'test' => 'testForNumeric',
                                'type' => 'numeric',
                                'null' => true,
                        ),
                        'block_old_event_alert' => array(
                                'level' => 1,
                                'description' => __('Enable this setting to start blocking alert e-mails for old events. The exact timing of what constitutes an old event is defined by MISP.block_old_event_alert_age.'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                                'null' => false,
                        ),
                        'block_old_event_alert_age' => array(
                                'level' => 1,
                                'description' => __('If the MISP.block_old_event_alert setting is set, this setting will control how old an event can be for it to be alerted on. The "timestamp" field of the event is used. Expected format: integer, in days'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testForNumeric',
                                'type' => 'numeric',
                                'null' => false,
                        ),
                        'block_old_event_alert_by_date' => array(
                                'level' => 1,
                                'description' => __('If the MISP.block_old_event_alert setting is set, this setting will control the threshold for the event.date field, indicating how old an event can be for it to be alerted on. The "date" field of the event is used. Expected format: integer, in days'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testForNumeric',
                                'type' => 'numeric',
                                'null' => false,
                        ),
                        'tmpdir' => array(
                                'level' => 1,
                                'description' => __('Please indicate the temp directory you wish to use for certain functionalities in MISP. By default this is set to /tmp and will be used among others to store certain temporary files extracted from imports during the import process.'),
                                'value' => '/tmp',
                                'errorMessage' => '',
                                'test' => 'testForPath',
                                'type' => 'string',
                                'null' => true,
                                'cli_only' => 1
                        ),
                        'custom_css' => array(
                                'level' => 2,
                                'description' => __('If you would like to customise the css, simply drop a css file in the /var/www/MISP/app/webroot/css directory and enter the name here.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForStyleFile',
                                'type' => 'string',
                                'null' => true,
                        ),
                        'proposals_block_attributes' => array(
                                'level' => 0,
                                'description' => __('Enable this setting to allow blocking attributes from to_ids sensitive exports if a proposal has been made to it to remove the IDS flag or to remove the attribute altogether. This is a powerful tool to deal with false-positives efficiently.'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                                'null' => false,
                        ),
                        'incoming_tags_disabled_by_default' => array(
                                'level' => 1,
                                'description' => __('Enable this settings if new tags synced / added via incoming events from any source should not be selectable by users by default.'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                                'null' => false
                        ),
                        'completely_disable_correlation' => array(
                                'level' => 0,
                                'description' => __('*WARNING* This setting will completely disable the correlation on this instance and remove any existing saved correlations. Enabling this will trigger a full recorrelation of all data which is an extremely long and costly procedure. Only enable this if you know what you\'re doing.'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testBoolFalse',
                                'type' => 'boolean',
                                'null' => true,
                                'afterHook' => 'correlationAfterHook',
                        ),
                        'allow_disabling_correlation' => array(
                                'level' => 0,
                                'description' => __('*WARNING* This setting will give event creators the possibility to disable the correlation of individual events / attributes that they have created.'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testBoolFalse',
                                'type' => 'boolean',
                                'null' => true
                        ),
                        'redis_host' => array(
                            'level' => 0,
                            'description' => __('The host running the redis server to be used for generic MISP tasks such as caching. This is not to be confused by the redis server used by the background processing.'),
                            'value' => '127.0.0.1',
                            'errorMessage' => '',
                            'test' => 'testForEmpty',
                            'type' => 'string'
                        ),
                        'redis_port' => array(
                            'level' => 0,
                            'description' => __('The port used by the redis server to be used for generic MISP tasks such as caching. This is not to be confused by the redis server used by the background processing.'),
                            'value' => 6379,
                            'errorMessage' => '',
                            'test' => 'testForNumeric',
                            'type' => 'numeric'
                        ),
                        'redis_database' => array(
                            'level' => 0,
                            'description' => __('The database on the redis server to be used for generic MISP tasks. If you run more than one MISP instance, please make sure to use a different database on each instance.'),
                            'value' => 13,
                            'errorMessage' => '',
                            'test' => 'testForNumeric',
                            'type' => 'numeric'
                        ),
                        'redis_password' => array(
                            'level' => 0,
                            'description' => __('The password on the redis server (if any) to be used for generic MISP tasks.'),
                            'value' => '',
                            'errorMessage' => '',
                            'test' => null,
                            'type' => 'string',
                            'redacted' => true
                        ),
                        'event_view_filter_fields' => array(
                            'level' => 2,
                            'description' => __('Specify which fields to filter on when you search on the event view. Default values are : "id, uuid, value, comment, type, category, Tag.name"'),
                            'value' => 'id, uuid, value, comment, type, category, Tag.name',
                            'errorMessage' => '',
                            'test' => null,
                            'type' => 'string',
                        ),
                        'manage_workers' => array(
                                'level' => 2,
                                'description' => __('Set this to false if you would like to disable MISP managing its own worker processes (for example, if you are managing the workers with a systemd unit).'),
                                'value' => true,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean'
                        ),
                        'deadlock_avoidance' => array(
                                'level' => 1,
                                'description' => __('Only enable this if you have some tools using MISP with extreme high concurency. General performance will be lower as normal as certain transactional queries are avoided in favour of shorter table locks.'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                                'null' => true
                        ),
                        'updateTimeThreshold' => array(
                               'level' => 1,
                               'description' => __('Sets the minimum time before being able to re-trigger an update if the previous one failed. (safe guard to avoid starting the same update multiple time)'),
                               'value' => '7200',
                               'test' => 'testForNumeric',
                               'type' => 'numeric',
                               'null' => true
                       ),
                       'attribute_filters_block_only' => array(
                               'level' => 1,
                               'description' => __('This is a performance tweak to change the behaviour of restSearch to use attribute filters solely for blocking. This means that a lookup on the event scope with for example the type field set will be ignored unless it\'s used to strip unwanted attributes from the results. If left disabled, passing [ip-src, ip-dst] for example will return any event with at least one ip-src or ip-dst attribute. This is generally not considered to be too useful and is a heavy burden on the database.'),
                               'value' => false,
                               'errorMessage' => '',
                               'test' => 'testBool',
                               'type' => 'boolean',
                               'null' => true
                       ),
                    'attachment_scan_module' => [
                        'level' => self::SETTING_OPTIONAL,
                        'description' => __('Name of enrichment module that will be used for attachment malware scanning. This module must return av-signature or sb-signature object.'),
                        'value' => '',
                        'errorMessage' => '',
                        'type' => 'string',
                        'null' => true,
                    ],
                    'attachment_scan_hash_only' => [
                        'level' => self::SETTING_OPTIONAL,
                        'description' => __('Send to attachment scan module just file hash. This can be useful if module sends attachment to remote service and you don\'t want to leak real data.'),
                        'value' => false,
                        'errorMessage' => '',
                        'test' => 'testBool',
                        'type' => 'boolean',
                        'null' => true,
                    ],
                    'attachment_scan_timeout' => [
                        'level' => self::SETTING_OPTIONAL,
                        'description' => __('How long to wait for scan results in seconds.'),
                        'value' => 30,
                        'errorMessage' => '',
                        'test' => 'testForPositiveInteger',
                        'type' => 'numeric',
                        'null' => true,
                    ]
                ),
                'GnuPG' => array(
                        'branch' => 1,
                        'binary' => array(
                                'level' => 2,
                                'description' => __('The location of the GnuPG executable. If you would like to use a different GnuPG executable than /usr/bin/gpg, you can set it here. If the default is fine, just keep the setting suggested by MISP.'),
                                'value' => '/usr/bin/gpg',
                                'errorMessage' => '',
                                'test' => 'testForGPGBinary',
                                'type' => 'string',
                                'cli_only' => 1
                        ),
                        'onlyencrypted' => array(
                                'level' => 0,
                                'description' => __('Allow (false) unencrypted e-mails to be sent to users that don\'t have a GnuPG key.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                        ),
                        'bodyonlyencrypted' => array(
                                'level' => 2,
                                'description' => __('Allow (false) the body of unencrypted e-mails to contain details about the event.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                        ),
                        'sign' => array(
                                'level' => 2,
                                'description' => __('Enable the signing of GnuPG emails. By default, GnuPG emails are signed'),
                                'value' => true,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                        ),
                        'email' => array(
                                'level' => 0,
                                'description' => __('The e-mail address that the instance\'s GnuPG key is tied to.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                        ),
                        'password' => array(
                                'level' => 1,
                                'description' => __('The password (if it is set) of the GnuPG key of the instance.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                                'redacted' => true
                        ),
                        'homedir' => array(
                                'level' => 0,
                                'description' => __('The location of the GnuPG homedir.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                        ),
                        'obscure_subject' => array(
                                'level' => 2,
                                'description' => __('When enabled, subject in signed and encrypted e-mails will not send in unencrypted form.'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                        )
                ),
                'SMIME' => array(
                        'branch' => 1,
                        'enabled' => array(
                                'level' => 2,
                                'description' => __('Enable SMIME encryption. The encryption posture of the GnuPG.onlyencrypted and GnuPG.bodyonlyencrypted settings are inherited if SMIME is enabled.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                        ),
                        'email' => array(
                                'level' => 2,
                                'description' => __('The e-mail address that the instance\'s SMIME key is tied to.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                        ),
                        'cert_public_sign' => array(
                                'level' => 2,
                                'description' => __('The location of the public half of the signing certificate.'),
                                'value' => '/var/www/MISP/.smime/email@address.com.pem',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                        ),
                        'key_sign' => array(
                                'level' => 2,
                                'description' => __('The location of the private half of the signing certificate.'),
                                'value' => '/var/www/MISP/.smime/email@address.com.key',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                        ),
                        'password' => array(
                                'level' => 2,
                                'description' => __('The password (if it is set) of the SMIME key of the instance.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                                'redacted' => true
                        ),
                ),
                'Proxy' => array(
                        'branch' => 1,
                        'host' => array(
                                'level' => 2,
                                'description' => __('The hostname of an HTTP proxy for outgoing sync requests. Leave empty to not use a proxy.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                        ),
                        'port' => array(
                                'level' => 2,
                                'description' => __('The TCP port for the HTTP proxy.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForNumeric',
                                'type' => 'numeric',
                        ),
                        'method' => array(
                                'level' => 2,
                                'description' => __('The authentication method for the HTTP proxy. Currently supported are Basic or Digest. Leave empty for no proxy authentication.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                        ),
                        'user' => array(
                                'level' => 2,
                                'description' => __('The authentication username for the HTTP proxy.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                        ),
                        'password' => array(
                                'level' => 2,
                                'description' => __('The authentication password for the HTTP proxy.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                        ),
                ),
                'Security' => array(
                        'branch' => 1,
                        'disable_form_security' => array(
                            'level' => 0,
                            'description' => __('Disabling this setting will remove all form tampering protection. Do not set this setting pretty much ever. You were warned.'),
                            'value' => false,
                            'errorMessage' => 'This setting leaves your users open to CSRF attacks. Do not please consider disabling this setting.',
                            'test' => 'testBoolFalse',
                            'type' => 'boolean',
                            'null' => true
                        ),
                        'salt' => array(
                                'level' => 0,
                                'description' => __('The salt used for the hashed passwords. You cannot reset this from the GUI, only manually from the settings.php file. Keep in mind, this will invalidate all passwords in the database.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testSalt',
                                'type' => 'string',
                                'editable' => false,
                                'redacted' => true
                        ),
                        'advanced_authkeys' => array(
                                'level' => 0,
                                'description' => __('Advanced authkeys will allow each user to create and manage a set of authkeys for themselves, each with individual expirations and comments. API keys are stored in a hashed state and can no longer be recovered from MISP. Users will be prompted to note down their key when creating a new authkey. You can generate a new set of API keys for all users on demand in the diagnostics page, or by triggering %s.', sprintf('<a href="%s/servers/serverSettings/diagnostics#advanced_authkey_update">%s</a>', $this->baseurl, __('the advanced upgrade'))),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                        ),
                    'auth_enforced' => [
                        'level' => self::SETTING_OPTIONAL,
                        'description' => __('This optional can be enabled if external auth provider is used and when set to true, it will disable default form authentication.'),
                        'value' => false,
                        'errorMessage' => '',
                        'test' => 'testBool',
                        'type' => 'boolean',
                    ],
                        'rest_client_enable_arbitrary_urls' => array(
                            'level' => 0,
                            'description' => __('Enable this setting if you wish for users to be able to query any arbitrary URL via the rest client. Keep in mind that queries are executed by the MISP server, so internal IPs in your MISP\'s network may be reachable.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean',
                            'null' => true
                        ),
                        'rest_client_baseurl' => array(
                            'level' => 1,
                            'description' => __('If left empty, the baseurl of your MISP is used. However, in some instances (such as port-forwarded VM installations) this will not work. You can override the baseurl with a url through which your MISP can reach itself (typically https://127.0.0.1 would work).'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => null,
                            'type' => 'string'
                        ),
                        'syslog' => array(
                            'level' => 0,
                            'description' => __('Enable this setting to pass all audit log entries directly to syslog. Keep in mind, this is verbose and will include user, organisation, event data.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean',
                            'null' => true
                        ),
                    'syslog_to_stderr' => array(
                        'level' => self::SETTING_OPTIONAL,
                        'description' => __('Write syslog messages also to standard error output.'),
                        'value' => true,
                        'errorMessage' => '',
                        'test' => 'testBool',
                        'type' => 'boolean',
                        'null' => true
                    ),
                    'syslog_ident' => array(
                        'level' => self::SETTING_OPTIONAL,
                        'description' => __('Syslog message identifier.'),
                        'value' => '',
                        'errorMessage' => '',
                        'test' => 'testForEmpty',
                        'type' => 'string',
                        'null' => true
                    ),
                        'do_not_log_authkeys' => array(
                            'level' => 0,
                            'description' => __('If enabled, any authkey will be replaced by asterisks in Audit log.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean',
                            'null' => true
                        ),
                        'disable_browser_cache' => array(
                            'level' => 0,
                            'description' => __('If enabled, HTTP headers that block browser cache will be send. Static files (like images or JavaScripts) will still be cached, but not generated pages.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean',
                            'null' => true,
                        ),
                        'check_sec_fetch_site_header' => [
                            'level' => 0,
                            'description' => __('If enabled, any POST, PUT or AJAX request will be allow just when Sec-Fetch-Site header is not defined or contains "same-origin".'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean',
                            'null' => true,
                        ],
                        'email_otp_enabled' => array(
                                'level'=> 2,
                                'description' => __('Enable two step authentication with a OTP sent by email. Requires e-mailing to be enabled. Warning: You cannot use it in combination with external authentication plugins.'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'beforeHook' => 'otpBeforeHook',
                                'type' => 'boolean',
                                'null' => true
                        ),
                        'email_otp_length' => array (
                                'level' => 2,
                                'description' => __('Define the length of the OTP code sent by email'),
                                'value' => '6',
                                'errorMessage' => '',
                                'type' => 'numeric',
                                'test' => 'testForNumeric',
                                'null' => true,
                        ),
                        'email_otp_validity' => array (
                                'level' => 2,
                                'description' => __('Define the validity (in minutes) of the OTP code sent by email'),
                                'value' => '5',
                                'errorMessage' => '',
                                'type' => 'numeric',
                                'test' => 'testForNumeric',
                                'null' => true,
                        ),
                        'email_otp_text' => array(
                                'level' => 2,
                                'bigField' => true,
                                'description' => __('The message sent to the user when a new OTP is requested. Use \\n for line-breaks. The following variables will be automatically replaced in the text: $otp = the new OTP generated by MISP, $username = the user\'s e-mail address, $org the Organisation managing the instance, $misp = the url of this instance, $contact = the e-mail address used to contact the support team (as set in MISP.contact), $ip the IP used to complete the first step of the login and $validity the validity time in minutes.'),
                                'value' => 'Dear MISP user,\n\nYou have attempted to login to MISP ($misp) from $ip with username $username.\n\n Use the following OTP to log into MISP: $otp\n This code is valid for the next $validity minutes.\n\nIf you have any questions, don\'t hesitate to contact us at: $contact.\n\nBest regards,\nYour $org MISP support team',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                                'null' => true,
                        ),
                        'email_otp_exceptions' => array(
                                'level' => 2,
                                'bigField' => true,
                                'description' => __('A comma separated list of emails for which the OTP is disabled. Note that if you remove someone from this list, the OTP will only be asked at next login.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                                'null' => true,
                        ),
                        'allow_self_registration' => array(
                            'level' => 1,
                            'description' => __('Enabling this setting will allow users to have access to the pre-auth registration form. This will create an inbox entry for administrators to review.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean',
                            'null' => true
                        ),
                        'self_registration_message' => array(
                                'level' => 1,
                                'bigField' => true,
                                'description' => __('The message sent shown to anyone trying to self-register.'),
                                'value' => 'If you would like to send us a registration request, please fill out the form below. Make sure you fill out as much information as possible in order to ease the task of the administrators.',
                                'errorMessage' => '',
                                'test' => false,
                                'type' => 'string'
                        ),
                        'password_policy_length' => array(
                                'level' => 2,
                                'description' => __('Password length requirement. If it is not set or it is set to 0, then the default value is assumed (12).'),
                                'value' => '12',
                                'errorMessage' => '',
                                'test' => 'testPasswordLength',
                                'type' => 'numeric',
                        ),
                        'password_policy_complexity' => array(
                                'level' => 2,
                                'description' => __('Password complexity requirement. Leave it empty for the default setting (3 out of 4, with either a digit or a special char) or enter your own regex. Keep in mind that the length is checked in another key. Default (simple 3 out of 4 or minimum 16 characters): /^((?=.*\d)|(?=.*\W+))(?![\n])(?=.*[A-Z])(?=.*[a-z]).*$|.{16,}/'),
                                'value' => '/^((?=.*\d)|(?=.*\W+))(?![\n])(?=.*[A-Z])(?=.*[a-z]).*$|.{16,}/',
                                'errorMessage' => '',
                                'test' => 'testPasswordRegex',
                                'type' => 'string',
                        ),
                        'require_password_confirmation' => array(
                            'level' => 1,
                            'description' => __('Enabling this setting will require users to submit their current password on any edits to their profile (including a triggered password change). For administrators, the confirmation will be required when changing the profile of any user. Could potentially mitigate an attacker trying to change a compromised user\'s password in order to establish persistance, however, enabling this feature will be highly annoying to users.'),
                            'value' => true,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean',
                            'null' => true
                        ),
                        'sanitise_attribute_on_delete' => array(
                            'level' => 1,
                            'description' => __('Enabling this setting will sanitise the contents of an attribute on a soft delete'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean',
                            'null' => true
                        ),
                        'hide_organisation_index_from_users' => array(
                            'level' => 1,
                            'description' => __('Enabling this setting will block the organisation index from being visible to anyone besides site administrators on the current instance. Keep in mind that users can still see organisations that produce data via events, proposals, event history log entries, etc.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean',
                            'null' => true
                        ),
                        'disable_local_feed_access' => array(
                                'level' => 0,
                                'description' => __('Disabling this setting will allow the creation/modification of local feeds (as opposed to network feeds). Enabling this setting will restrict feed sources to be network based only. When disabled, keep in mind that a malicious site administrator could get access to any arbitrary file on the system that the apache user has access to. Make sure that proper safe-guards are in place. This setting can only be modified via the CLI.'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                                'null' => true,
                                'cli_only' => 1
                        ),
                        'allow_unsafe_apikey_named_param' => array(
                            'level' => 0,
                            'description' => __('Allows passing the API key via the named url parameter "apikey" - highly recommended not to enable this, but if you have some dodgy legacy tools that cannot pass the authorization header it can work as a workaround. Again, only use this as a last resort.'),
                            'value' => false,
                            'errorMessage' => __('You have enabled the passing of API keys via URL parameters. This is highly recommended against, do you really want to reveal APIkeys in your logs?...'),
                            'test' => 'testBoolFalse',
                            'type' => 'boolean',
                            'null' => true
                        ),
                        'allow_cors' => array(
                            'level' => 1,
                            'description' => __('Allow cross-origin requests to this instance, matching origins given in Security.cors_origins. Set to false to totally disable'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean',
                            'null' => true
                        ),
                        'cors_origins' => array(
                            'level' => 1,
                            'description' => __('Set the origins from which MISP will allow cross-origin requests. Useful for external integration. Comma seperate if you need more than one.'),
                            'value' => '',
                            'errorMessage' => '',
                            'test' => 'testForEmpty',
                            'type' => 'string',
                            'null' => true
                        ),
                        'sync_audit' => array(
                            'level' => 1,
                            'description' => __('Enable this setting to create verbose logs of synced event data for debugging reasons. Logs are saved in your MISP directory\'s app/files/scripts/tmp/ directory.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBoolFalse',
                            'type' => 'boolean',
                            'null' => true
                        ),
                        'user_monitoring_enabled' => array(
                            'level' => 1,
                            'description' => __('Enables the functionality to monitor users - thereby enabling all logging functionalities for a single user. This functionality is intrusive and potentially heavy on the system - use it with care.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean',
                            'null' => true
                        )
                ),
                'SecureAuth' => array(
                        'branch' => 1,
                        'amount' => array(
                                'level' => 0,
                                'description' => __('The number of tries a user can try to login and fail before the bruteforce protection kicks in.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForNumeric',
                                'type' => 'string',
                        ),
                        'expire' => array(
                                'level' => 0,
                                'description' => __('The duration (in seconds) of how long the user will be locked out when the allowed number of login attempts are exhausted.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForNumeric',
                                'type' => 'string',
                        ),
                ),
                'Session' => array(
                        'branch' => 1,
                        'autoRegenerate' => array(
                                'level' => 0,
                                'description' => __('Set to true to automatically regenerate sessions after x number of requests. This might lead to the user getting de-authenticated and is frustrating in general, so only enable it if you really need to regenerate sessions. (Not recommended)'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testBoolFalse',
                                'type' => 'boolean',
                        ),
                        'checkAgent' => array(
                                'level' => 0,
                                'description' => __('Set to true to check for the user agent string in each request. This can lead to occasional logouts (not recommended).'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testBoolFalse',
                                'type' => 'boolean',
                        ),
                        'defaults' => array(
                                'level' => 0,
                                'description' => __('The session type used by MISP. The default setting is php, which will use the session settings configured in php.ini for the session data (supported options: php, database). The recommended option is php and setting your PHP up to use redis sessions via your php.ini. Just add \'session.save_handler = redis\' and "session.save_path = \'tcp://localhost:6379\'" (replace the latter with your redis connection) to '),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForSessionDefaults',
                                'type' => 'string',
                                'options' => array('php' => 'php', 'database' => 'database', 'cake' => 'cake', 'cache' => 'cache'),
                        ),
                        'timeout' => array(
                                'level' => 0,
                                'description' => __('The timeout duration of sessions (in MINUTES). 0 does not mean infinite for the PHP session handler, instead sessions will invalidate immediately.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForNumeric',
                                'type' => 'string'
                        ),
                        'cookieTimeout' => array(
                                'level' => 0,
                                'description' => __('The expiration of the cookie (in MINUTES). The session timeout gets refreshed frequently, however the cookies do not. Generally it is recommended to have a much higher cookie_timeout than timeout.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForCookieTimeout',
                                'type' => 'numeric'
                        )
                ),
                'Plugin' => array(
                        'branch' => 1,
                        'RPZ_policy' => array(
                            'level' => 2,
                            'description' => __('The default policy action for the values added to the RPZ.'),
                            'value' => 1,
                            'errorMessage' => '',
                            'test' => 'testForRPZBehaviour',
                            'type' => 'numeric',
                            'options' => array(0 => 'DROP', 1 => 'NXDOMAIN', 2 => 'NODATA', 3 => 'Local-Data', 4 => 'PASSTHRU', 5 => 'TCP-only' ),
                        ),
                        'RPZ_walled_garden' => array(
                            'level' => 2,
                            'description' => __('The default walled garden used by the RPZ export if the Local-Data policy setting is picked for the export.'),
                            'value' => '127.0.0.1',
                            'errorMessage' => '',
                            'test' => 'testForEmpty',
                            'type' => 'string',
                        ),
                        'RPZ_serial' => array(
                                'level' => 2,
                                'description' => __('The serial in the SOA portion of the zone file. (numeric, best practice is yyyymmddrr where rr is the two digit sub-revision of the file. $date will automatically get converted to the current yyyymmdd, so $date00 is a valid setting). Setting it to $time will give you an unixtime-based serial (good then you need more than 99 revisions per day).'),
                                'value' => '$date00',
                                'errorMessage' => '',
                                'test' => 'testForRPZSerial',
                                'type' => 'string',
                        ),
                        'RPZ_refresh' => array(
                                'level' => 2,
                                'description' => __('The refresh specified in the SOA portion of the zone file. (in seconds, or shorthand duration such as 15m)'),
                                'value' => '2h',
                                'errorMessage' => '',
                                'test' => 'testForRPZDuration',
                                'type' => 'string',
                        ),
                        'RPZ_retry' => array(
                                'level' => 2,
                                'description' => __('The retry specified in the SOA portion of the zone file. (in seconds, or shorthand duration such as 15m)'),
                                'value' => '30m',
                                'errorMessage' => '',
                                'test' => 'testForRPZDuration',
                                'type' => 'string',
                        ),
                        'RPZ_expiry' => array(
                                'level' => 2,
                                'description' => __('The expiry specified in the SOA portion of the zone file. (in seconds, or shorthand duration such as 15m)'),
                                'value' => '30d',
                                'errorMessage' => '',
                                'test' => 'testForRPZDuration',
                                'type' => 'string',
                        ),
                        'RPZ_minimum_ttl' => array(
                                'level' => 2,
                                'description' => __('The minimum TTL specified in the SOA portion of the zone file. (in seconds, or shorthand duration such as 15m)'),
                                'value' => '1h',
                                'errorMessage' => '',
                                'test' => 'testForRPZDuration',
                                'type' => 'string',
                        ),
                        'RPZ_ttl' => array(
                                'level' => 2,
                                'description' => __('The TTL of the zone file. (in seconds, or shorthand duration such as 15m)'),
                                'value' => '1w',
                                'errorMessage' => '',
                                'test' => 'testForRPZDuration',
                                'type' => 'string',
                        ),
                        'RPZ_ns' => array(
                                'level' => 2,
                                'description' => __('Nameserver'),
                                'value' => 'localhost.',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                        ),
                        'RPZ_ns_alt' => array(
                            'level' => 2,
                            'description' => __('Alternate nameserver'),
                            'value' => '',
                            'errorMessage' => '',
                            'test' => 'testForEmpty',
                            'type' => 'string',
                    ),
                        'RPZ_email' => array(
                            'level' => 2,
                            'description' => __('The e-mail address specified in the SOA portion of the zone file.'),
                            'value' => 'root.localhost',
                            'errorMessage' => '',
                            'test' => 'testForEmpty',
                            'type' => 'string',
                        ),
                        'Kafka_enable' => array(
                            'level' => 2,
                            'description' => __('Enables or disables the Kafka pub feature of MISP. Make sure that you install the requirements for the plugin to work. Refer to the installation instructions for more information.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean',
                        ),
                        'Kafka_brokers' => array(
                            'level' => 2,
                            'description' => __('A comma separated list of Kafka bootstrap brokers'),
                            'value' => 'kafka:9092',
                            'errorMessage' => '',
                            'test' => 'testForEmpty',
                            'type' => 'string',
                        ),
                        'Kafka_rdkafka_config' => array(
                            'level' => 2,
                            'description' => __('A path to an ini file with configuration options to be passed to rdkafka. Section headers in the ini file will be ignored.'),
                            'value' => '/etc/rdkafka.ini',
                            'errorMessage' => '',
                            'test' => 'testForEmpty',
                            'type' => 'string',
                        ),
                        'Kafka_include_attachments' => array(
                            'level' => 2,
                            'description' => __('Enable this setting to include the base64 encoded payloads of malware-samples/attachments in the output.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean'
                        ),
                        'Kafka_event_notifications_enable' => array(
                            'level' => 2,
                            'description' => __('Enables or disables the publishing of any event creations/edits/deletions.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean'
                        ),
                        'Kafka_event_notifications_topic' => array(
                            'level' => 2,
                            'description' => __('Topic for publishing event creations/edits/deletions.'),
                            'value' => 'misp_event',
                            'errorMessage' => '',
                            'test' => 'testForEmpty',
                            'type' => 'string'
                        ),
                        'Kafka_event_publish_notifications_enable' => array(
                            'level' => 2,
                            'description' => __('If enabled it will publish to Kafka the event at the time that the event gets published in MISP. Event actions (creation or edit) will not be published to Kafka.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean'
                        ),
                        'Kafka_event_publish_notifications_topic' => array(
                            'level' => 2,
                            'description' => __('Topic for publishing event information on publish.'),
                            'value' => 'misp_event_publish',
                            'errorMessage' => '',
                            'test' => 'testForEmpty',
                            'type' => 'string'
                        ),
                        'Kafka_object_notifications_enable' => array(
                            'level' => 2,
                            'description' => __('Enables or disables the publishing of any object creations/edits/deletions.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean'
                        ),
                        'Kafka_object_notifications_topic' => array(
                            'level' => 2,
                            'description' => __('Topic for publishing object creations/edits/deletions.'),
                            'value' => 'misp_object',
                            'errorMessage' => '',
                            'test' => 'testForEmpty',
                            'type' => 'string'
                        ),
                        'Kafka_object_reference_notifications_enable' => array(
                            'level' => 2,
                            'description' => __('Enables or disables the publishing of any object reference creations/deletions.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean'
                        ),
                        'Kafka_object_reference_notifications_topic' => array(
                            'level' => 2,
                            'description' => __('Topic for publishing object reference creations/deletions.'),
                            'value' => 'misp_object_reference',
                            'errorMessage' => '',
                            'test' => 'testForEmpty',
                            'type' => 'string'
                        ),
                        'Kafka_attribute_notifications_enable' => array(
                            'level' => 2,
                            'description' => __('Enables or disables the publishing of any attribute creations/edits/soft deletions.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean'
                        ),
                        'Kafka_attribute_notifications_topic' => array(
                            'level' => 2,
                            'description' => __('Topic for publishing attribute creations/edits/soft deletions.'),
                            'value' => 'misp_attribute',
                            'errorMessage' => '',
                            'test' => 'testForEmpty',
                            'type' => 'string'
                        ),
                        'Kafka_shadow_attribute_notifications_enable' => array(
                            'level' => 2,
                            'description' => __('Enables or disables the publishing of any proposal creations/edits/deletions.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean'
                        ),
                        'Kafka_shadow_attribute_notifications_topic' => array(
                            'level' => 2,
                            'description' => __('Topic for publishing proposal creations/edits/deletions.'),
                            'value' => 'misp_shadow_attribute',
                            'errorMessage' => '',
                            'test' => 'testForEmpty',
                            'type' => 'string'
                        ),
                        'Kafka_tag_notifications_enable' => array(
                            'level' => 2,
                            'description' => __('Enables or disables the publishing of any tag creations/edits/deletions as well as tags being attached to / detached from various MISP elements.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean'
                        ),
                        'Kafka_tag_notifications_topic' => array(
                            'level' => 2,
                            'description' => __('Topic for publishing tag creations/edits/deletions as well as tags being attached to / detached from various MISP elements.'),
                            'value' => 'misp_tag',
                            'errorMessage' => '',
                            'test' => 'testForEmpty',
                            'type' => 'string'
                        ),
                        'Kafka_sighting_notifications_enable' => array(
                            'level' => 2,
                            'description' => __('Enables or disables the publishing of new sightings.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean'
                        ),
                        'Kafka_sighting_notifications_topic' => array(
                            'level' => 2,
                            'description' => __('Topic for publishing sightings.'),
                            'value' => 'misp_sighting',
                            'errorMessage' => '',
                            'test' => 'testForEmpty',
                            'type' => 'string'
                        ),
                        'Kafka_user_notifications_enable' => array(
                            'level' => 2,
                            'description' => __('Enables or disables the publishing of new/modified users.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean'
                        ),
                        'Kafka_user_notifications_topic' => array(
                            'level' => 2,
                            'description' => __('Topic for publishing new/modified users.'),
                            'value' => 'misp_user',
                            'errorMessage' => '',
                            'test' => 'testForEmpty',
                            'type' => 'string'
                        ),
                        'Kafka_organisation_notifications_enable' => array(
                            'level' => 2,
                            'description' => __('Enables or disables the publishing of new/modified organisations.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean'
                        ),
                        'Kafka_organisation_notifications_topic' => array(
                            'level' => 2,
                            'description' => __('Topic for publishing new/modified organisations.'),
                            'value' => 'misp_organisation',
                            'errorMessage' => '',
                            'test' => 'testForEmpty',
                            'type' => 'string'
                        ),
                        'Kafka_audit_notifications_enable' => array(
                            'level' => 2,
                            'description' => __('Enables or disables the publishing of log entries. Keep in mind, this can get pretty verbose depending on your logging settings.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean'
                        ),
                        'Kafka_audit_notifications_topic' => array(
                            'level' => 2,
                            'description' => __('Topic for publishing log entries.'),
                            'value' => 'misp_audit',
                            'errorMessage' => '',
                            'test' => 'testForEmpty',
                            'type' => 'string'
                        ),
                        'ZeroMQ_enable' => array(
                            'level' => 2,
                            'description' => __('Enables or disables the pub/sub feature of MISP. Make sure that you install the requirements for the plugin to work. Refer to the installation instructions for more information.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean',
                            'afterHook' => 'zmqAfterHook',
                        ),
                        'ZeroMQ_port' => array(
                            'level' => 2,
                            'description' => __('The port that the pub/sub feature will use.'),
                            'value' => 50000,
                            'errorMessage' => '',
                            'test' => 'testForZMQPortNumber',
                            'type' => 'numeric',
                            'afterHook' => 'zmqAfterHook',
                        ),
                        'ZeroMQ_username' => array(
                            'level' => 2,
                            'description' => __('The username that client need to use to connect to ZeroMQ.'),
                            'value' => '',
                            'errorMessage' => '',
                            'test' => 'testForEmpty',
                            'type' => 'string',
                            'afterHook' => 'zmqAfterHook',
                        ),
                        'ZeroMQ_password' => array(
                            'level' => 2,
                            'description' => __('The password that client need to use to connect to ZeroMQ.'),
                            'value' => '',
                            'errorMessage' => '',
                            'test' => 'testForEmpty',
                            'type' => 'string',
                            'afterHook' => 'zmqAfterHook',
                        ),
                        'ZeroMQ_redis_host' => array(
                            'level' => 2,
                            'description' => __('Location of the Redis db used by MISP and the Python PUB script to queue data to be published.'),
                            'value' => 'localhost',
                            'errorMessage' => '',
                            'test' => 'testForEmpty',
                            'type' => 'string',
                            'afterHook' => 'zmqAfterHook',
                        ),
                        'ZeroMQ_redis_port' => array(
                            'level' => 2,
                            'description' => __('The port that Redis is listening on.'),
                            'value' => 6379,
                            'errorMessage' => '',
                            'test' => 'testForPortNumber',
                            'type' => 'numeric',
                            'afterHook' => 'zmqAfterHook',
                        ),
                        'ZeroMQ_redis_password' => array(
                            'level' => 2,
                            'description' => __('The password, if set for Redis.'),
                            'value' => '',
                            'errorMessage' => '',
                            'test' => 'testForEmpty',
                            'type' => 'string',
                            'afterHook' => 'zmqAfterHook',
                        ),
                        'ZeroMQ_redis_database' => array(
                            'level' => 2,
                            'description' => __('The database to be used for queuing messages for the pub/sub functionality.'),
                            'value' => 1,
                            'errorMessage' => '',
                            'test' => 'testForEmpty',
                            'type' => 'string',
                            'afterHook' => 'zmqAfterHook',
                        ),
                        'ZeroMQ_redis_namespace' => array(
                            'level' => 2,
                            'description' => __('The namespace to be used for queuing messages for the pub/sub functionality.'),
                            'value' => 'mispq',
                            'errorMessage' => '',
                            'test' => 'testForEmpty',
                            'type' => 'string',
                            'afterHook' => 'zmqAfterHook',
                        ),
                        'ZeroMQ_include_attachments' => array(
                            'level' => 2,
                            'description' => __('Enable this setting to include the base64 encoded payloads of malware-samples/attachments in the output.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean'
                        ),
                        'ZeroMQ_event_notifications_enable' => array(
                            'level' => 2,
                            'description' => __('Enables or disables the publishing of any event creations/edits/deletions.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean'
                        ),
                        'ZeroMQ_object_notifications_enable' => array(
                            'level' => 2,
                            'description' => __('Enables or disables the publishing of any object creations/edits/deletions.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean'
                        ),
                        'ZeroMQ_object_reference_notifications_enable' => array(
                            'level' => 2,
                            'description' => __('Enables or disables the publishing of any object reference creations/deletions.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean'
                        ),
                        'ZeroMQ_attribute_notifications_enable' => array(
                            'level' => 2,
                            'description' => __('Enables or disables the publishing of any attribute creations/edits/soft deletions.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean'
                        ),
                        'ZeroMQ_tag_notifications_enable' => array(
                            'level' => 2,
                            'description' => __('Enables or disables the publishing of any tag creations/edits/deletions as well as tags being attached to / detached from various MISP elements.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean'
                        ),
                        'ZeroMQ_sighting_notifications_enable' => array(
                            'level' => 2,
                            'description' => __('Enables or disables the publishing of new sightings to the ZMQ pubsub feed.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean'
                        ),
                        'ZeroMQ_user_notifications_enable' => array(
                            'level' => 2,
                            'description' => __('Enables or disables the publishing of new/modified users to the ZMQ pubsub feed.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean'
                        ),
                        'ZeroMQ_organisation_notifications_enable' => array(
                            'level' => 2,
                            'description' => __('Enables or disables the publishing of new/modified organisations to the ZMQ pubsub feed.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean'
                        ),
                        'ZeroMQ_audit_notifications_enable' => array(
                            'level' => 2,
                            'description' => __('Enables or disables the publishing of log entries to the ZMQ pubsub feed. Keep in mind, this can get pretty verbose depending on your logging settings.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean'
                        ),
                        'ElasticSearch_logging_enable' => array(
                            'level' => 2,
                            'description' => __('Enabled logging to an ElasticSearch instance'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean'
                        ),
                        'ElasticSearch_connection_string' => array(
                            'level' => 2,
                            'description' => __('The URL(s) at which to access ElasticSearch - comma separate if you want to have more than one.'),
                            'value' => '',
                            'errorMessage' => '',
                            'test' => 'testForEmpty',
                            'type' => 'string'
                        ),
                        'ElasticSearch_log_index' => array(
                            'level' => 2,
                            'description' => __('The index in which to place logs'),
                            'value' => '',
                            'errorMessage' => '',
                            'test' => 'testForEmpty',
                            'type' => 'string'
                        ),
                        'S3_enable' => array(
                            'level' => 2,
                            'description' => __('Enables or disables uploading of malware samples to S3 rather than to disk (WARNING: Get permission from amazon first!)'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean'
                        ),
                        'S3_bucket_name' => array(
                            'level' => 2,
                            'description' => __('Bucket name to upload to'),
                            'value' => '',
                            'errorMessage' => '',
                            'test' => 'testForEmpty',
                            'type' => 'string'
                        ),
                        'S3_region' => array(
                            'level' => 2,
                            'description' => __('Region in which your S3 bucket resides'),
                            'value' => '',
                            'errorMessage' => '',
                            'test' => 'testForEmpty',
                            'type' => 'string'
                        ),
                        'S3_aws_access_key' => array(
                            'level' => 2,
                            'description' => __('AWS key to use when uploading samples (WARNING: It\' highly recommended that you use EC2 IAM roles if at all possible)'),
                            'value' => '',
                            'errorMessage' => '',
                            'test' => 'testForEmpty',
                            'type' => 'string'
                        ),
                        'S3_aws_secret_key' => array(
                            'level' => 2,
                            'description' => __('AWS secret key to use when uploading samples'),
                            'value' => '',
                            'errorMessage' => '',
                            'test' => 'testForEmpty',
                            'type' => 'string'
                        ),
                        'Sightings_policy' => array(
                            'level' => 1,
                            'description' => __('This setting defines who will have access to seeing the reported sightings. The default setting is the event owner alone (in addition to everyone seeing their own contribution) with the other options being Sighting reporters (meaning the event owner and anyone that provided sighting data about the event) and Everyone (meaning anyone that has access to seeing the event / attribute).'),
                            'value' => 0,
                            'errorMessage' => '',
                            'test' => 'testForSightingVisibility',
                            'type' => 'numeric',
                            'options' => array(0 => 'Event Owner', 1 => 'Sighting reporters', 2 => 'Everyone'),
                        ),
                        'Sightings_anonymise' => array(
                            'level' => 1,
                            'description' => __('Enabling the anonymisation of sightings will simply aggregate all sightings instead of showing the organisations that have reported a sighting. Users will be able to tell the number of sightings their organisation has submitted and the number of sightings for other organisations'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean',
                        ),
                        'Sightings_anonymise_as' => array(
                                'level' => 1,
                                'description' => __('When pushing sightings to another server, report all sightings from this instance as this organisation. This effectively hides all sightings from this instance behind a single organisation to the outside world. Sightings pulled from this instance follow the Sightings_policy above.'),
                                'value' => '0',
                                'errorMessage' => '',
                                'test' => 'testLocalOrg',
                                'type' => 'numeric',
                                'optionsSource' => 'LocalOrgs',
                        ),
                        'Sightings_range' => array(
                            'level' => 1,
                            'description' => __('Set the range in which sightings will be taken into account when generating graphs. For example a sighting with a sighted_date of 7 years ago might not be relevant anymore. Setting given in number of days, default is 365 days'),
                            'value' => 365,
                            'errorMessage' => '',
                            'test' => 'testForNumeric',
                            'type' => 'numeric'
                        ),
                        'Sightings_sighting_db_enable' => array(
                            'level' => 1,
                            'description' => __('Enable SightingDB integration.'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean'
                        ),
                        'CustomAuth_enable' => array(
                                'level' => 2,
                                'description' => __('Enable this functionality if you would like to handle the authentication via an external tool and authenticate with MISP using a custom header.'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                                'null' => true,
                                'beforeHook' => 'customAuthBeforeHook'
                        ),
                        'CustomAuth_header' => array(
                                'level' => 2,
                                'description' => __('Set the header that MISP should look for here. If left empty it will default to the Authorization header.'),
                                'value' => 'Authorization',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                                'null' => true
                        ),
                        'CustomAuth_use_header_namespace' => array(
                                'level' => 2,
                                'description' => __('Use a header namespace for the auth header - default setting is enabled'),
                                'value' => true,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                                'null' => true
                        ),
                        'CustomAuth_header_namespace' => array(
                                'level' => 2,
                                'description' => __('The default header namespace for the auth header - default setting is HTTP_'),
                                'value' => 'HTTP_',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                                'null' => true
                        ),
                        'CustomAuth_required' => array(
                                'level' => 2,
                                'description' => __('If this setting is enabled then the only way to authenticate will be using the custom header. Alternatively, you can run in mixed mode that will log users in via the header if found, otherwise users will be redirected to the normal login page.'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                                'null' => true
                        ),
                        'CustomAuth_only_allow_source' => array(
                                'level' => 2,
                                'description' => __('If you are using an external tool to authenticate with MISP and would like to only allow the tool\'s url as a valid point of entry then set this field. '),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                                'null' => true
                        ),
                        'CustomAuth_name' => array(
                                'level' => 2,
                                'description' => __('The name of the authentication method, this is cosmetic only and will be shown on the user creation page and logs.'),
                                'value' => 'External authentication',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                                'null' => true
                        ),
                        'CustomAuth_disable_logout' => array(
                                'level' => 2,
                                'description' => __('Disable the logout button for users authenticate with the external auth mechanism.'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean'
                        ),
                        'Enrichment_services_enable' => array(
                            'level' => 0,
                            'description' => __('Enable/disable the enrichment services'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean'
                        ),
                        'Enrichment_timeout' => array(
                                'level' => 1,
                                'description' => __('Set a timeout for the enrichment services'),
                                'value' => 10,
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'numeric'
                        ),
                        'Import_services_enable' => array(
                                'level' => 0,
                                'description' => __('Enable/disable the import services'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean'
                        ),
                        'Import_timeout' => array(
                                'level' => 1,
                                'description' => __('Set a timeout for the import services'),
                                'value' => 10,
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'numeric'
                        ),
                        'Import_services_url' => array(
                                'level' => 1,
                                'description' => __('The url used to access the import services. By default, it is accessible at http://127.0.0.1:6666'),
                                'value' => 'http://127.0.0.1',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string'
                        ),
                        'Import_services_port' => array(
                                'level' => 1,
                                'description' => __('The port used to access the import services. By default, it is accessible at 127.0.0.1:6666'),
                                'value' => '6666',
                                'errorMessage' => '',
                                'test' => 'testForPortNumber',
                                'type' => 'numeric'
                        ),
                        'Export_services_url' => array(
                                'level' => 1,
                                'description' => __('The url used to access the export services. By default, it is accessible at http://127.0.0.1:6666'),
                                'value' => 'http://127.0.0.1',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string'
                        ),
                        'Export_services_port' => array(
                                'level' => 1,
                                'description' => __('The port used to access the export services. By default, it is accessible at 127.0.0.1:6666'),
                                'value' => '6666',
                                'errorMessage' => '',
                                'test' => 'testForPortNumber',
                                'type' => 'numeric'
                        ),
                        'Export_services_enable' => array(
                                'level' => 0,
                                'description' => __('Enable/disable the export services'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean'
                        ),
                        'Export_timeout' => array(
                                'level' => 1,
                                'description' => __('Set a timeout for the export services'),
                                'value' => 10,
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'numeric'
                        ),
                        'Enrichment_hover_enable' => array(
                                'level' => 0,
                                'description' => __('Enable/disable the hover over information retrieved from the enrichment modules'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean'
                        ),
                        'Enrichment_hover_popover_only' => array(
                            'level' => 0,
                            'description' => __('When enabled, users have to click on the magnifier icon to show the enrichment'),
                            'value' => false,
                            'errorMessage' => '',
                            'test' => 'testBool',
                            'type' => 'boolean'
                        ),
                        'Enrichment_hover_timeout' => array(
                                'level' => 1,
                                'description' => __('Set a timeout for the hover services'),
                                'value' => 5,
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'numeric'
                        ),
                        'Enrichment_services_url' => array(
                                'level' => 1,
                                'description' => __('The url used to access the enrichment services. By default, it is accessible at http://127.0.0.1:6666'),
                                'value' => 'http://127.0.0.1',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string'
                        ),
                        'Enrichment_services_port' => array(
                                'level' => 1,
                                'description' => __('The port used to access the enrichment services. By default, it is accessible at 127.0.0.1:6666'),
                                'value' => 6666,
                                'errorMessage' => '',
                                'test' => 'testForPortNumber',
                                'type' => 'numeric'
                        ),
                        'Cortex_services_url' => array(
                                'level' => 1,
                                'description' => __('The url used to access Cortex. By default, it is accessible at http://cortex-url'),
                                'value' => 'http://127.0.0.1',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string'
                        ),
                        'Cortex_services_port' => array(
                                'level' => 1,
                                'description' => __('The port used to access Cortex. By default, this is port 9000'),
                                'value' => 9000,
                                'errorMessage' => '',
                                'test' => 'testForPortNumber',
                                'type' => 'numeric'
                        ),
                        'Cortex_services_enable' => array(
                                'level' => 0,
                                'description' => __('Enable/disable the Cortex services'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean'
                        ),
                        'Cortex_authkey' => array(
                                'level' => 1,
                                'description' => __('Set an authentication key to be passed to Cortex'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                                'null' => true
                        ),
                        'Cortex_timeout' => array(
                                'level' => 1,
                                'description' => __('Set a timeout for the Cortex services'),
                                'value' => 120,
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'numeric'
                        ),
                        'Cortex_ssl_verify_peer' => array(
                                'level' => 1,
                                'description' => __('Set to false to disable SSL verification. This is not recommended.'),
                                'value' => true,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                                'null' => true
                        ),
                        'Cortex_ssl_verify_host' => array(
                                'level' => 1,
                                'description' => __('Set to false if you wish to ignore hostname match errors when validating certificates.'),
                                'value' => true,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                                'null' => true
                        ),
                        'Cortex_ssl_allow_self_signed' => array(
                                'level' => 1,
                                'description' => __('Set to true to enable self-signed certificates to be accepted. This requires Cortex_ssl_verify_peer to be enabled.'),
                                'value' => false,
                                'errorMessage' => '',
                                'test' => 'testBool',
                                'type' => 'boolean',
                                'null' => true
                        ),
                        'Cortex_ssl_cafile' => array(
                                'level' => 1,
                                'description' => __('Set to the absolute path of the Certificate Authority file that you wish to use for verifying SSL certificates.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                                'null' => true
                        ),
                        'CustomAuth_custom_password_reset' => array(
                                'level' => 2,
                                'description' => __('Provide your custom authentication users with an external URL to the authentication system to reset their passwords.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                                'null' => true
                        ),
                        'CustomAuth_custom_logout' => array(
                                'level' => 2,
                                'description' => __('Provide a custom logout URL for your users that will log them out using the authentication system you use.'),
                                'value' => '',
                                'errorMessage' => '',
                                'test' => 'testForEmpty',
                                'type' => 'string',
                                'null' => true
                        )
                ),
                'debug' => array(
                        'level' => 0,
                        'description' => __('The debug level of the instance, always use 0 for production instances.'),
                        'value' => '',
                        'errorMessage' => '',
                        'test' => 'testDebug',
                        'type' => 'numeric',
                        'options' => array(0 => 'Debug off', 1 => 'Debug on', 2 => 'Debug + SQL dump'),
                ),
                'site_admin_debug' => array(
                        'level' => 0,
                        'description' => __('The debug level of the instance for site admins. This feature allows site admins to run debug mode on a live instance without exposing it to other users. The most verbose option of debug and site_admin_debug is used for site admins.'),
                        'value' => '',
                        'errorMessage' => '',
                        'test' => 'testDebugAdmin',
                        'type' => 'boolean',
                        'null' => true
                ),
        );
    }

    private $__settingTabMergeRules = array(
            'GnuPG' => 'Encryption',
            'SMIME' => 'Encryption',
            'misc' => 'Security',
            'Security' => 'Security',
            'Session' => 'Security'
    );


    public $validEventIndexFilters = array('searchall', 'searchpublished', 'searchorg', 'searchtag', 'searcheventid', 'searchdate', 'searcheventinfo', 'searchthreatlevel', 'searchdistribution', 'searchanalysis', 'searchattribute');

    public function isOwnedByOrg($serverid, $org)
    {
        return $this->field('id', array('id' => $serverid, 'org' => $org)) === $serverid;
    }

    public function beforeSave($options = array())
    {
        $this->data['Server']['url'] = rtrim($this->data['Server']['url'], '/');
        if (empty($this->data['Server']['id'])) {
            $max_prio = $this->find('first', array(
                'recursive' => -1,
                'order' => array('Server.priority' => 'DESC'),
                'fields' => array('Server.priority')
            ));
            if (empty($max_prio)) {
                $max_prio = 0;
            } else {
                $max_prio = $max_prio['Server']['priority'];
            }
            $this->data['Server']['priority'] = $max_prio + 1;
        }
        return true;
    }

    /**
     * @param int|string $technique 'full', 'update', remote event ID or remote event UUID
     * @param array $server
     * @param bool $force
     * @return array
     */
    private function __getEventIdListBasedOnPullTechnique($technique, array $server, $force = false)
    {
        try {
            if ("full" === $technique) {
                // get a list of the event_ids on the server
                $eventIds = $this->getEventIdsFromServer($server, false, null, false, 'events', $force);
                // reverse array of events, to first get the old ones, and then the new ones
                return array_reverse($eventIds);
            } elseif ("update" === $technique) {
                $eventIds = $this->getEventIdsFromServer($server, false, null, true, 'events', $force);
                $eventModel = ClassRegistry::init('Event');
                $local_event_ids = $eventModel->find('list', array(
                    'fields' => array('uuid'),
                    'recursive' => -1,
                ));
                return array_intersect($eventIds, $local_event_ids);
            } elseif (is_numeric($technique)) {
                return array(intval($technique));
            } elseif (Validation::uuid($technique)) {
                return array($technique);
            } else {
                return array('error' => array(4, null));
            }
        } catch (HttpException $e) {
            $this->logException("Could not fetch event IDs from server {$server['Server']['name']}", $e);
            if ($e->getCode() === 403) {
                return array('error' => array(1, null));
            } else {
                return array('error' => array(2, $e->getMessage()));
            }
        } catch (Exception $e) {
            $this->logException("Could not fetch event IDs from server {$server['Server']['name']}", $e);
            return array('error' => array(2, $e->getMessage()));
        }
    }

    private function __checkIfEventIsBlockedBeforePull($event)
    {
        if (Configure::read('MISP.enableEventBlocklisting') !== false) {
            $this->EventBlocklist = ClassRegistry::init('EventBlocklist');
            if ($this->EventBlocklist->isBlocked($event['Event']['uuid'])) {
                return true;
            }
        }
        return false;
    }

    private function __updatePulledEventBeforeInsert(&$event, $server, $user)
    {
        // we have an Event array
        // The event came from a pull, so it should be locked.
        $event['Event']['locked'] = true;
        if (!isset($event['Event']['distribution'])) { // version 1
            $event['Event']['distribution'] = '1';
        }
        // Distribution
        if (empty(Configure::read('MISP.host_org_id')) || !$server['Server']['internal'] ||  Configure::read('MISP.host_org_id') != $server['Server']['org_id']) {
            switch ($event['Event']['distribution']) {
                case 1:
                    // if community only, downgrade to org only after pull
                    $event['Event']['distribution'] = '0';
                    break;
                case 2:
                    // if connected communities downgrade to community only
                    $event['Event']['distribution'] = '1';
                    break;
            }
            if (isset($event['Event']['Attribute']) && !empty($event['Event']['Attribute'])) {
                foreach ($event['Event']['Attribute'] as $key => $a) {
                    switch ($a['distribution']) {
                        case '1':
                            $event['Event']['Attribute'][$key]['distribution'] = '0';
                            break;
                        case '2':
                            $event['Event']['Attribute'][$key]['distribution'] = '1';
                            break;
                    }
                }
            }
            if (isset($event['Event']['Object']) && !empty($event['Event']['Object'])) {
                foreach ($event['Event']['Object'] as $i => $o) {
                    switch ($o['distribution']) {
                        case '1':
                            $event['Event']['Object'][$i]['distribution'] = '0';
                            break;
                        case '2':
                            $event['Event']['Object'][$i]['distribution'] = '1';
                            break;
                    }
                    if (isset($event['Event']['Object'][$i]['Attribute']) && !empty($event['Event']['Object'][$i]['Attribute'])) {
                        foreach ($event['Event']['Object'][$i]['Attribute'] as $j => $a) {
                            switch ($a['distribution']) {
                                case '1':
                                    $event['Event']['Object'][$i]['Attribute'][$j]['distribution'] = '0';
                                    break;
                                case '2':
                                    $event['Event']['Object'][$i]['Attribute'][$j]['distribution'] = '1';
                                    break;
                            }
                        }
                    }
                }
            }
            if (isset($event['Event']['EventReport']) && !empty($event['Event']['EventReport'])) {
                foreach ($event['Event']['EventReport'] as $key => $r) {
                    switch ($r['distribution']) {
                        case '1':
                            $event['Event']['EventReport'][$key]['distribution'] = '0';
                            break;
                        case '2':
                            $event['Event']['EventReport'][$key]['distribution'] = '1';
                            break;
                    }
                }
            }
        }

        // Distribution, set reporter of the event, being the admin that initiated the pull
        $event['Event']['user_id'] = $user['id'];
        return $event;
    }

    private function __checkIfEventSaveAble($event) {
        if (!empty($event['Event']['Attribute'])) {
            foreach ($event['Event']['Attribute'] as $attribute) {
                if (empty($attribute['deleted'])) {
                    return true;
                }
            }
        }
        if (!empty($event['Event']['Object'])) {
            foreach ($event['Event']['Object'] as $object) {
                if (!empty($object['deleted'])) {
                    continue;
                }
                if (!empty($object['Attribute'])) {
                    foreach ($object['Attribute'] as $attribute) {
                        if (empty($attribute['deleted'])) {
                            return true;
                        }
                    }
                }
            }
        }
        if (!empty($event['Event']['EventReport'])) {
            foreach ($event['Event']['EventReport'] as $report) {
                if (empty($report['deleted'])) {
                    return true;
                }
            }
        }
        return false;
    }

    private function __checkIfPulledEventExistsAndAddOrUpdate($event, $eventId, &$successes, &$fails, $eventModel, $server, $user, $jobId, $force = false)
    {
        // check if the event already exist (using the uuid)
        $existingEvent = $eventModel->find('first', array('conditions' => array('Event.uuid' => $event['Event']['uuid'])));
        $passAlong = $server['Server']['id'];
        if (!$existingEvent) {
            // add data for newly imported events
            $result = $eventModel->_add($event, true, $user, $server['Server']['org_id'], $passAlong, true, $jobId);
            if ($result) {
                $successes[] = $eventId;
                if (Configure::read('Plugin.ZeroMQ_enable') && Configure::read('Plugin.ZeroMQ_event_notifications_enable')) {
                    $pubSubTool = $this->getPubSubTool();
                    $pubSubTool->event_save(array('Event' => $eventId, 'Server' => $server['Server']['id']), 'add_from_connected_server');
                }
            } else {
                $fails[$eventId] = __('Failed (partially?) because of validation errors: ') . json_encode($eventModel->validationErrors, true);
            }
        } else {
            if (!$existingEvent['Event']['locked'] && !$server['Server']['internal']) {
                $fails[$eventId] = __('Blocked an edit to an event that was created locally. This can happen if a synchronised event that was created on this instance was modified by an administrator on the remote side.');
            } else {
                $result = $eventModel->_edit($event, $user, $existingEvent['Event']['id'], $jobId, $passAlong, $force);
                if ($result === true) {
                    $successes[] = $eventId;
                    if (Configure::read('Plugin.ZeroMQ_enable') && Configure::read('Plugin.ZeroMQ_event_notifications_enable')) {
                        $pubSubTool = $this->getPubSubTool();
                        $pubSubTool->event_save(array('Event' => $eventId, 'Server' => $server['Server']['id']), 'edit_from_connected_server');
                    }
                } elseif (isset($result['error'])) {
                    $fails[$eventId] = $result['error'];
                } else {
                    $fails[$eventId] = json_encode($result);
                }
            }
        }
    }

    private function __pullEvent($eventId, &$successes, &$fails, $eventModel, $server, $user, $jobId, $force = false)
    {
        try {
            $event = $eventModel->downloadEventFromServer($eventId, $server);
        } catch (Exception $e) {
            $this->logException('Failed downloading the event ' . $eventId, $e);
            $fails[$eventId] = __('failed downloading the event');
            return false;
        }

        if (!empty($event)) {
            if ($this->__checkIfEventIsBlockedBeforePull($event)) {
                return false;
            }
            $event = $this->__updatePulledEventBeforeInsert($event, $server, $user);
            if (!$this->__checkIfEventSaveAble($event)) {
                $fails[$eventId] = __('Empty event detected.');
            } else {
                $this->__checkIfPulledEventExistsAndAddOrUpdate($event, $eventId, $successes, $fails, $eventModel, $server, $user, $jobId, $force);
            }
        } else {
            // error
            $fails[$eventId] = __('failed downloading the event');
        }
        return true;
    }

    public function pull($user, $id = null, $technique=false, $server, $jobId = false, $force = false)
    {
        if ($jobId) {
            $job = ClassRegistry::init('Job');
            $job->read(null, $jobId);
            $email = "Scheduled job";
        } else {
            $email = $user['email'];
        }
        $server['Server']['version'] = $this->getRemoteVersion($id);
        $pulledClusters = 0;
        if (!empty($server['Server']['pull_galaxy_clusters'])) {
            $this->GalaxyCluster = ClassRegistry::init('GalaxyCluster');
            if ($jobId) {
                $job->saveField('message', $technique == 'pull_relevant_clusters' ? __('Pulling relevant galaxy clusters.') : __('Pulling galaxy clusters.'));
            }
            $pulledClusters = $this->GalaxyCluster->pullGalaxyClusters($user, $server, $technique);
            if ($technique == 'pull_relevant_clusters') {
                if ($jobId) {
                    $job->saveField('progress', 100);
                    $job->saveField('message', 'Pulling complete.');
                }
                return array(array(), array(), 0, 0, $pulledClusters);
            }
            if ($jobId) {
                $job->saveField('progress', 10);
                $job->saveField('message', 'Pulling events.');
            }
        }
        $eventModel = ClassRegistry::init('Event');
        $eventIds = $this->__getEventIdListBasedOnPullTechnique($technique, $server, $force);
        if (!empty($eventIds['error'])) {
            $errors = array(
                '1' => __('Not authorised. This is either due to an invalid auth key, or due to the sync user not having authentication permissions enabled on the remote server. Another reason could be an incorrect sync server setting.'),
                '2' => $eventIds['error'][1],
                '3' => __('Sorry, this is not yet implemented'),
                '4' => __('Something went wrong while trying to pull')
            );
            $this->Log = ClassRegistry::init('Log');
            $this->Log->create();
            $this->Log->save(array(
                'org' => $user['Organisation']['name'],
                'model' => 'Server',
                'model_id' => $id,
                'email' => $user['email'],
                'action' => 'error',
                'user_id' => $user['id'],
                'title' => 'Failed pull from ' . $server['Server']['url'] . ' initiated by ' . $email,
                'change' => !empty($errors[$eventIds['error'][0]]) ? $errors[$eventIds['error'][0]] : __('Unknown issue.')
            ));
            return !empty($errors[$eventIds['error'][0]]) ? $errors[$eventIds['error'][0]] : __('Unknown issue.');
        }
        $successes = array();
        $fails = array();
        // now process the $eventIds to pull each of the events sequentially
        if (!empty($eventIds)) {
            // download each event
            if ($jobId) {
                $job->saveProgress($jobId, __n('Pulling %s event.', 'Pulling %s events.', count($eventIds), count($eventIds)));
            }
            foreach ($eventIds as $k => $eventId) {
                $this->__pullEvent($eventId, $successes, $fails, $eventModel, $server, $user, $jobId, $force);
                if ($jobId) {
                    if ($k % 10 == 0) {
                        $job->saveProgress($jobId, null, 10 + 40 * (($k + 1) / count($eventIds)));
                    }
                }
            }
        }
        if (!empty($fails)) {
            $this->Log = ClassRegistry::init('Log');
            foreach ($fails as $eventid => $message) {
                $this->Log->create();
                $this->Log->save(array(
                    'org' => $user['Organisation']['name'],
                    'model' => 'Server',
                    'model_id' => $id,
                    'email' => $user['email'],
                    'action' => 'pull',
                    'user_id' => $user['id'],
                    'title' => 'Failed to pull event #' . $eventid . '.',
                    'change' => 'Reason: ' . $message
                ));
            }
        }
        if ($jobId) {
            $job->saveProgress($jobId, 'Pulling proposals.', 50);
        }
        $pulledProposals = $eventModel->ShadowAttribute->pullProposals($user, $server);

        if ($jobId) {
            $job->saveProgress($jobId, 'Pulling sightings.', 75);
        }
        $pulledSightings = $eventModel->Sighting->pullSightings($user, $server);

        if ($jobId) {
            $job->saveProgress($jobId, 'Pull completed.', 100);
        }
        $this->Log = ClassRegistry::init('Log');
        $this->Log->create();
        $this->Log->save(array(
            'org' => $user['Organisation']['name'],
            'model' => 'Server',
            'model_id' => $id,
            'email' => $user['email'],
            'action' => 'pull',
            'user_id' => $user['id'],
            'title' => 'Pull from ' . $server['Server']['url'] . ' initiated by ' . $email,
            'change' => sprintf(
                '%s events, %s proposals, %s sightings and %s galaxyClusters pulled or updated. %s events failed or didn\'t need an update.',
                count($successes),
                $pulledProposals,
                $pulledSightings,
                $pulledClusters,
                count($fails)
            )
        ));
        return array($successes, $fails, $pulledProposals, $pulledSightings, $pulledClusters);
    }

    public function filterRuleToParameter($filter_rules)
    {
        $final = array();
        if (empty($filter_rules)) {
            return $final;
        }
        $filter_rules = $this->jsonDecode($filter_rules);
        $url_params = array();
        foreach ($filter_rules as $field => $rules) {
            $temp = array();
            if ($field === 'url_params') {
                $url_params = empty($rules) ? [] : $this->jsonDecode($rules);
            } else {
                foreach ($rules as $operator => $elements) {
                    foreach ($elements as $k => $element) {
                        if ($operator === 'NOT') {
                            $element = '!' . $element;
                        }
                        if (!empty($element)) {
                            $temp[] = $element;
                        }
                    }
                }
                if (!empty($temp)) {
                    $final[substr($field, 0, strlen($field) -1)] = $temp;
                }
            }
        }
        if (!empty($url_params)) {
            $final = array_merge_recursive($final, $url_params);
        }
        return $final;
    }

    /**
     * @param HttpSocket $HttpSocket
     * @param array $request
     * @param array $server
     * @param array $filterRules
     * @return array
     * @throws JsonException
     */
    private function __orgRuleDowngrade(HttpSocket $HttpSocket, array $request, array $server, array $filterRules)
    {
        $uri = $server['Server']['url'] . '/servers/getVersion';
        $version_response = $HttpSocket->get($uri, false, $request);
        $version = $this->jsonDecode($version_response->body)['version'];
        $version = explode('.', $version);
        if ($version[0] <= 2 && $version[1] <= 4 && $version[0] <= 123) {
            $filterRules['org'] = implode('|', $filterRules['org']);
        }
        return $filterRules;
    }

    /**
     * fetchCustomClusterIdsFromServer Fetch custom-published remote clusters' UUIDs and versions
     *
     * @param  array $server
     * @param  mixed $HttpSocket
     * @param  array $conditions
     * @return mixed The list of clusters or the error
     */
    public function fetchCustomClusterIdsFromServer(array $server, $HttpSocket=null, array $conditions=array())
    {
        $url = $server['Server']['url'];
        $HttpSocket = $this->setupHttpSocket($server, $HttpSocket);
        $request = $this->setupSyncRequest($server);
        $uri = $url . '/galaxy_clusters/restSearch';
        $filterRules['published'] = 1;
        $filterRules['minimal'] = 1;
        $filterRules['custom'] = 1;
        $filterRules = array_merge($filterRules, $conditions);
        try {
            $response = $HttpSocket->post($uri, json_encode($filterRules), $request);
            if ($response->isOk()) {
                $clusterArray = json_decode($response->body, true);
                if (isset($clusterArray['response'])) {
                    $clusterArray = $clusterArray['response'];
                }
                return $clusterArray;
            }

            if ($response->code == '403') {
                return 403;
            }
        } catch (SocketException $e) {
            return $e->getMessage();
        }

        // error, so return error message, since that is handled and everything is expecting an array
        return __('Error: got response code %s', $response->code);
    }

    /**
     * getElligibleClusterIdsFromServerForPull Get a list of cluster IDs that are present on the remote server and returns clusters that should be pulled
     *
     * @param  array $server
     * @param  mixed $HttpSocket
     * @param  bool  $onlyUpdateLocalCluster If set to true, only cluster present locally will be returned
     * @param  array $elligibleClusters Array of cluster present locally that could potentially be updated. Linked to $onlyUpdateLocalCluster 
     * @param  array $conditions Conditions to be sent to the remote server while fetching accessible clusters IDs
     * @return array List of cluster IDs to be pulled
     */
    public function getElligibleClusterIdsFromServerForPull(array $server, $HttpSocket=null, $onlyUpdateLocalCluster=true, array $elligibleClusters=array(), array $conditions=array())
    {
        $clusterArray = $this->fetchCustomClusterIdsFromServer($server, $HttpSocket=null, $conditions=$conditions);
        if (!empty($clusterArray)) {
            foreach ($clusterArray as $cluster) {
                if (isset($elligibleClusters[$cluster['GalaxyCluster']['uuid']])) {
                    $localVersion = $elligibleClusters[$cluster['GalaxyCluster']['uuid']];
                    if ($localVersion >= $cluster['GalaxyCluster']['version']) {
                        unset($elligibleClusters[$cluster['GalaxyCluster']['uuid']]);
                    }
                } else {
                    if ($onlyUpdateLocalCluster) {
                        unset($elligibleClusters[$cluster['GalaxyCluster']['uuid']]);
                    } else {
                        $elligibleClusters[$cluster['GalaxyCluster']['uuid']] = true;
                    }
                }
            }
            return array_keys($elligibleClusters);
        }
        return $clusterArray;
    }

    // Get an array of cluster_ids that are present on the remote server and returns clusters that should be pushed
    public function getElligibleClusterIdsFromServerForPush($server, $HttpSocket=null, $localClusters=array(), $conditions=array())
    {
        $clusterArray = $this->fetchCustomClusterIdsFromServer($server, $HttpSocket=null, $conditions=$conditions);
        $keyedClusterArray = Hash::combine($clusterArray, '{n}.GalaxyCluster.uuid', '{n}.GalaxyCluster.version');
        if (!empty($localClusters)) {
            foreach ($localClusters as $k => $localCluster) {
                if (isset($keyedClusterArray[$localCluster['GalaxyCluster']['uuid']])) {
                    $remoteVersion = $keyedClusterArray[$localCluster['GalaxyCluster']['uuid']];
                    if ($localCluster['GalaxyCluster']['version'] <= $remoteVersion) {
                        unset($localClusters[$k]);
                    }
                }
            }
        }
        return $localClusters;
    }

    /**
     * Get an array of event UUIDs that are present on the remote server.
     *
     * @param array $server
     * @param bool $all
     * @param HttpSocket|null $HttpSocket
     * @param bool $ignoreFilterRules
     * @param string $scope 'events' or 'sightings'
     * @param bool $force
     * @return array Array of event UUIDs.
     * @throws JsonException
     * @throws InvalidArgumentException
     */
    public function getEventIdsFromServer(array $server, $all = false, HttpSocket $HttpSocket = null, $ignoreFilterRules = false, $scope = 'events', $force = false)
    {
        if (!in_array($scope, array('events', 'sightings'))) {
            throw new InvalidArgumentException("Scope mus be 'events' or 'sightings', '$scope' given.");
        }

        if ($ignoreFilterRules) {
            $filterRules = array();
        } else {
            $filterRules = $this->filterRuleToParameter($server['Server']['pull_rules']);
        }

        $HttpSocket = $this->setupHttpSocket($server, $HttpSocket);
        $request = $this->setupSyncRequest($server);
        if (!empty($filterRules['org'])) {
            $filterRules = $this->__orgRuleDowngrade($HttpSocket, $request, $server, $filterRules);
        }
        $filterRules['minimal'] = 1;
        $filterRules['published'] = 1;

        $uri = $server['Server']['url'] . '/events/index';
        $response = $HttpSocket->post($uri, json_encode($filterRules), $request);
        if ($response === false) {
            throw new Exception("Could not reach '$uri'.");
        }
        if (!$response->isOk()) {
            throw new HttpException("Fetching the '$uri' failed with HTTP error {$response->code}: {$response->reasonPhrase}", intval($response->code));
        }

        $eventArray = $this->jsonDecode($response->body);
        // correct $eventArray if just one event
        if (isset($eventArray['id'])) {
            $eventArray = array($eventArray);
        }
        if ($all) {
            if ($scope === 'sightings') {
                $this->Event = ClassRegistry::init('Event');
                $localEvents = $this->Event->find('list', array(
                    'recursive' => -1,
                    'fields' => array('Event.uuid', 'Event.sighting_timestamp'),
                    'conditions' => array('Event.uuid' => array_column($eventArray, 'uuid'))
                ));

                $eventUuids = array();
                foreach ($eventArray as $event) {
                    if (!isset($localEvents[$event['uuid']]) && $localEvents[$event['uuid']] > $event['sighting_timestamp']) {
                        $eventUuids[] = $event['uuid'];
                    }
                }
            } else {
                $eventUuids = array_column($eventArray, 'uuid');
            }
        } else {
            if (Configure::read('MISP.enableEventBlocklisting') !== false) {
                $this->EventBlocklist = ClassRegistry::init('EventBlocklist');
                $blocklistHits = $this->EventBlocklist->find('list', array(
                    'recursive' => -1,
                    'conditions' => array('EventBlocklist.event_uuid' => array_column($eventArray, 'uuid')),
                    'fields' => array('EventBlocklist.event_uuid', 'EventBlocklist.event_uuid'),
                ));
                foreach ($eventArray as $k => $event) {
                    if (isset($blocklistHits[$event['uuid']])) {
                        unset($eventArray[$k]);
                    }
                }
            }

            if (Configure::read('MISP.enableOrgBlocklisting') !== false) {
                $this->OrgBlocklist = ClassRegistry::init('OrgBlocklist');
                $blocklistHits = $this->OrgBlocklist->find('list', array(
                    'recursive' => -1,
                    'conditions' => array('OrgBlocklist.org_uuid' => array_unique(array_column($eventArray, 'orgc_uuid'))),
                    'fields' => array('OrgBlocklist.org_uuid', 'OrgBlocklist.org_uuid'),
                ));
                foreach ($eventArray as $k => $event) {
                    if (isset($blocklistHits[$event['orgc_uuid']])) {
                        unset($eventArray[$k]);
                    }
                }
            }

            foreach ($eventArray as $k => $event) {
                if (1 != $event['published']) {
                    unset($eventArray[$k]); // do not keep non-published events
                }
            }
            if (!$force) {
                $this->Event = ClassRegistry::init('Event');
                $this->Event->removeOlder($eventArray, $scope);
            }
            $eventUuids = array_column($eventArray, 'uuid');
        }
        return $eventUuids;
    }

    /**
     * @param int $id Server ID
     * @param string|int $technique Can be 'full', 'incremental' or event ID
     * @param int|false $jobId
     * @param HttpSocket $HttpSocket
     * @param array $user
     * @return array|bool
     * @throws Exception
     */
    public function push($id, $technique, $jobId = false, $HttpSocket, array $user)
    {
        if ($jobId) {
            $job = ClassRegistry::init('Job');
        }
        $server = $this->find('first', ['conditions' => ['Server.id' => $id]]);
        if (!$server) {
            throw new NotFoundException('Server not found');
        }
        $this->Event = ClassRegistry::init('Event');
        $url = $server['Server']['url'];
        $push = $this->checkVersionCompatibility($id, $user);
        if (is_array($push) && !$push['canPush'] && !$push['canSight']) {
            $push = 'Remote instance is outdated or no permission to push.';
        }
        if (!is_array($push)) {
            $message = __('Push to server %s failed. Reason: %s', $id, $push);
            $this->Log = ClassRegistry::init('Log');
            $this->Log->create();
            $this->Log->save(array(
                    'org' => $user['Organisation']['name'],
                    'model' => 'Server',
                    'model_id' => $id,
                    'email' => $user['email'],
                    'action' => 'error',
                    'user_id' => $user['id'],
                    'title' => 'Failed: Push to ' . $url . ' initiated by ' . $user['email'],
                    'change' => $message
            ));
            if ($jobId) {
                $job->saveStatus($jobId, false, $message);
            }
            return $push;
        }

        // sync events if user is capable and server is configured for push
        if ($push['canPush'] && $server['Server']['push']) {
            $successes = array();
            if ("full" == $technique) {
                $eventid_conditions_key = 'Event.id >';
                $eventid_conditions_value = 0;
            } elseif ("incremental" == $technique) {
                $eventid_conditions_key = 'Event.id >';
                $eventid_conditions_value = $server['Server']['lastpushedid'];
            } elseif (intval($technique) !== 0) {
                $eventid_conditions_key = 'Event.id';
                $eventid_conditions_value = intval($technique);
            } else {
                throw new InvalidArgumentException("Technique parameter must be 'full', 'incremental' or event ID.");
            }

            // sync custom galaxy clusters if user is capable
            if ($push['canEditGalaxyCluster'] && $server['Server']['push_galaxy_clusters'] && "full" == $technique) {
                $clustersSuccesses = $this->syncGalaxyClusters($HttpSocket, $this->data, $user, $technique='full');
            } else {
                $clustersSuccesses = array();
            }
            $successes = array_merge($successes, $clustersSuccesses);

            $sgs = $this->Event->SharingGroup->find('all', array(
                'recursive' => -1,
                'contain' => array('Organisation', 'SharingGroupOrg' => array('Organisation'), 'SharingGroupServer')
            ));
            $sgIds = array();
            foreach ($sgs as $sg) {
                if ($this->Event->SharingGroup->checkIfServerInSG($sg, $server)) {
                    $sgIds[] = $sg['SharingGroup']['id'];
                }
            }
            if (empty($sgIds)) {
                $sgIds = array(-1);
            }
            $tableName = $this->Event->EventReport->table;
            $eventReportQuery = sprintf('EXISTS (SELECT id, deleted FROM %s WHERE %s.event_id = Event.id and %s.deleted = 0)', $tableName, $tableName, $tableName);
            $findParams = array(
                    'conditions' => array(
                            $eventid_conditions_key => $eventid_conditions_value,
                            'Event.published' => 1,
                            'OR' => array(
                                array('Event.attribute_count >' => 0),
                                array($eventReportQuery),
                            ),
                            'OR' => array(
                                array(
                                    'AND' => array(
                                        array('Event.distribution >' => 0),
                                        array('Event.distribution <' => 4),
                                    ),
                                ),
                                array(
                                    'AND' => array(
                                        'Event.distribution' => 4,
                                        'Event.sharing_group_id' => $sgIds
                                    ),
                                )
                            )
                    ), // array of conditions
                    'recursive' => -1, //int
                    'contain' => array('EventTag' => array('fields' => array('EventTag.tag_id'))),
                    'fields' => array('Event.id', 'Event.timestamp', 'Event.sighting_timestamp', 'Event.uuid', 'Event.orgc_id'), // array of field names
            );
            $eventIds = $this->Event->find('all', $findParams);
            $eventUUIDsFiltered = $this->getEventIdsForPush($id, $HttpSocket, $eventIds, $user);
            if (!empty($eventUUIDsFiltered)) {
                $eventCount = count($eventUUIDsFiltered);
                // now process the $eventIds to push each of the events sequentially
                $fails = array();
                foreach ($eventUUIDsFiltered as $k => $eventUuid) {
                    $params = array();
                    if (!empty($server['Server']['push_rules'])) {
                        $push_rules = json_decode($server['Server']['push_rules'], true);
                        if (!empty($push_rules['tags']['NOT'])) {
                            $params['blockedAttributeTags'] = $push_rules['tags']['NOT'];
                        }
                    }
                    $params = array_merge($params, array(
                        'event_uuid' => $eventUuid,
                        'includeAttachments' => true,
                        'includeAllTags' => true,
                        'deleted' => array(0,1),
                        'excludeGalaxy' => 1
                    ));
                    if (empty($server['Server']['push_sightings'])) {
                        $params = array_merge($params, array(
                            'noSightings' => 1
                        ));
                    }
                    $event = $this->Event->fetchEvent($user, $params);
                    $event = $event[0];
                    $event['Event']['locked'] = 1;
                    if ($push['canEditGalaxyCluster'] && $server['Server']['push_galaxy_clusters'] && "full" != $technique) {
                        $clustersSuccesses = $this->syncGalaxyClusters($HttpSocket, $this->data, $user, $technique=$event['Event']['id'], $event=$event);
                    } else {
                        $clustersSuccesses = array();
                    }
                    $result = $this->Event->uploadEventToServer($event, $server, $HttpSocket);
                    if ('Success' === $result) {
                        $successes[] = $event['Event']['id'];
                    } else {
                        $fails[$event['Event']['id']] = $result;
                    }
                    if ($jobId && $k % 10 == 0) {
                        $job->saveProgress($jobId, null, 100 * $k / $eventCount);
                    }
                }
                if (count($fails) > 0) {
                    // there are fails, take the lowest fail
                    $lastpushedid = min(array_keys($fails));
                } else {
                    // no fails, take the highest success
                    $lastpushedid = max($successes);
                }
                // increment lastid based on the highest ID seen
                // Save the entire Server data instead of just a single field, so that the logger can be fed with the extra fields.
                $server['Server']['lastpushedid'] = $lastpushedid;
                $this->save($server);
            }
            $this->syncProposals($HttpSocket, $server, null, null, $this->Event);
        }

        if ($push['canPush'] || $push['canSight']) {
            $sightingSuccesses = $this->syncSightings($HttpSocket, $server, $user, $this->Event);
        } else {
            $sightingSuccesses = array();
        }

        if (!isset($successes)) {
            $successes = $sightingSuccesses;
        } else {
            $successes = array_merge($successes, $sightingSuccesses);
        }
        if (!isset($fails)) {
            $fails = array();
        }

        $this->Log = ClassRegistry::init('Log');
        $this->Log->create();
        $this->Log->save(array(
                'org' => $user['Organisation']['name'],
                'model' => 'Server',
                'model_id' => $id,
                'email' => $user['email'],
                'action' => 'push',
                'user_id' => $user['id'],
                'title' => 'Push to ' . $url . ' initiated by ' . $user['email'],
                'change' => count($successes) . ' events pushed or updated. ' . count($fails) . ' events failed or didn\'t need an update.'
        ));
        if ($jobId) {
            $job->saveStatus($jobId, true, __('Push to server %s complete.', $id));
        } else {
            return array($successes, $fails);
        }
        return true;
    }

    public function getEventIdsForPush($id, $HttpSocket, $eventIds, $user)
    {
        $server = $this->read(null, $id);
        $this->Event = ClassRegistry::init('Event');

        foreach ($eventIds as $k => $event) {
            if (empty($this->eventFilterPushableServers($event, array($server)))) {
                unset($eventIds[$k]);
                continue;
            }
            unset($eventIds[$k]['Event']['id']);
        }
        $HttpSocket = $this->setupHttpSocket($server, $HttpSocket);
        $request = $this->setupSyncRequest($server);
        $data = json_encode($eventIds);
        $uri = $server['Server']['url'] . '/events/filterEventIdsForPush';
        $response = $HttpSocket->post($uri, $data, $request);
        if ($response->code == '200') {
            $uuidList = json_decode($response->body());
        } else {
            return false;
        }
        return $uuidList;
    }
    
    /**
     * syncGalaxyClusters Push elligible clusters depending on the provided technique
     *
     * @param  mixed $HttpSocket
     * @param  array $server
     * @param  array $user
     * @param  string|int $technique Either the 'full' string or the event id
     * @param  bool  $event
     * @return array List of successfully pushed clusters
     */
    public function syncGalaxyClusters($HttpSocket, array $server, array $user, $technique='full', $event=false)
    {
        $successes = array();
        if (!$server['Server']['push_galaxy_clusters']) {
            return $successes;
        }
        $this->GalaxyCluster = ClassRegistry::init('GalaxyCluster');
        $this->Event = ClassRegistry::init('Event');
        $HttpSocket = $this->setupHttpSocket($server, $HttpSocket);
        $clusters = array();
        if ($technique == 'full') {
            $clusters = $this->GalaxyCluster->getElligibleClustersToPush($user, $conditions=array(), $full=true);
        } else {
            if ($event === false) { // The event from which the cluster should be taken must be provided
                return $successes;
            }
            $tagNames = $this->Event->extractAllTagNames($event);
            if (!empty($tagNames)) {
                $clusters = $this->GalaxyCluster->getElligibleClustersToPush($user, $conditions=array('GalaxyCluster.tag_name' => $tagNames), $full=true);
            }
        }
        $localClusterUUIDs = Hash::extract($clusters, '{n}.GalaxyCluster.uuid');
        $clustersToPush = $this->getElligibleClusterIdsFromServerForPush($server, $HttpSocket=$HttpSocket, $localClusters=$clusters, $conditions=array('uuid' => $localClusterUUIDs));
        foreach ($clustersToPush as $k => $cluster) {
            $result = $this->GalaxyCluster->uploadClusterToServer($cluster, $server, $HttpSocket, $user);
            if ($result === 'Success') {
                $successes[] = __('GalaxyCluster %s', $cluster['GalaxyCluster']['uuid']);
            }
        }
        return $successes;
    }

    public function syncSightings($HttpSocket, $server, $user, $eventModel)
    {
        $successes = array();
        if (!$server['Server']['push_sightings']) {
            return $successes;
        }
        $this->Sighting = ClassRegistry::init('Sighting');
        $HttpSocket = $this->setupHttpSocket($server, $HttpSocket);
        try {
            $eventIds = $this->getEventIdsFromServer($server, true, $HttpSocket, true, 'sightings');
        } catch (Exception $e) {
            $this->logException("Could not fetch event IDs from server {$server['Server']['name']}", $e);
            return $successes;
        }
        // now process the $eventIds to push each of the events sequentially
        // check each event and push sightings when needed
        foreach ($eventIds as $k => $eventId) {
            $event = $eventModel->fetchEvent($user, $options = array('event_uuid' => $eventId, 'metadata' => true));
            if (!empty($event)) {
                $event = $event[0];
                $event['Sighting'] = $this->Sighting->attachToEvent($event, $user, null, false, true);
                $result = $eventModel->uploadEventToServer($event, $server, $HttpSocket, 'sightings');
                if ($result === 'Success') {
                    $successes[] = 'Sightings for event ' .  $event['Event']['id'];
                }
            }
        }
        return $successes;
    }

    public function syncProposals($HttpSocket, array $server, $sa_id = null, $event_id = null, $eventModel)
    {
        $saModel = ClassRegistry::init('ShadowAttribute');
        $HttpSocket = $this->setupHttpSocket($server, $HttpSocket);
        if ($sa_id == null) {
            if ($event_id == null) {
                // event_id is null when we are doing a push
                try {
                    $ids = $this->getEventIdsFromServer($server, true, $HttpSocket, true);
                } catch (Exception $e) {
                    $this->logException("Could not fetch event IDs from server {$server['Server']['name']}", $e);
                    return false;
                }
                $conditions = array('uuid' => $ids);
            } else {
                $conditions = array('id' => $event_id);
                // event_id is not null when we are doing a publish
            }
            $events = $eventModel->find('all', array(
                    'conditions' => $conditions,
                    'recursive' => 1,
                    'contain' => 'ShadowAttribute',
                    'fields' => array('Event.uuid')
            ));

            $fails = 0;
            $success = 0;
            $error_message = "";
            foreach ($events as $k => &$event) {
                if (!empty($event['ShadowAttribute'])) {
                    foreach ($event['ShadowAttribute'] as &$sa) {
                        $sa['data'] = $saModel->base64EncodeAttachment($sa);
                        unset($sa['id']);
                        unset($sa['value1']);
                        unset($sa['value2']);
                    }

                    $data = json_encode($event['ShadowAttribute']);
                    $request = $this->setupSyncRequest($server);
                    $uri = $server['Server']['url'] . '/events/pushProposals/' . $event['Event']['uuid'];
                    $response = $HttpSocket->post($uri, $data, $request);
                    if ($response->code == '200') {
                        $result = json_decode($response->body(), true);
                        if ($result['success']) {
                            $success += intval($result['counter']);
                        } else {
                            $fails++;
                            if ($error_message == "") {
                                $result['message'];
                            } else {
                                $error_message .= " --- " . $result['message'];
                            }
                        }
                    } else {
                        $fails++;
                    }
                }
            }
        } else {
            // connect to checkuuid($uuid)
            $request = $this->setupSyncRequest($server);
            $uri = $server['Server']['url'] . '/events/checkuuid/' . $sa_id;
            $response = $HttpSocket->get($uri, '', $request);
            if ($response->code != '200') {
                return false;
            }
        }
        return true;
    }

    public function getCurrentServerSettings()
    {
        $this->Module = ClassRegistry::init('Module');
        $serverSettings = $this->serverSettings;
        $moduleTypes = array('Enrichment', 'Import', 'Export', 'Cortex');
        $serverSettings = $this->readModuleSettings($serverSettings, $moduleTypes);
        return $serverSettings;
    }

    private function readModuleSettings($serverSettings, $moduleTypes)
    {
        $this->Module = ClassRegistry::init('Module');
        foreach ($moduleTypes as $moduleType) {
            if (Configure::read('Plugin.' . $moduleType . '_services_enable')) {
                $results = $this->Module->getModuleSettings($moduleType);
                foreach ($results as $module => $data) {
                    foreach ($data as $result) {
                        $setting = array('level' => 1, 'errorMessage' => '');
                        if ($result['type'] == 'boolean') {
                            $setting['test'] = 'testBool';
                            $setting['type'] = 'boolean';
                            $setting['description'] = __('Enable or disable the %s module.', $module);
                            $setting['value'] = false;
                        } elseif ($result['type'] == 'orgs') {
                            $setting['description'] = __('Restrict the %s module to the given organisation.', $module);
                            $setting['value'] = 0;
                            $setting['test'] = 'testLocalOrg';
                            $setting['type'] = 'numeric';
                            $setting['optionsSource'] = 'LocalOrgs';
                        } else {
                            $setting['test'] = 'testForEmpty';
                            $setting['type'] = 'string';
                            $setting['description'] = isset($result['description']) ? $result['description'] : __('Set this required module specific setting.');
                            $setting['value'] = '';
                        }
                        $serverSettings['Plugin'][$moduleType . '_' . $module . '_' .  $result['name']] = $setting;
                    }
                }
            }
        }
        return $serverSettings;
    }

    private function __serverSettingsRead($serverSettings, $currentSettings)
    {
        foreach ($serverSettings as $branchKey => &$branchValue) {
            if (isset($branchValue['branch'])) {
                foreach ($branchValue as $leafKey => &$leafValue) {
                    if ($leafKey !== 'branch' && $leafValue['level'] == 3 && !(isset($currentSettings[$branchKey][$leafKey]))) {
                        continue;
                    }
                    $setting = null;
                    if (isset($currentSettings[$branchKey][$leafKey])) {
                        $setting = $currentSettings[$branchKey][$leafKey];
                    }
                    $leafValue = $this->__evaluateLeaf($leafValue, $leafKey, $setting);
                    if ($leafKey != 'branch') {
                        if ($branchKey == 'Plugin') {
                            $pluginData = explode('_', $leafKey);
                            $leafValue['subGroup'] = $pluginData[0];
                        }
                        if (strpos($branchKey, 'Secur') === 0) {
                            $leafValue['tab'] = 'Security';
                        } else {
                            $leafValue['tab'] = $branchKey;
                        }
                        $finalSettingsUnsorted[$branchKey . '.' . $leafKey] = $leafValue;
                    }
                }
            } else {
                $setting = null;
                if (isset($currentSettings[$branchKey])) {
                    $setting = $currentSettings[$branchKey];
                }
                $branchValue = $this->__evaluateLeaf($branchValue, $branchKey, $setting);
                $branchValue['tab'] = 'misc';
                $finalSettingsUnsorted[$branchKey] = $branchValue;
            }
        }
        return $finalSettingsUnsorted;
    }

    private function __sortFinalSettings($finalSettingsUnsorted)
    {
        $finalSettings = array();
        for ($i = 0; $i < 4; $i++) {
            foreach ($finalSettingsUnsorted as $k => $s) {
                $s['setting'] = $k;
                if ($s['level'] == $i) {
                    $finalSettings[] = $s;
                }
            }
        }
        return $finalSettings;
    }

    public function serverSettingsRead($unsorted = false)
    {
        $this->Module = ClassRegistry::init('Module');
        $serverSettings = $this->getCurrentServerSettings();
        $currentSettings = Configure::read();
        if (Configure::read('Plugin.Enrichment_services_enable')) {
            $this->readModuleSettings($serverSettings, array('Enrichment'));
        }
        $finalSettingsUnsorted = $this->__serverSettingsRead($serverSettings, $currentSettings);
        foreach ($finalSettingsUnsorted as $key => $temp) {
            if (in_array($temp['tab'], array_keys($this->__settingTabMergeRules))) {
                $finalSettingsUnsorted[$key]['tab'] = $this->__settingTabMergeRules[$temp['tab']];
            }
        }
        if ($unsorted) {
            return $finalSettingsUnsorted;
        }
        return $this->__sortFinalSettings($finalSettingsUnsorted);
    }

    public function serverSettingReadSingle($settingObject, $settingName, $leafKey)
    {
        // invalidate config.php from php opcode cache
        if (function_exists('opcache_reset')) {
            opcache_reset();
        }

        $setting = Configure::read($settingName);
        $result = $this->__evaluateLeaf($settingObject, $leafKey, $setting);
        $result['setting'] = $settingName;
        return $result;
    }

    private function __evaluateLeaf($leafValue, $leafKey, $setting)
    {
        if (isset($setting)) {
            if (!empty($leafValue['test'])) {
                $result = $this->{$leafValue['test']}($setting, empty($leafValue['errorMessage']) ? false : $leafValue['errorMessage']);
                if ($result !== true) {
                    $leafValue['error'] = 1;
                    if ($result !== false) {
                        $leafValue['errorMessage'] = $result;
                    }
                }
            }
            if ($setting !== '') {
                $leafValue['value'] = $setting;
            }
        } else {
            if ($leafKey != 'branch' && (!isset($leafValue['null']) || !$leafValue['null'])) {
                $leafValue['error'] = 1;
                $leafValue['errorMessage'] = __('Value not set.');
            }
        }
        return $leafValue;
    }

    public function loadAvailableLanguages()
    {
        $dirs = glob(APP . 'Locale/*', GLOB_ONLYDIR);
        $languages = array('eng' => 'eng');
        foreach ($dirs as $k => $dir) {
            $dir = str_replace(APP . 'Locale' . DS, '', $dir);
            $languages[$dir] = $dir;
        }
        return $languages;
    }

    public function testLanguage($value)
    {
        $languages = $this->loadAvailableLanguages();
        if (!isset($languages[$value])) {
            return __('Invalid language.');
        }
        return true;
    }

    public function loadTagCollections()
    {
        $this->TagCollection = ClassRegistry::init('TagCollection');
        $user = array('Role' => array('perm_site_admin' => 1));
        $tagCollections = $this->TagCollection->fetchTagCollection($user);
        $options = array(0 => 'None');
        foreach ($tagCollections as $tagCollection) {
            $options[intval($tagCollection['TagCollection']['id'])] = $tagCollection['TagCollection']['name'];
        }
        return $options;
    }

    public function testTagCollections($value)
    {
        $tag_collections = $this->loadTagCollections();
        if (!isset($tag_collections[intval($value)])) {
            return __('Invalid tag_collection.');
        }
        return true;
    }

    public function testForNumeric($value)
    {
        if (!is_numeric($value)) {
            return __('This setting has to be a number.');
        }
        return true;
    }

    public function testForPositiveInteger($value)
    {
        if ((is_int($value) && $value >= 0) || ctype_digit($value)) {
            return true;
        }
        return __('The value has to be a whole number greater or equal 0.');
    }

    public function testForCookieTimeout($value)
    {
        $numeric = $this->testForNumeric($value);
        if ($numeric !== true) {
            return $numeric;
        }
        if ($value < Configure::read('Session.timeout') && $value !== 0) {
            return __('The cookie timeout is currently lower than the session timeout. This will invalidate the cookie before the session expires.');
        }
        return true;
    }

    public function testUuid($value)
    {
        if (empty($value) || !preg_match('/^\{?[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}\}?$/', $value)) {
            return 'Invalid UUID.';
        }
        return true;
    }

    public function testForSessionDefaults($value)
    {
        if (empty($value) || !in_array($value, array('php', 'database', 'cake', 'cache'))) {
            return 'Please choose a valid session handler. Recommended values: php or database. Alternate options are cake (cakephp file based sessions) and cache.';
        } else {
            return true;
        }
    }

    public function testLocalOrg($value)
    {
        $this->Organisation = ClassRegistry::init('Organisation');
        if ($value == 0) {
            return 'No organisation selected';
        }
        $local_orgs = $this->Organisation->find('list', array(
            'conditions' => array('local' => 1),
            'recursive' => -1,
            'fields' => array('Organisation.id', 'Organisation.name')
        ));
        if (in_array($value, array_keys($local_orgs))) {
            return true;
        }
        return 'Invalid organisation';
    }

    public function testForEmpty($value)
    {
        $value = trim($value);
        if ($value === '') {
            return 'Value not set.';
        }
        return true;
    }

    public function testForPath($value)
    {
        if ($value === '') {
            return true;
        }
        if (preg_match('@^\/?(([a-z0-9_.]+[a-z0-9_.\-.\:]*[a-z0-9_.\-.\:]|[a-z0-9_.])+\/?)+$@i', $value)) {
            return true;
        }
        return 'Invalid characters in the path.';
    }

    public function beforeHookBinExec($setting, $value)
    {
        return $this->testForBinExec($value);
    }

    public function testForBinExec($value)
    {
        if (substr($value, 0, 7) === "phar://") {
            return 'Phar protocol not allowed.';
        }
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        if ($value === '') {
            return true;
        }
        if (is_executable($value)) {
            if (finfo_file($finfo, $value) == "application/x-executable" || finfo_file($finfo, $value) == "application/x-sharedlib") {
                finfo_close($finfo);
                return true;
            } else {
                return 'Binary file not executable. It is of type: ' . finfo_file($finfo, $value);
            }
        } else {
            return false;
        }
    }

    public function testForWritableDir($value)
    {
        if (substr($value, 0, 7) === "phar://") {
            return 'Phar protocol not allowed.';
        }
        if (!is_dir($value)) {
            return 'Not a valid directory.';
        }
        if (!is_writeable($value)) {
            return 'Not a writable directory.';
        }
        return true;
    }

    public function testDebug($value)
    {
        if ($this->testForEmpty($value) !== true) {
            return $this->testForEmpty($value);
        }
        if ($this->testForNumeric($value) !== true) {
            return 'This setting has to be a number between 0 and 2, with 0 disabling debug mode.';
        }
        if ($value === 0) {
            return true;
        }
        return 'This setting has to be set to 0 on production systems. Ignore this warning if this is not the case.';
    }

    public function testDebugAdmin($value)
    {
        if ($this->testBool($value) !== true) {
            return 'This setting has to be either true or false.';
        }
        if (!$value) {
            return true;
        }
        return 'Enabling debug is not recommended. Turn this on temporarily if you need to see a stack trace to debug an issue, but make sure this is not left on.';
    }

    public function testDate($date)
    {
        if ($this->testForEmpty($date) !== true) {
            return $this->testForEmpty($date);
        }
        if (!strtotime($date)) {
            return 'The date that you have entered is invalid. Expected: yyyy-mm-dd';
        }
        return true;
    }


    public function getHost()
    {
        if (function_exists('apache_request_headers')) {
            $headers = apache_request_headers();
        } else {
            $headers = $_SERVER;
        }

        if (array_key_exists('X-Forwarded-Host', $headers)) {
            $host = $headers['X-Forwarded-Host'];
        } else {
            $host = $_SERVER['HTTP_HOST'];
        }
        return $host;
    }

    public function getProto()
    {
        if (function_exists('apache_request_headers')) {
            $headers = apache_request_headers();
        } else {
            $headers = $_SERVER;
        }

        if (array_key_exists('X-Forwarded-Proto', $headers)) {
            $proto = $headers['X-Forwarded-Proto'];
        } else {
            $proto = ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || $_SERVER['SERVER_PORT'] == 443) === true ? 'HTTPS' : 'HTTP';
        }
        return $proto;
    }

    public function testBaseURL($value)
    {
        // only run this check via the GUI, via the CLI it won't work
        if (php_sapi_name() == 'cli') {
            if (!empty($value) && !preg_match('/^http(s)?:\/\//i', $value)) {
                return 'Invalid baseurl, please make sure that the protocol is set.';
            }
            return true;
        }
        if ($this->testForEmpty($value) !== true) {
            return $this->testForEmpty($value);
        }
        $regex = "%^(?<proto>https?)://(?<host>(?:(?:\w|-)+\.)+[a-z]{2,})(?::(?<port>[0-9]+))?(?<base>/[a-z0-9_\-\.]+)?$%i";
	if ( !preg_match($regex, $value, $matches)
                || strtolower($matches['proto']) != strtolower($this->getProto())
                || strtolower($matches['host']) != strtolower($this->getHost()) ) {
            return 'Invalid baseurl, it has to be in the "https://FQDN" format.';
        }
        return true;
    }

    public function testURL($value)
    {
        // only run this check via the GUI, via the CLI it won't work
        if (!empty($value) && !preg_match('/^http(s)?:\/\//i', $value)) {
            return 'Invalid baseurl, please make sure that the protocol is set.';
        }
        if ($this->testForEmpty($value) !== true) {
            return $this->testForEmpty($value);
        }
        return true;
    }

    public function testDisableEmail($value)
    {
        if (isset($value) && $value) {
            return 'E-mailing is blocked.';
        }
        return true;
    }

    public function testDisableCache($value)
    {
        if (isset($value) && $value) {
            return 'Export caches are disabled.';
        }
        return true;
    }

    public function testLive($value)
    {
        if ($this->testBool($value) !== true) {
            return $this->testBool($value);
        }
        if (!$value) {
            return 'MISP disabled.';
        }
        return true;
    }

    public function testBool($value, $errorMessage = false)
    {
        if ($value !== true && $value !== false) {
            if ($errorMessage) {
                return $errorMessage;
            }
            return __('Value is not a boolean, make sure that you convert \'true\' to true for example.');
        }
        return true;
    }

    public function testBoolTrue($value, $errorMessage = false)
    {
        if ($this->testBool($value, $errorMessage) !== true) {
            return $this->testBool($value, $errorMessage);
        }
        if ($value === false) {
            if ($errorMessage) {
                return $errorMessage;
            }
            return 'It is highly recommended that this setting is enabled. Make sure you understand the impact of having this setting turned off.';
        } else {
            return true;
        }
    }

    public function testBoolFalse($value, $errorMessage = false)
    {
        if ($this->testBool($value, $errorMessage) !== true) {
            return $this->testBool($value, $errorMessage);
        }
        if ($value !== false) {
            if ($errorMessage) {
                return $errorMessage;
            }
            return 'It is highly recommended that this setting is disabled. Make sure you understand the impact of having this setting turned on.';
        } else {
            return true;
        }
    }

    public function testParanoidSkipDb($value)
    {
        if (!empty(Configure::read('MISP.log_paranoid')) && empty($value)) {
            return 'Perhaps consider skipping the database when using paranoid mode. A great number of entries will be added to your log database otherwise that will lead to performance degradation.';
        }
        return true;
    }

    public function testSalt($value)
    {
        if ($this->testForEmpty($value) !== true) {
            return $this->testForEmpty($value);
        }
        if (strlen($value) < 32) {
            return 'The salt has to be an at least 32 byte long string.';
        }
        if ($value == "Rooraenietu8Eeyo<Qu2eeNfterd-dd+") {
            return 'This is the default salt shipped with the application and is therefore unsecure.';
        }
        return true;
    }

    public function testForTermsFile($value)
    {
        return $this->__testForFile($value, APP . 'files' . DS . 'terms');
    }

    public function testForCABundle($value)
    {
        $file = new File($value);
        if (!$file->exists()) {
            return __('Invalid file path or file not accessible.');
        }
        if ($file->ext() !== 'pem') {
            return __('File has to be in .pem format.');
        }
    }

    public function testForStyleFile($value)
    {
        if (empty($value)) {
            return true;
        }
        return $this->__testForFile($value, APP . 'webroot' . DS . 'css');
    }

    public function testForCustomImage($value)
    {
        return $this->__testForFile($value, APP . 'webroot' . DS . 'img' . DS . 'custom');
    }

    public function testPasswordLength($value)
    {
        $numeric = $this->testForNumeric($value);
        if ($numeric !== true) {
            return $numeric;
        }
        if ($value < 0) {
            return 'Length cannot be negative, set a positive integer or 0 (to choose the default option).';
        }
        return true;
    }

    public function testForPortNumber($value)
    {
        $numeric = $this->testForNumeric($value);
        if ($numeric !== true) {
            return $numeric;
        }
        if ($value < 21 || $value > 65535) {
            return 'Make sure that you pick a valid port number.';
        }
        return true;
    }

    public function testForZMQPortNumber($value)
    {
        $numeric = $this->testForNumeric($value);
        if ($numeric !== true) {
            return $numeric;
        }
        if ($value < 49152 || $value > 65535) {
            return 'It is recommended that you pick a port number in the dynamic range (49152-65535). However, if you have a valid reason to use a different port, ignore this message.';
        }
        return true;
    }

    public function testPasswordRegex($value)
    {
        if (!empty($value) && @preg_match($value, 'test') === false) {
            return 'Invalid regex.';
        }
        return true;
    }

    public function testPasswordResetText($value)
    {
        if (strpos($value, '$password') === false || strpos($value, '$username') === false || strpos($value, '$misp') === false) {
            return 'The text served to the users must include the following replacement strings: "$username", "$password", "$misp"';
        }
        return true;
    }

    public function testForGPGBinary($value)
    {
        if (empty($value)) {
            $value = $this->serverSettings['GnuPG']['binary']['value'];
        }
        if (file_exists($value)) {
            return true;
        }
        return 'Could not find the GnuPG executable at the defined location.';
    }

    public function testForRPZDuration($value)
    {
        if (($this->testForNumeric($value) !== true && preg_match('/^[0-9]*[mhdw]$/i', $value)) || $value >= 0) {
            return true;
        } else {
            return 'Negative seconds found. The following formats are accepted: seconds (positive integer), or duration (positive integer) followed by a letter denoting scale (such as m, h, d, w for minutes, hours, days, weeks)';
        }
    }

    public function testForRPZBehaviour($value)
    {
        $numeric = $this->testForNumeric($value);
        if ($numeric !== true) {
            return $numeric;
        }
        if ($value < 0 || $value > 5) {
            return 'Invalid setting, valid range is 0-5 (0 = DROP, 1 = NXDOMAIN, 2 = NODATA, 3 = walled garden, 4 = PASSTHRU, 5 = TCP-only.';
        }
        return true;
    }

    public function testForSightingVisibility($value)
    {
        $numeric = $this->testForNumeric($value);
        if ($numeric !== true) {
            return $numeric;
        }
        if ($value < 0 || $value > 2) {
            return 'Invalid setting, valid range is 0-2 (0 = Event owner, 1 = Sighting reporters, 2 = Everyone.';
        }
        return true;
    }

    public function sightingsBeforeHook($setting, $value)
    {
        if ($value == true) {
            $this->updateDatabase('addSightings');
        }
        return true;
    }

    public function otpBeforeHook($setting, $value)
    {
        if ($value && !empty(Configure::read('MISP.disable_emailing'))) {
            return __('Emailing is currently disabled. Enabling OTP without e-mailing being configured would lock all users out.');
        }
        return true;
    }

    public function testForRPZSerial($value)
    {
        if ($this->testForEmpty($value) !== true) {
            return $this->testForEmpty($value);
        }
        if (!preg_match('/^((\$date(\d*)|\$time|\d*))$/', $value)) {
            return 'Invalid format.';
        }
        return true;
    }

    public function testForRPZNS($value)
    {
        if ($this->testForEmpty($value) !== true) {
            return $this->testForEmpty($value);
        }
        if (!preg_match('/^\w+(\.\w+)*(\.?) \w+(\.\w+)*$/', $value)) {
            return 'Invalid format.';
        }
        return true;
    }

    public function zmqAfterHook($setting, $value)
    {
        // If we are trying to change the enable setting to false, we don't need to test anything, just kill the server and return true.
        if ($setting === 'Plugin.ZeroMQ_enable') {
            if ($value == false || $value == 0) {
                $this->getPubSubTool()->killService();
                return true;
            }
        } elseif (!Configure::read('Plugin.ZeroMQ_enable')) {
            // If we are changing any other ZeroMQ settings but the feature is disabled, don't reload the service
            return true;
        }
        $this->getPubSubTool()->reloadServer();
        return true;
    }

    public function disableCacheAfterHook($setting, $value)
    {
        if ($value) {
            $this->Event = ClassRegistry::init('Event');
            App::uses('Folder', 'Utility');
            App::uses('File', 'Utility');
            // delete all cache files
            foreach ($this->Event->export_types as $type => $settings) {
                $dir = new Folder(APP . 'tmp/cached_exports/' . $type);
                // No caches created for this type of export, move on
                if ($dir == null) {
                    continue;
                }
                $files = $dir->find('.*' . $settings['extension']);
                foreach ($files as $file) {
                    $file = new File($dir->pwd() . DS . $file);
                    $file->delete();
                    $file->close();
                }
            }
        }
        return true;
    }

    public function correlationAfterHook($setting, $value)
    {
        if (!Configure::read('MISP.background_jobs')) {
            $this->Attribute = ClassRegistry::init('Attribute');
            if ($value) {
                $k = $this->Attribute->purgeCorrelations();
            } else {
                $k = $this->Attribute->generateCorrelation();
            }
        } else {
            if ($value == true) {
                $jobType = 'jobPurgeCorrelation';
                $jobTypeText = 'purge correlations';
            } else {
                $jobType = 'jobGenerateCorrelation';
                $jobTypeText = 'generate correlation';
            }
            $job = ClassRegistry::init('Job');
            $job->create();
            $data = array(
                    'worker' => 'default',
                    'job_type' => $jobTypeText,
                    'job_input' => 'All attributes',
                    'status' => 0,
                    'retries' => 0,
                    'org' => 'ADMIN',
                    'message' => 'Job created.',
            );
            $job->save($data);
            $jobId = $job->id;
            $process_id = CakeResque::enqueue(
                    'default',
                    'AdminShell',
                    array($jobType, $jobId),
                    true
            );
            $job->saveField('process_id', $process_id);
        }
    }

    public function ipLogBeforeHook($setting, $value)
    {
        if ($setting == 'MISP.log_client_ip') {
            if ($value == true) {
                $this->updateDatabase('addIPLogging');
            }
        }
        return true;
    }

    public function customAuthBeforeHook($setting, $value)
    {
        if (!empty($value)) {
            $this->updateDatabase('addCustomAuth');
        }
        $this->cleanCacheFiles();
        return true;
    }

    // never come here directly, always go through a secondary check like testForTermsFile in order to also pass along the expected file path
    private function __testForFile($value, $path)
    {
        if ($this->testForEmpty($value) !== true) {
            return $this->testForEmpty($value);
        }
        if (!$this->checkFilename($value)) {
            return 'Invalid filename.';
        }
        $file = $path . DS . $value;
        if (!file_exists($file)) {
            return 'Could not find the specified file. Make sure that it is uploaded into the following directory: ' . $path;
        }
        return true;
    }

    private function __serverSettingNormaliseValue($data, $value, $setting)
    {
        if (!empty($data['type'])) {
            if ($data['type'] == 'boolean') {
                $value = $value ? true : false;
            } elseif ($data['type'] == 'numeric') {
                $value = intval($value);
            }
        }
        return $value;
    }

    public function getSettingData($setting_name)
    {
        // invalidate config.php from php opcode cache
        if (function_exists('opcache_reset')) {
            opcache_reset();
        }
        if (strpos($setting_name, 'Plugin.Enrichment') !== false || strpos($setting_name, 'Plugin.Import') !== false || strpos($setting_name, 'Plugin.Export') !== false || strpos($setting_name, 'Plugin.Cortex') !== false) {
            $serverSettings = $this->getCurrentServerSettings();
        } else {
            $serverSettings = $this->serverSettings;
        }
        $setting = false;
        foreach ($serverSettings as $k => $s) {
            if (isset($s['branch'])) {
                foreach ($s as $ek => $es) {
                    if ($ek != 'branch') {
                        if ($setting_name == $k . '.' . $ek) {
                            $setting = $es;
                            continue 2;
                        }
                    }
                }
            } else {
                if ($setting_name == $k) {
                    $setting = $s;
                    continue;
                }
            }
        }
        if (!empty($setting)) {
            $setting['name'] = $setting_name;
        }
        return $setting;
    }

    public function serverSettingsEditValue(array $user, array $setting, $value, $forceSave = false)
    {
        if (isset($setting['beforeHook'])) {
            $beforeResult = call_user_func_array(array($this, $setting['beforeHook']), array($setting['name'], $value));
            if ($beforeResult !== true) {
                $this->Log = ClassRegistry::init('Log');
                $this->Log->create();
                $result = $this->Log->save(array(
                        'org' => $user['Organisation']['name'],
                        'model' => 'Server',
                        'model_id' => 0,
                        'email' => $user['email'],
                        'action' => 'serverSettingsEdit',
                        'user_id' => $user['id'],
                        'title' => 'Server setting issue',
                        'change' => 'There was an issue witch changing ' . $setting['name'] . ' to ' . $value  . '. The error message returned is: ' . $beforeResult . 'No changes were made.',
                ));
                return $beforeResult;
            }
        }
        $value = trim($value);
        if ($setting['type'] == 'boolean') {
            $value = ($value ? true : false);
        }
        if ($setting['type'] == 'numeric') {
            $value = intval($value);
        }
        if (!empty($setting['test'])) {
            $testResult = $this->{$setting['test']}($value);
        } else {
            $testResult = true;  # No test defined for this setting: cannot fail
        }
        if (!$forceSave && $testResult !== true) {
            if ($testResult === false) {
                $errorMessage = $setting['errorMessage'];
            } else {
                $errorMessage = $testResult;
            }
            return $errorMessage;
        } else {
            $oldValue = Configure::read($setting['name']);
            $settingSaveResult = $this->serverSettingsSaveValue($setting['name'], $value);

            if ($settingSaveResult) {
                $this->Log = ClassRegistry::init('Log');
                $change = array($setting['name'] => array($oldValue, $value));
                $this->Log->createLogEntry($user, 'serverSettingsEdit', 'Server', 0, 'Server setting changed', $change);

                // execute after hook
                if (isset($setting['afterHook'])) {
                    $afterResult = call_user_func_array(array($this, $setting['afterHook']), array($setting['name'], $value));
                    if ($afterResult !== true) {
                        $change = 'There was an issue after setting a new setting. The error message returned is: ' . $afterResult;
                        $this->Log->createLogEntry($user, 'serverSettingsEdit', 'Server', 0, 'Server setting issue', $change);
                        return $afterResult;
                    }
                }
                return true;
            } else {
                return __('Something went wrong. MISP tried to save a malformed config file. Setting change reverted.');
            }
        }
    }

    public function serverSettingsSaveValue($setting, $value)
    {
        // validate if current config.php is intact:
        $current = file_get_contents(APP . 'Config' . DS . 'config.php');
        $current = trim($current);
        if (strlen($current) < 20) {
            $this->Log = ClassRegistry::init('Log');
            $this->Log->create();
            $this->Log->save(array(
                    'org' => 'SYSTEM',
                    'model' => 'Server',
                    'model_id' => $id,
                    'email' => 'SYSTEM',
                    'action' => 'error',
                    'user_id' => 0,
                    'title' => 'Error: Tried to modify server settings but current config is broken.',
            ));
            return false;
        }
        copy(APP . 'Config' . DS . 'config.php', APP . 'Config' . DS . 'config.php.bk');
        $settingObject = $this->getCurrentServerSettings();
        foreach ($settingObject as $branchName => $branch) {
            if (!isset($branch['level'])) {
                foreach ($branch as $settingName => $settingObject) {
                    if ($setting == $branchName . '.' . $settingName) {
                        $value = $this->__serverSettingNormaliseValue($settingObject, $value, $setting);
                    }
                }
            } else {
                if ($setting == $branchName) {
                    $value = $this->__serverSettingNormaliseValue($branch, $value, $setting);
                }
            }
        }
        Configure::write($setting, $value);
        $arrayFix = array(
            'Security.auth',
            'ApacheSecureAuth.ldapFilter'
        );
        foreach ($arrayFix as $settingFix) {
            if (Configure::read($settingFix) && is_array(Configure::read($settingFix)) && !empty(Configure::read($settingFix))) {
                $arrayElements = array();
                foreach (Configure::read($settingFix) as $array) {
                    if (!in_array($array, $arrayElements)) {
                        $arrayElements[] = $array;
                    }
                }
                Configure::write($settingFix, $arrayElements);
            }
        }
        $settingsToSave = array(
            'debug', 'MISP', 'GnuPG', 'SMIME', 'Proxy', 'SecureAuth',
            'Security', 'Session.defaults', 'Session.timeout', 'Session.cookieTimeout',
            'Session.autoRegenerate', 'Session.checkAgent', 'site_admin_debug',
            'Plugin', 'CertAuth', 'ApacheShibbAuth', 'ApacheSecureAuth'
        );
        $settingsArray = array();
        foreach ($settingsToSave as $setting) {
            $settingsArray[$setting] = Configure::read($setting);
        }
        $settingsString = var_export($settingsArray, true);
        $settingsString = '<?php' . "\n" . '$config = ' . $settingsString . ';';
        if (function_exists('opcache_reset')) {
            opcache_reset();
        }
        if (empty(Configure::read('MISP.server_settings_skip_backup_rotate'))) {
            $randomFilename = $this->generateRandomFileName();
            // To protect us from 2 admin users having a concurent file write to the config file, solar flares and the bogeyman
            file_put_contents(APP . 'Config' . DS . $randomFilename, $settingsString);
            rename(APP . 'Config' . DS . $randomFilename, APP . 'Config' . DS . 'config.php');
            $config_saved = file_get_contents(APP . 'Config' . DS . 'config.php');
            // if the saved config file is empty, restore the backup.
            if (strlen($config_saved) < 20) {
                copy(APP . 'Config' . DS . 'config.php.bk', APP . 'Config' . DS . 'config.php');
                $this->Log = ClassRegistry::init('Log');
                $this->Log->create();
                $this->Log->save(array(
                        'org' => 'SYSTEM',
                        'model' => 'Server',
                        'model_id' => $id,
                        'email' => 'SYSTEM',
                        'action' => 'error',
                        'user_id' => 0,
                        'title' => 'Error: Something went wrong saving the config file, reverted to backup file.',
                ));
                return false;
            }
        } else {
            file_put_contents(APP . 'Config' . DS . 'config.php', $settingsString);
        }
        return true;
    }

    public function checkVersion($newest)
    {
        $version_array = $this->checkMISPVersion();
        $current = 'v' . $version_array['major'] . '.' . $version_array['minor'] . '.' . $version_array['hotfix'];
        $newest_array = $this->__dissectVersion($newest);
        $upToDate = $this->__compareVersions(array($version_array['major'], $version_array['minor'], $version_array['hotfix']), $newest_array, 0);
        return array('current' => $current, 'newest' => $newest, 'upToDate' => $upToDate);
    }

    private function __dissectVersion($version)
    {
        $version = substr($version, 1);
        return explode('.', $version);
    }

    private function __compareVersions($current, $newest, $i)
    {
        if ($current[$i] == $newest[$i]) {
            if ($i < 2) {
                return $this->__compareVersions($current, $newest, $i+1);
            } else {
                return 'same';
            }
        } elseif ($current[$i] < $newest[$i]) {
            return 'older';
        } else {
            return 'newer';
        }
    }

    public function getFileRules()
    {
        $validItems = array(
                'orgs' => array(
                        'name' => __('Organisation logos'),
                        'description' => __('The logo used by an organisation on the event index, event view, discussions, proposals, etc. Make sure that the filename is in the org.png format, where org is the case-sensitive organisation name.'),
                        'expected' => array(),
                        'valid_format' => __('48x48 pixel .png files'),
                        'path' => APP . 'webroot' . DS . 'img' . DS . 'orgs',
                        'regex' => '.*\.(png|PNG)$',
                        'regex_error' => __('Filename must be in the following format: *.png'),
                        'files' => array(),
                ),
                'img' => array(
                        'name' => __('Additional image files'),
                        'description' => __('Image files uploaded into this directory can be used for various purposes, such as for the login page logos'),
                        'expected' => array(
                                'MISP.footer_logo' => Configure::read('MISP.footer_logo'),
                                'MISP.home_logo' => Configure::read('MISP.home_logo'),
                                'MISP.welcome_logo' => Configure::read('MISP.welcome_logo'),
                                'MISP.welcome_logo2' => Configure::read('MISP.welcome_logo2'),
                        ),
                        'valid_format' => __('text/html if served inline, anything that conveys the terms of use if served as download'),
                        'path' => APP . 'webroot' . DS . 'img' . DS . 'custom',
                        'regex' => '.*\.(png|PNG)$',
                        'regex_error' => __('Filename must be in the following format: *.png'),
                        'files' => array(),
                ),
        );
        return $validItems;
    }

    public function grabFiles()
    {
        $validItems = $this->getFileRules();
        App::uses('Folder', 'Utility');
        App::uses('File', 'Utility');
        foreach ($validItems as $k => $item) {
            $dir = new Folder($item['path']);
            $files = $dir->find($item['regex'], true);
            foreach ($files as $file) {
                $f = new File($item['path'] . DS . $file);
                $validItems[$k]['files'][] = array('filename' => $file, 'filesize' => $f->size(), 'read' => $f->readable(), 'write' => $f->writable(), 'execute' => $f->executable());
            }
        }
        return $validItems;
    }

    /**
     * @param array $server
     * @return array
     * @throws JsonException
     */
    public function runConnectionTest(array $server)
    {
        App::uses('SyncTool', 'Tools');
        try {
            $clientCertificate = SyncTool::getServerClientCertificateInfo($server);
            if ($clientCertificate) {
                $clientCertificate['valid_from'] = $clientCertificate['valid_from'] ? $clientCertificate['valid_from']->format('c') : __('Not defined');
                $clientCertificate['valid_to'] = $clientCertificate['valid_to'] ? $clientCertificate['valid_to']->format('c') : __('Not defined');
                $clientCertificate['public_key_size'] = $clientCertificate['public_key_size'] ?: __('Unknwon');
                $clientCertificate['public_key_type'] = $clientCertificate['public_key_type'] ?: __('Unknwon');
            }
        } catch (Exception $e) {
            $clientCertificate = ['error' => $e->getMessage()];
        }

        $HttpSocket = $this->setupHttpSocket($server, null, 5);
        $request = $this->setupSyncRequest($server);
        $uri = $server['Server']['url'] . '/servers/getVersion';

        try {
            $response = $HttpSocket->get($uri, false, $request);
            if ($response === false) {
                throw new Exception("Connection failed for unknown reason.");
            }
        } catch (Exception $e) {
            $logTitle = 'Error: Connection test failed. Reason: ' .  $e->getMessage();
            $this->loadLog()->createLogEntry('SYSTEM', 'error', 'Server', $server['Server']['id'], $logTitle);
            return array('status' => 2, 'client_certificate' => $clientCertificate);
        }

        if ($response->code == '403') {
            return array('status' => 4, 'client_certificate' => $clientCertificate);
        } else if ($response->code == '405') {
            try {
                $responseText = $this->jsonDecode($response->body)['message'];
                if ($responseText === 'Your user account is expecting a password change, please log in via the web interface and change it before proceeding.') {
                    return array('status' => 5, 'client_certificate' => $clientCertificate);
                } elseif ($responseText === 'You have not accepted the terms of use yet, please log in via the web interface and accept them.') {
                    return array('status' => 6, 'client_certificate' => $clientCertificate);
                }
            } catch (Exception $e) {
                // pass
            }
        } else if ($response->isOk()) {
            try {
                $info = $this->jsonDecode($response->body());
                if (!isset($info['version'])) {
                    throw new Exception("Server returns JSON response, but doesn't contain required 'version' field.");
                }
                return array('status' => 1, 'info' => $info, 'client_certificate' => $clientCertificate);
            } catch (Exception $e) {
                // Even if server returns OK status, that doesn't mean that connection to another MISP instance works
            }
        }

        $logTitle = 'Error: Connection test failed. Returned data is in the change field.';
        $this->loadLog()->createLogEntry('SYSTEM', 'error', 'Server', $server['Server']['id'], $logTitle, [
            'response' => ['', $response->body],
            'response-code' => ['', $response->code],
        ]);
        return array('status' => 3, 'client_certificate' => $clientCertificate);
    }

    /**
     * @param array $server
     * @return int
     * @throws JsonException
     */
    public function runPOSTtest(array $server)
    {
        $testFile = file_get_contents(APP . 'files/scripts/test_payload.txt');
        if (!$testFile) {
            throw new Exception("Could not load payload for POST test.");
        }
        $HttpSocket = $this->setupHttpSocket($server);
        $request = $this->setupSyncRequest($server);
        $uri = $server['Server']['url'] . '/servers/postTest';

        try {
            $response = $HttpSocket->post($uri, json_encode(array('testString' => $testFile)), $request);
            $rawBody = $response->body;
            $response = $this->jsonDecode($rawBody);
        } catch (Exception $e) {
            $title = 'Error: POST connection test failed. Reason: ' . $e->getMessage();
            $this->loadLog()->createLogEntry('SYSTEM', 'error', 'Server', $server['Server']['id'], $title);
            return 8;
        }
        if (!isset($response['body']['testString']) || $response['body']['testString'] !== $testFile) {
            if (!empty($repsonse['body']['testString'])) {
                $responseString = $response['body']['testString'];
            } else if (!empty($rawBody)){
                $responseString = $rawBody;
            } else {
                $responseString = __('Response was empty.');
            }

            $title = 'Error: POST connection test failed due to the message body not containing the expected data. Response: ' . PHP_EOL . PHP_EOL . $responseString;
            $this->loadLog()->createLogEntry('SYSTEM', 'error', 'Server', $server['Server']['id'], $title);
            return 9;
        }
        $headers = array('Accept', 'Content-type');
        foreach ($headers as $header) {
            if (!isset($response['headers'][$header]) || $response['headers'][$header] != 'application/json') {
                $responseHeader = isset($response['headers'][$header]) ? $response['headers'][$header] : 'Header was not set.';
                $title = 'Error: POST connection test failed due to a header not matching the expected value. Expected: "application/json", received "' . $responseHeader . '"';
                $this->loadLog()->createLogEntry('SYSTEM', 'error', 'Server', $server['Server']['id'], $title);
                return 10;
            }
        }
        return 1;
    }

    public function checkVersionCompatibility($id, $user = array(), $HttpSocket = false)
    {
        // for event publishing when we don't have a user.
        if (empty($user)) {
            $user = array('Organisation' => array('name' => 'SYSTEM'), 'email' => 'SYSTEM', 'id' => 0);
        }
        $localVersion = $this->checkMISPVersion();
        $server = $this->find('first', array('conditions' => array('Server.id' => $id)));
        $HttpSocket = $this->setupHttpSocket($server, $HttpSocket);
        $request = $this->setupSyncRequest($server);
        $uri = $server['Server']['url'] . '/servers/getVersion';
        try {
            $response = $HttpSocket->get($uri, '', $request);
        } catch (Exception $e) {
            $error = $e->getMessage();
        }
        if (!isset($response) || $response->code != '200') {
            $this->Log = ClassRegistry::init('Log');
            $this->Log->create();
            if (isset($response->code)) {
                $title = 'Error: Connection to the server has failed.' . (isset($response->code) ? ' Returned response code: ' . $response->code : '');
            } else {
                $title = 'Error: Connection to the server has failed. The returned exception\'s error message was: ' . $e->getMessage();
            }
            $this->Log->save(array(
                    'org' => $user['Organisation']['name'],
                    'model' => 'Server',
                    'model_id' => $id,
                    'email' => $user['email'],
                    'action' => 'error',
                    'user_id' => $user['id'],
                    'title' => $title
            ));
            return $title;
        }
        $remoteVersion = json_decode($response->body, true);
        $canPush = isset($remoteVersion['perm_sync']) ? $remoteVersion['perm_sync'] : false;
        $canSight = isset($remoteVersion['perm_sighting']) ? $remoteVersion['perm_sighting'] : false;
        $supportEditOfGalaxyCluster = isset($remoteVersion['perm_galaxy_editor']);
        $canEditGalaxyCluster = isset($remoteVersion['perm_galaxy_editor']) ? $remoteVersion['perm_galaxy_editor'] : false;
        $remoteVersion = explode('.', $remoteVersion['version']);
        if (!isset($remoteVersion[0])) {
            $this->Log = ClassRegistry::init('Log');
            $this->Log->create();
            $message = __('Error: Server didn\'t send the expected response. This may be because the remote server version is outdated.');
            $this->Log->save(array(
                    'org' => $user['Organisation']['name'],
                    'model' => 'Server',
                    'model_id' => $id,
                    'email' => $user['email'],
                    'action' => 'error',
                    'user_id' => $user['id'],
                    'title' => $message,
            ));
            return $message;
        }
        $response = false;
        $success = false;
        $issueLevel = "warning";
        if ($localVersion['major'] > $remoteVersion[0]) {
            $response = "Sync to Server ('" . $id . "') aborted. The remote instance's MISP version is behind by a major version.";
        }
        if ($response === false && $localVersion['major'] < $remoteVersion[0]) {
            $response = "Sync to Server ('" . $id . "') aborted. The remote instance is at least a full major version ahead - make sure you update your MISP instance!";
        }
        if ($response === false && $localVersion['minor'] > $remoteVersion[1]) {
            $response = "Sync to Server ('" . $id . "') aborted. The remote instance's MISP version is behind by a minor version.";
        }
        if ($response === false && $localVersion['minor'] < $remoteVersion[1]) {
            $response = "Sync to Server ('" . $id . "') aborted. The remote instance is at least a full minor version ahead - make sure you update your MISP instance!";
        }

        // if we haven't set a message yet, we're good to go. We are only behind by a hotfix version
        if ($response === false) {
            $success = true;
        } else {
            $issueLevel = "error";
        }
        if ($response === false && $localVersion['hotfix'] > $remoteVersion[2]) {
            $response = "Sync to Server ('" . $id . "') initiated, but the remote instance is a few hotfixes behind.";
        }
        if ($response === false && $localVersion['hotfix'] < $remoteVersion[2]) {
            $response = "Sync to Server ('" . $id . "') initiated, but the remote instance is a few hotfixes ahead. Make sure you keep your instance up to date!";
        }
        if (empty($response) && $remoteVersion[2] < 111) {
            $response = "Sync to Server ('" . $id . "') initiated, but version 2.4.111 is required in order to be able to pull proposals from the remote side.";
        }

        if ($response !== false) {
            $this->Log = ClassRegistry::init('Log');
            $this->Log->create();
            $this->Log->save(array(
                    'org' => $user['Organisation']['name'],
                    'model' => 'Server',
                    'model_id' => $id,
                    'email' => $user['email'],
                    'action' => $issueLevel,
                    'user_id' => $user['id'],
                    'title' => ucfirst($issueLevel) . ': ' . $response,
            ));
        }
        return array('success' => $success, 'response' => $response, 'canPush' => $canPush, 'canSight' => $canSight, 'canEditGalaxyCluster' => $canEditGalaxyCluster, 'supportEditOfGalaxyCluster' => $supportEditOfGalaxyCluster, 'version' => $remoteVersion);
    }

    public function isJson($string)
    {
        try {
            $this->jsonDecode($string);
            return true;
        } catch (Exception $e) {
            return false;
        }
    }

    public function captureServer($server, $user)
    {
        if (isset($server[0])) {
            $server = $server[0];
        }
        if ($server['url'] == Configure::read('MISP.baseurl')) {
            return 0;
        }
        $existingServer = $this->find('first', array(
                'recursive' => -1,
                'conditions' => array('url' => $server['url'])
        ));
        // unlike with other capture methods, if we find a server that we don't know
        // we don't want to save it.
        if (empty($existingServer)) {
            return false;
        }
        return $existingServer[$this->alias]['id'];
    }

    public function dbSpaceUsage()
    {
        $dataSource = $this->getDataSource()->config['datasource'];
        if ($dataSource == 'Database/Mysql' || $dataSource == 'Database/MysqlObserver') {
            $sql = sprintf(
                'select TABLE_NAME, sum((DATA_LENGTH+INDEX_LENGTH)/1024/1024) AS used, sum(DATA_FREE)/1024/1024 AS reclaimable from information_schema.tables where table_schema = %s group by TABLE_NAME;',
                "'" . $this->getDataSource()->config['database'] . "'"
            );
            $sqlResult = $this->query($sql);
            $result = array();
            foreach ($sqlResult as $temp) {
                foreach ($temp[0] as $k => $v) {
                    $temp[0][$k] = round($v, 2) . 'MB';
                }
                $temp[0]['table'] = $temp['tables']['TABLE_NAME'];
                $result[] = $temp[0];
            }
            return $result;
        }
        else if ($dataSource == 'Database/Postgres') {
            $sql = sprintf(
                'select TABLE_NAME as table, pg_total_relation_size(%s||%s||TABLE_NAME) as used from information_schema.tables where table_schema = %s group by TABLE_NAME;',
                "'" . $this->getDataSource()->config['database'] . "'",
                "'.'",
                "'" . $this->getDataSource()->config['database'] . "'"
            );
            $sqlResult = $this->query($sql);
            $result = array();
            foreach ($sqlResult as $temp) {
                foreach ($temp[0] as $k => $v) {
                    if ($k == "table") {
                        continue;
                    }
                    $temp[0][$k] = round($v / 1024 / 1024, 2) . 'MB';
                }
                $temp[0]['reclaimable'] = '0MB';
                $result[] = $temp[0];
            }
            return $result;
        }
    }

    public function redisInfo()
    {
        $output = array(
            'extensionVersion' => phpversion('redis'),
            'connection' => false,
        );

        try {
            $redis = $this->setupRedisWithException();
            $output['connection'] = true;
            $output = array_merge($output, $redis->info());
        } catch (Exception $e) {
            $output['connection_error'] = $e->getMessage();
        }

        return $output;
    }

    public function dbSchemaDiagnostic()
    {
        $actualDbVersion = $this->AdminSetting->find('first', array(
            'conditions' => array('setting' => 'db_version')
        ))['AdminSetting']['value'];
        $dataSource = $this->getDataSource()->config['datasource'];
        $schemaDiagnostic = array(
            'dataSource' => $dataSource,
            'actual_db_version' => $actualDbVersion,
            'checked_table_column' => array(),
            'diagnostic' => array(),
            'diagnostic_index' => array(),
            'expected_db_version' => '?',
            'error' => '',
            'update_locked' => $this->isUpdateLocked(),
            'remaining_lock_time' => $this->getLockRemainingTime(),
            'update_fail_number_reached' => $this->UpdateFailNumberReached(),
            'indexes' => array()
        );
        if ($dataSource == 'Database/Mysql' || $dataSource == 'Database/MysqlObserver') {
            $dbActualSchema = $this->getActualDBSchema();
            $dbExpectedSchema = $this->getExpectedDBSchema();
            if ($dbExpectedSchema !== false) {
                $db_schema_comparison = $this->compareDBSchema($dbActualSchema['schema'], $dbExpectedSchema['schema']);
                $db_indexes_comparison = $this->compareDBIndexes($dbActualSchema['indexes'], $dbExpectedSchema['indexes'], $dbExpectedSchema);
                $schemaDiagnostic['checked_table_column'] = $dbActualSchema['column'];
                $schemaDiagnostic['diagnostic'] = $db_schema_comparison;
                $schemaDiagnostic['diagnostic_index'] = $db_indexes_comparison;
                $schemaDiagnostic['expected_db_version'] = $dbExpectedSchema['db_version'];
                foreach($dbActualSchema['schema'] as $tableName => $tableMetas) {
                    foreach($tableMetas as $tableMeta) {
                        $schemaDiagnostic['columnPerTable'][$tableName][] = $tableMeta['column_name'];
                    }
                }
                $schemaDiagnostic['indexes'] = $dbActualSchema['indexes'];
            } else {
                $schemaDiagnostic['error'] = sprintf('Diagnostic not available as the expected schema file could not be loaded');
            }
        } else {
            $schemaDiagnostic['error'] = sprintf('Diagnostic not available for DataSource `%s`', $dataSource);
        }
        if (!empty($schemaDiagnostic['diagnostic'])) {
            foreach ($schemaDiagnostic['diagnostic'] as $table => &$fields) {
                foreach ($fields as &$field) {
                    $field = $this->__attachRecoveryQuery($field, $table);
                }
            }
        }
        return $schemaDiagnostic;
    }

    /*
     * Work in progress, still needs DEFAULT in the schema for it to work correctly
     * Currently only works for missing_column and column_different
     * Only currently supported field types are: int, tinyint, varchar, text
     */
    private function __attachRecoveryQuery($field, $table)
    {
        if (isset($field['error_type'])) {
            $length = false;
            if (in_array($field['error_type'], array('missing_column', 'column_different'))) {
                preg_match('/([a-z]+)(?:\((?<dw>[0-9,]+)\))?\s*([a-z]+)?/i', $field['expected']['column_type'], $displayWidthMatches);
                if (isset($displayWidthMatches['dw'])) {
                    $length = $displayWidthMatches[2];
                } elseif ($field['expected']['data_type'] === 'int') {
                    $length = 11;
                } elseif ($field['expected']['data_type'] === 'tinyint') {
                    $length = 1;
                } elseif ($field['expected']['data_type'] === 'varchar') {
                    $length = $field['expected']['character_maximum_length'];
                } elseif ($field['expected']['data_type'] === 'text') {
                    $length = null;
                }
            }
            if ($length !== false) {
                switch($field['error_type']) {
                    case 'missing_column':
                        $field['sql'] = sprintf(
                            'ALTER TABLE `%s` ADD COLUMN `%s` %s%s %s %s %s %s %s;',
                            $table,
                            $field['column_name'],
                            $field['expected']['data_type'],
                            $length !== null ? sprintf('(%d)', $length) : '',
                            strpos($field['expected']['column_type'], 'unsigned') != -1 ? 'UNSIGNED' : '',
                            isset($field['expected']['column_default']) ? 'DEFAULT "' . $field['expected']['column_default'] . '"' : '',
                            $field['expected']['is_nullable'] === 'NO' ? 'NOT NULL' : 'NULL',
                            empty($field['expected']['collation_name']) ? '' : 'COLLATE ' . $field['expected']['collation_name'],
                            empty($field['expected']['extra']) ? '' : $field['expected']['extra']
                        );
                        break;
                    case 'column_different':
                        $field['sql'] = sprintf(
                            'ALTER TABLE `%s` MODIFY COLUMN `%s` %s%s %s %s %s %s %s;',
                            $table,
                            $field['column_name'],
                            $field['expected']['data_type'],
                            $length !== null ? sprintf('(%d)', $length) : '',
                            strpos($field['expected']['column_type'], 'unsigned') != -1 ? 'UNSIGNED' : '',
                            isset($field['expected']['column_default']) ? 'DEFAULT "' . $field['expected']['column_default'] . '"' : '',
                            $field['expected']['is_nullable'] === 'NO' ? 'NOT NULL' : 'NULL',
                            empty($field['expected']['collation_name']) ? '' : 'COLLATE ' . $field['expected']['collation_name'],
                            empty($field['expected']['extra']) ? '' : $field['expected']['extra']
                        );
                        break;
                }
            } elseif($field['error_type'] == 'missing_table') {
                $allFields = array();
                foreach ($field['expected_table'] as $expectedField) {
                    $length = false;
                    if ($expectedField['data_type'] === 'int') {
                        $length = 11;
                    } elseif ($expectedField['data_type'] === 'tinyint') {
                        $length = 1;
                    } elseif ($expectedField['data_type'] === 'varchar') {
                        $length = $expectedField['character_maximum_length'];
                    } elseif ($expectedField['data_type'] === 'text') {
                        $length = null;
                    }
                    $fieldSql = sprintf('`%s` %s%s %s %s %s %s %s',
                        $expectedField['column_name'],
                        $expectedField['data_type'],
                        $length !== null ? sprintf('(%d)', $length) : '',
                        strpos($expectedField['column_type'], 'unsigned') != -1 ? 'UNSIGNED' : '',
                        isset($expectedField['column_default']) ? 'DEFAULT "' . $expectedField['column_default'] . '"' : '',
                        $expectedField['is_nullable'] === 'NO' ? 'NOT NULL' : 'NULL',
                        empty($expectedField['collation_name']) ? '' : 'COLLATE ' . $expectedField['collation_name'],
                        empty($field['expected']['extra']) ? '' : $field['expected']['extra']
                    );
                    $allFields[] = $fieldSql;
                }
                $field['sql'] = __("% The command below is a suggestion and might be incorrect. Please ask if you are not sure what you are doing.") . "</br></br>" . sprintf(
                    "CREATE TABLE IF NOT EXISTS `%s` ( %s ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;",
                        $table,
                        implode(', ', $allFields)
                );
            }
        }
        return $field;
    }

    public function getExpectedDBSchema()
    {
        App::uses('Folder', 'Utility');
        $file = new File(ROOT . DS . 'db_schema.json', true);
        $dbExpectedSchema = json_decode($file->read(), true);
        $file->close();
        if (!is_null($dbExpectedSchema)) {
            return $dbExpectedSchema;
        } else {
            return false;
        }
    }

    // TODO: Use CakePHP 3.X's Schema System
    /*
        $db = ConnectionManager::get('default');

        // Create a schema collection.
        $collection = $db->schemaCollection();

        // Get the table names
        $tables = $collection->listTables();

        // Get a single table (instance of Schema\TableSchema)
        $tableSchema = $collection->describe('posts');

    */
    public function getActualDBSchema(
        $tableColumnNames = array(
            'column_name',
            'is_nullable',
            'data_type',
            'character_maximum_length',
            'numeric_precision',
            // 'datetime_precision',    -- Only available on MySQL 5.6+
            'collation_name',
            'column_type',
            'column_default',
            'extra',
        )
    ){
        $dbActualSchema = array();
        $dbActualIndexes = array();
        $dataSource = $this->getDataSource()->config['datasource'];
        if ($dataSource == 'Database/Mysql' || $dataSource == 'Database/MysqlObserver') {
            $sqlGetTable = sprintf('SELECT TABLE_NAME FROM information_schema.tables WHERE table_schema = %s ORDER BY TABLE_NAME;', "'" . $this->getDataSource()->config['database'] . "'");
            $sqlResult = $this->query($sqlGetTable);
            $tables = Hash::extract($sqlResult, '{n}.tables.TABLE_NAME');
            foreach ($tables as $table) {
                $sqlSchema = sprintf(
                    "SELECT %s
                    FROM information_schema.columns
                    WHERE table_schema = '%s' AND TABLE_NAME = '%s'", implode(',', $tableColumnNames), $this->getDataSource()->config['database'], $table);
                $sqlResult = $this->query($sqlSchema);
                foreach ($sqlResult as $column_schema) {
                    $column_schema['columns'] = array_change_key_case($column_schema['columns'],CASE_LOWER);
                    $dbActualSchema[$table][] = $column_schema['columns'];
                }
                $dbActualIndexes[$table] = $this->getDatabaseIndexes($this->getDataSource()->config['database'], $table);
            }
        }
        else if ($dataSource == 'Database/Postgres') {
            return array('Database/Postgres' => array('description' => __('Can\'t check database schema for Postgres database type')));
        }
        return array('schema' => $dbActualSchema, 'column' => $tableColumnNames, 'indexes' => $dbActualIndexes);
    }

    public function compareDBSchema($dbActualSchema, $dbExpectedSchema)
    {
        // Column that should be ignored while performing the comparison
        $allowedlistFields = array(
            'users' => array('external_auth_required', 'external_auth_key'),
        );
        $nonCriticalColumnElements = array('is_nullable', 'collation_name');
        $dbDiff = array();
        // perform schema comparison for tables
        foreach($dbExpectedSchema as $tableName => $columns) {
            if (!array_key_exists($tableName, $dbActualSchema)) {
                $dbDiff[$tableName][] = array(
                    'description' => sprintf(__('Table `%s` does not exist'), $tableName),
                    'error_type' => 'missing_table',
                    'expected_table' => $columns,
                    'column_name' => $tableName,
                    'is_critical' => true
                );
            } else {
                // perform schema comparison for table's columns
                $expectedColumnKeys = array();
                $keyedExpectedColumn = array();
                foreach($columns as $column) {
                    $expectedColumnKeys[] = $column['column_name'];
                    $keyedExpectedColumn[$column['column_name']] = $column;
                }
                $existingColumnKeys = array();
                $keyedActualColumn = array();
                foreach($dbActualSchema[$tableName] as $column) {
                    $existingColumnKeys[] = $column['column_name'];
                    $keyedActualColumn[$column['column_name']] = $column;
                }

                $additionalKeysInActualSchema = array_diff($existingColumnKeys, $expectedColumnKeys);
                foreach($additionalKeysInActualSchema as $additionalKeys) {
                    if (isset($allowedlistFields[$tableName]) && in_array($additionalKeys, $allowedlistFields[$tableName])) {
                        continue; // column is allowedlisted
                    }
                    $dbDiff[$tableName][] = array(
                        'description' => sprintf(__('Column `%s` exists but should not'), $additionalKeys),
                        'error_type' => 'additional_column',
                        'column_name' => $additionalKeys,
                        'is_critical' => false
                    );
                }
                foreach ($keyedExpectedColumn as $columnName => $column) {
                    if (isset($allowedlistFields[$tableName]) && in_array($columnName, $allowedlistFields[$tableName])) {
                        continue; // column is allowedlisted
                    }
                    if (isset($keyedActualColumn[$columnName])) {
                        $colDiff = array_diff_assoc($column, $keyedActualColumn[$columnName]);
                        if (count($colDiff) > 0) {
                            $colElementDiffs = array_keys(array_diff_assoc($column, $keyedActualColumn[$columnName]));
                            $isCritical = false;
                            foreach($colElementDiffs as $colElementDiff) {
                                if(!in_array($colElementDiff, $nonCriticalColumnElements)) {
                                    if ($colElementDiff == 'column_default') {
                                        $expectedValue = $column['column_default'];
                                        $actualValue = $keyedActualColumn[$columnName]['column_default'];
                                        if (preg_match(sprintf('@(\'|")+%s(\1)+@', $expectedValue), $actualValue) || (empty($expectedValue) && $actualValue === 'NULL')) { // some version of mysql quote the default value
                                            continue;
                                        } else {
                                            $isCritical = true;
                                            break;
                                        }
                                    } else {
                                        $isCritical = true;
                                        break;
                                    }
                                }
                            }
                            $dbDiff[$tableName][] = array(
                                'description' => sprintf(__('Column `%s` is different'), $columnName),
                                'column_name' => $column['column_name'],
                                'error_type' => 'column_different',
                                'actual' => $keyedActualColumn[$columnName],
                                'expected' => $column,
                                'is_critical' => $isCritical
                            );
                        }
                    } else {
                        $dbDiff[$tableName][] = array(
                            'description' => sprintf(__('Column `%s` does not exist but should'), $columnName),
                            'column_name' => $columnName,
                            'error_type' => 'missing_column',
                            'actual' => array(),
                            'expected' => $column,
                            'is_critical' => true
                        );
                    }
                }
            }
        }
        foreach(array_diff(array_keys($dbActualSchema), array_keys($dbExpectedSchema)) as $additionalTable) {
            $dbDiff[$additionalTable][] = array(
                'description' => sprintf(__('Table `%s` is an additional table'), $additionalTable),
                'column_name' => $additionalTable,
                'error_type' => 'additional_table',
                'is_critical' => false
            );
        }
        return $dbDiff;
    }

    /**
     * Returns `true` if given column for given table contains just unique values.
     *
     * @param string $tableName
     * @param string $columnName
     * @return bool
     */
    private function checkIfColumnContainsJustUniqueValues($tableName, $columnName)
    {
        $db = $this->getDataSource();
        $duplicates = $this->query(
            sprintf('SELECT %s, COUNT(*) c FROM %s GROUP BY %s HAVING c > 1;',
                $db->name($columnName), $db->name($tableName), $db->name($columnName))
        );
        return empty($duplicates);
    }

    private function generateSqlDropIndexQuery($tableName, $columnName)
    {
        return sprintf('DROP INDEX `%s` ON %s;',
            $columnName,
            $tableName
        );
    }

    private function generateSqlIndexQuery(array $dbExpectedSchema, $tableName, $columnName, $shouldBeUnique = false, $defaultIndexKeylength = 255)
    {
        $columnData = Hash::extract($dbExpectedSchema['schema'][$tableName], "{n}[column_name=$columnName]");
        if (empty($columnData)) {
            throw new Exception("Index in db_schema.json is defined for `$tableName.$columnName`, but this column is not defined.");
        }

        $columnData = $columnData[0];
        if ($columnData['data_type'] === 'varchar') {
            $keyLength = sprintf('(%s)', $columnData['character_maximum_length'] < $defaultIndexKeylength ? $columnData['character_maximum_length'] : $defaultIndexKeylength);
        } elseif ($columnData['data_type'] === 'text') {
            $keyLength = sprintf('(%s)', $defaultIndexKeylength);
        } else {
            $keyLength = '';
        }
        return sprintf('CREATE%s INDEX `%s` ON `%s` (`%s`%s);',
            $shouldBeUnique ? ' UNIQUE' : '',
            $columnName,
            $tableName,
            $columnName,
            $keyLength
        );
    }

    public function compareDBIndexes(array $actualIndex, array $expectedIndex, array $dbExpectedSchema)
    {
        $allowedlistTables = array();
        $indexDiff = array();
        foreach ($expectedIndex as $tableName => $indexes) {
            if (!array_key_exists($tableName, $actualIndex)) {
                continue; // If table does not exists, it is covered by the schema diagnostic
            } elseif(in_array($tableName, $allowedlistTables)) {
                continue; // Ignore allowedlisted tables
            } else {
                $tableIndexDiff = array_diff(array_keys($indexes), array_keys($actualIndex[$tableName])); // check for missing indexes
                foreach ($tableIndexDiff as $columnDiff) {
                    $shouldBeUnique = $indexes[$columnDiff];
                    if ($shouldBeUnique && !$this->checkIfColumnContainsJustUniqueValues($tableName, $columnDiff)) {
                        $indexDiff[$tableName][$columnDiff] = array(
                            'message' => __('Column `%s` should be unique indexed, but contains duplicate values', $columnDiff),
                            'sql' => '',
                        );
                        continue;
                    }

                    $message = __('Column `%s` should be indexed', $columnDiff);
                    $indexDiff[$tableName][$columnDiff] = array(
                        'message' => $message,
                        'sql' => $this->generateSqlIndexQuery($dbExpectedSchema, $tableName, $columnDiff, $shouldBeUnique),
                    );
                }
                $tableIndexDiff = array_diff(array_keys($actualIndex[$tableName]), array_keys($indexes)); // check for additional indexes
                foreach ($tableIndexDiff as $columnDiff) {
                    $message = __('Column `%s` is indexed but should not', $columnDiff);
                    $indexDiff[$tableName][$columnDiff] = array(
                        'message' => $message,
                        'sql' => $this->generateSqlDropIndexQuery($tableName, $columnDiff),
                    );
                }
                foreach ($indexes as $column => $unique) {
                    if (isset($actualIndex[$tableName][$column]) && $actualIndex[$tableName][$column] != $unique) {
                        if ($actualIndex[$tableName][$column]) {
                            $sql = $this->generateSqlDropIndexQuery($tableName, $column);
                            $sql .= '<br>' . $this->generateSqlIndexQuery($dbExpectedSchema, $tableName, $column, false);

                            $message = __('Column `%s` has unique index, but should be non unique', $column);
                            $indexDiff[$tableName][$column] = array(
                                'message' => $message,
                                'sql' => $sql,
                            );
                        } else {
                            if (!$this->checkIfColumnContainsJustUniqueValues($tableName, $column)) {
                                $message = __('Column `%s` should be unique index, but contains duplicate values', $column);
                                $indexDiff[$tableName][$column] = array(
                                    'message' => $message,
                                    'sql' => '',
                                );
                                continue;
                            }

                            $sql = $this->generateSqlDropIndexQuery($tableName, $column);
                            $sql .= '<br>' . $this->generateSqlIndexQuery($dbExpectedSchema, $tableName, $column, true);

                            $message = __('Column `%s` should be unique index', $column);
                            $indexDiff[$tableName][$column] = array(
                                'message' => $message,
                                'sql' => $sql,
                            );
                        }
                    }
                }
            }
        }
        return $indexDiff;
    }

    /**
     * Returns indexes for given schema and table in array, where key is column name and value is `true` if
     * index is index is unique, `false` otherwise.
     *
     * @param string $database
     * @param string $table
     * @return array
     */
    public function getDatabaseIndexes($database, $table)
    {
        $sqlTableIndex = sprintf(
            "SELECT DISTINCT TABLE_NAME, COLUMN_NAME, NON_UNIQUE FROM information_schema.statistics WHERE TABLE_SCHEMA = '%s' AND TABLE_NAME = '%s';",
            $database,
            $table
        );
        $sqlTableIndexResult = $this->query($sqlTableIndex);
        $output = [];
        foreach ($sqlTableIndexResult as $index) {
            $output[$index['statistics']['COLUMN_NAME']] = $index['statistics']['NON_UNIQUE'] == 0;
        }
        return $output;
    }

    public function writeableDirsDiagnostics(&$diagnostic_errors)
    {
        App::uses('File', 'Utility');
        App::uses('Folder', 'Utility');
        // check writeable directories
        $writeableDirs = array(
                '/tmp' => 0,
                APP . 'tmp' => 0,
                APP . 'files' => 0,
                APP . 'files' . DS . 'scripts' . DS . 'tmp' => 0,
                APP . 'tmp' . DS . 'csv_all' => 0,
                APP . 'tmp' . DS . 'csv_sig' => 0,
                APP . 'tmp' . DS . 'md5' => 0,
                APP . 'tmp' . DS . 'sha1' => 0,
                APP . 'tmp' . DS . 'snort' => 0,
                APP . 'tmp' . DS . 'suricata' => 0,
                APP . 'tmp' . DS . 'text' => 0,
                APP . 'tmp' . DS . 'xml' => 0,
                APP . 'tmp' . DS . 'files' => 0,
                APP . 'tmp' . DS . 'logs' => 0,
                APP . 'tmp' . DS . 'bro' => 0,
        );
        foreach ($writeableDirs as $path => &$error) {
            $dir = new Folder($path);
            if (is_null($dir->path)) {
                $error = 1;
            }
            $file = new File($path . DS . 'test.txt', true);
            if ($error == 0 && !$file->write('test')) {
                $error = 2;
            }
            if ($error != 0) {
                $diagnostic_errors++;
            }
            $file->delete();
            $file->close();
        }
        return $writeableDirs;
    }

    public function writeableFilesDiagnostics(&$diagnostic_errors)
    {
        $writeableFiles = array(
                APP . 'Config' . DS . 'config.php' => 0,
                ROOT .  DS . '.git' . DS . 'ORIG_HEAD' => 0,
        );
        foreach ($writeableFiles as $path => &$error) {
            if (!file_exists($path)) {
                $error = 1;
                continue;
            }
            if (!is_writeable($path)) {
                $error = 2;
                $diagnostic_errors++;
            }
        }
        return $writeableFiles;
    }

    public function readableFilesDiagnostics(&$diagnostic_errors)
    {
        $readableFiles = array(
                APP . 'files' . DS . 'scripts' . DS . 'stixtest.py' => 0
        );
        foreach ($readableFiles as $path => &$error) {
            if (!is_readable($path)) {
                $error = 1;
                continue;
            }
        }
        return $readableFiles;
    }

    public function yaraDiagnostics(&$diagnostic_errors)
    {
        $scriptResult = shell_exec($this->getPythonVersion() . ' ' . APP . 'files' . DS . 'scripts' . DS . 'yaratest.py');
        $scriptResult = json_decode($scriptResult, true);
        return array('operational' => $scriptResult['success'], 'plyara' => $scriptResult['plyara']);
    }

    public function stixDiagnostics(&$diagnostic_errors, &$stixVersion, &$cyboxVersion, &$mixboxVersion, &$maecVersion, &$stix2Version, &$pymispVersion)
    {
        $result = array();
        $expected = array('stix' => '>1.2.0.9', 'cybox' => '>2.1.0.21', 'mixbox' => '1.0.3', 'maec' => '>4.1.0.14', 'stix2' => '>2.0', 'pymisp' => '>2.4.120');
        // check if the STIX and Cybox libraries are working using the test script stixtest.py
        $scriptResult = shell_exec($this->getPythonVersion() . ' ' . APP . 'files' . DS . 'scripts' . DS . 'stixtest.py');
        try {
            $scriptResult = $this->jsonDecode($scriptResult);
        } catch (Exception $e) {
            $this->logException('Invalid JSON returned from stixtest', $e);
            return array(
                'operational' => 0,
                'stix' => array('expected' => $expected['stix']),
                'cybox' => array('expected' => $expected['cybox']),
                'mixbox' => array('expected' => $expected['mixbox']),
                'maec' => array('expected' => $expected['maec']),
                'stix2' => array('expected' => $expected['stix2']),
                'pymisp' => array('expected' => $expected['pymisp'])
            );
        }
        $scriptResult['operational'] = $scriptResult['success'];
        if ($scriptResult['operational'] == 0) {
            $diagnostic_errors++;
        }
        $result['operational'] = $scriptResult['operational'];
        foreach ($expected as $package => $version) {
            $result[$package]['version'] = $scriptResult[$package];
            $result[$package]['expected'] = $expected[$package];
            if ($expected[$package][0] === '>') {
                $expected[$package] = trim($expected[$package], '>');
                $result[$package]['status'] = (version_compare($result[$package]['version'], $expected[$package]) >= 0) ? 1 : 0;
            } else {
                $result[$package]['status'] = $result[$package]['version'] == $result[$package]['expected'] ? 1 : 0;
            }
            if ($result[$package]['status'] == 0) {
                $diagnostic_errors++;
            }
            ${$package . 'Version'}[0] = str_replace('$current', $result[$package]['version'], ${$package . 'Version'}[0]);
            ${$package . 'Version'}[0] = str_replace('$expected', $result[$package]['expected'], ${$package . 'Version'}[0]);
        }
        return $result;
    }

    /**
     * @param int $diagnostic_errors
     * @return array
     */
    public function gpgDiagnostics(&$diagnostic_errors)
    {
        $output = ['status' => 0, 'version' => null];
        if (Configure::read('GnuPG.email') && Configure::read('GnuPG.homedir')) {
            try {
                $gpg = GpgTool::initializeGpg();
            } catch (Exception $e) {
                $this->logException("Error during initializing GPG.", $e, LOG_NOTICE);
                $output['status'] = 2;
            }
            if ($output['status'] === 0) {
                try {
                    $output['version'] = $gpg->getVersion();
                } catch (Exception $e) {
                    // ingore
                }

                try {
                    $gpg->addSignKey(Configure::read('GnuPG.email'), Configure::read('GnuPG.password'));
                } catch (Exception $e) {
                    $this->logException("Error during adding GPG signing key.", $e, LOG_NOTICE);
                    $output['status'] = 3;
                }
            }
            if ($output['status'] === 0) {
                try {
                    $gpg->sign('test', Crypt_GPG::SIGN_MODE_CLEAR);
                } catch (Exception $e) {
                    $this->logException("Error during GPG signing.", $e, LOG_NOTICE);
                    $output['status'] = 4;
                }
            }
        } else {
            $output['status'] = 1;
        }
        if ($output['status'] !== 0) {
            $diagnostic_errors++;
        }
        return $output;
    }

    public function zmqDiagnostics(&$diagnostic_errors)
    {
        if (!Configure::read('Plugin.ZeroMQ_enable')) {
            return 1;
        }
        $pubSubTool = $this->getPubSubTool();
        if (!$pubSubTool->checkIfPythonLibInstalled()) {
            $diagnostic_errors++;
            return 2;
        }
        if ($pubSubTool->checkIfRunning()) {
            return 0;
        }
        $diagnostic_errors++;
        return 3;
    }

    public function moduleDiagnostics(&$diagnostic_errors, $type = 'Enrichment')
    {
        $this->Module = ClassRegistry::init('Module');
        $diagnostic_errors++;
        if (Configure::read('Plugin.' . $type . '_services_enable')) {
            try {
                $result = $this->Module->getModules($type, true);
            } catch (Exception $e) {
                return $e->getMessage();
            }
            if (empty($result)) {
                return 2;
            }
            $diagnostic_errors--;
            return 0;
        }
        return 1;
    }

    public function proxyDiagnostics(&$diagnostic_errors)
    {
        $proxyStatus = 0;
        $proxy = Configure::read('Proxy');
        if (!empty($proxy['host'])) {
            App::uses('SyncTool', 'Tools');
            $syncTool = new SyncTool();
            try {
                $HttpSocket = $syncTool->setupHttpSocket();
                $proxyResponse = $HttpSocket->get('https://www.github.com/');
            } catch (Exception $e) {
                $proxyStatus = 2;
            }
            if (empty($proxyResponse) || $proxyResponse->code > 399) {
                $proxyStatus = 2;
            }
        } else {
            $proxyStatus = 1;
        }
        if ($proxyStatus > 1) {
            $diagnostic_errors++;
        }
        return $proxyStatus;
    }

    public function sessionDiagnostics(&$diagnostic_errors = 0, &$sessionCount = '')
    {
        if (Configure::read('Session.defaults') !== 'database') {
            $sessionCount = 'N/A';
            return 2;
        }
        $sql = 'SELECT COUNT(id) AS session_count FROM cake_sessions WHERE expires < ' . time() . ';';
        $sqlResult = $this->query($sql);
        if (isset($sqlResult[0][0])) {
            $sessionCount = $sqlResult[0][0]['session_count'];
        } else {
            $sessionCount = 'Error';
            return 3;
        }
        if ($sessionCount > 1000) {
            $diagnostic_errors++;
            return 1;
        }
        return 0;
    }

    public function workerDiagnostics(&$workerIssueCount)
    {
        $worker_array = array(
            'cache' => array('ok' => false),
            'default' => array('ok' => false),
            'email' => array('ok' => false),
            'prio' => array('ok' => false),
            'update' => array('ok' => false),
            'scheduler' => array('ok' => false)
        );
        try {
            $this->ResqueStatus = new ResqueStatus\ResqueStatus(Resque::redis());
        } catch (Exception $e) {
            // redis connection failed
            return $worker_array;
        }
        $workers = $this->ResqueStatus->getWorkers();
        if (function_exists('posix_getpwuid')) {
            $currentUser = posix_getpwuid(posix_geteuid());
            $currentUser = $currentUser['name'];
        } else {
            $currentUser = trim(shell_exec('whoami'));
        }
        $procAccessible = file_exists('/proc');
        foreach ($workers as $pid => $worker) {
            $entry = ($worker['type'] == 'regular') ? $worker['queue'] : $worker['type'];
            $correct_user = ($currentUser === $worker['user']);
            if (!is_numeric($pid)) {
                throw new MethodNotAllowedException('Non numeric PID found.');
            }
            if ($procAccessible) {
                $alive = $correct_user ? (file_exists('/proc/' . addslashes($pid))) : false;
            } else {
                $alive = 'N/A';
            }
            $ok = true;
            if (!$alive || !$correct_user) {
                $ok = false;
                $workerIssueCount++;
            }
            $worker_array[$entry]['workers'][] = array(
                'pid' => $pid,
                'user' => $worker['user'],
                'alive' => $alive,
                'correct_user' => $correct_user,
                'ok' => $ok
            );
        }
        foreach ($worker_array as $k => $queue) {
            if (isset($worker_array[$k]['workers'])) {
                foreach($worker_array[$k]['workers'] as $worker) {
                    if ($worker['ok']) {
                        $worker_array[$k]['ok'] = true; // If at least one worker is up, the queue can be considered working
                    }
                }
            }
            if ($k != 'scheduler') {
                $worker_array[$k]['jobCount'] = CakeResque::getQueueSize($k);
            }
            if (!isset($queue['workers'])) {
                $workerIssueCount++;
                $worker_array[$k]['ok'] = false;
            }
        }
        $worker_array['proc_accessible'] = $procAccessible;
        $worker_array['controls'] = 1;
        if (Configure::check('MISP.manage_workers')) {
            $worker_array['controls'] = Configure::read('MISP.manage_workers');
        }
        return $worker_array;
    }

    public function retrieveCurrentSettings($branch, $subString)
    {
        $settings = array();
        foreach ($this->serverSettings[$branch] as $settingName => $setting) {
            if (strpos($settingName, $subString) !== false) {
                $settings[$settingName] = $setting['value'];
                if (Configure::read('Plugin.' . $settingName)) {
                    $settings[$settingName] = Configure::read('Plugin.' . $settingName);
                }
                if (isset($setting['options'])) {
                    $settings[$settingName] = $setting['options'][$settings[$settingName]];
                }
            }
        }
        return $settings;
    }

    public function killWorker($pid, $user)
    {
        if (!is_numeric($pid)) {
            throw new MethodNotAllowedException('Non numeric PID found!');
        }
        $this->ResqueStatus = new ResqueStatus\ResqueStatus(Resque::redis());
        $workers = $this->ResqueStatus->getWorkers();
        $this->Log = ClassRegistry::init('Log');
        if (isset($workers[$pid])) {
            $worker = $workers[$pid];
            if (substr_count(trim(shell_exec('ps -p ' . $pid)), PHP_EOL) > 0 ? true : false) {
                shell_exec('kill ' . $pid . ' > /dev/null 2>&1 &');
                $this->__logRemoveWorker($user, $pid, $worker['queue'], false);
            } else {
                $this->ResqueStatus->removeWorker($pid);
                $this->__logRemoveWorker($user, $pid, $worker['queue'], true);
            }
            $this->ResqueStatus->removeWorker($pid);
        }
    }

    public function killAllWorkers($user = false, $force = false)
    {
        $this->ResqueStatus = new ResqueStatus\ResqueStatus(Resque::redis());
        $workers = $this->ResqueStatus->getWorkers();
        $killed = array();
        foreach ($workers as $pid => $worker) {
            if (!is_numeric($pid)) {
                continue;
            }
            if (substr_count(trim(shell_exec('ps -p ' . $pid)), PHP_EOL) > 0) {
                shell_exec('kill ' . ($force ? ' -9 ' : '') . $pid . ' > /dev/null 2>&1 &');
                $this->ResqueStatus->removeWorker($pid);
                $this->__logRemoveWorker($user, $pid, $worker['queue'], false);
            } else {
                $this->ResqueStatus->removeWorker($pid);
                $this->__logRemoveWorker($user, $pid, $worker['queue'], true);
            }
        }
        return $killed;
    }

    public function workerRemoveDead($user = false)
    {
        $this->ResqueStatus = new ResqueStatus\ResqueStatus(Resque::redis());
        $workers = $this->ResqueStatus->getWorkers();
        if (function_exists('posix_getpwuid')) {
            $currentUser = posix_getpwuid(posix_geteuid());
            $currentUser = $currentUser['name'];
        } else {
            $currentUser = trim(shell_exec('whoami'));
        }
        $killed = array();
        foreach ($workers as $pid => $worker) {
            if (!is_numeric($pid)) {
                throw new MethodNotAllowedException('Non numeric PID found!');
            }
            $pidTest = substr_count(trim(shell_exec('ps -p ' . $pid)), PHP_EOL) > 0 ? true : false;
            if ($worker['user'] == $currentUser && !$pidTest) {
                $this->ResqueStatus->removeWorker($pid);
                $this->__logRemoveWorker($user, $pid, $worker['queue'], true);
                if (empty($killed[$worker['queue']])) {
                    $killed[$worker['queue']] = 1;
                } else {
                    $killed[$worker['queue']] += 1;
                }
            }
        }
        return $killed;
    }

    private function __logRemoveWorker($user, $pid, $queue, $dead = false)
    {
        $this->Log = ClassRegistry::init('Log');
        $this->Log->create();
        if (empty($user)) {
            $user = array(
                'id' => 0,
                'Organisation' => array(
                    'name' => 'SYSTEM'
                ),
                'email' => 'SYSTEM'
            );
        }
        $type = $dead ? 'dead' : 'kill';
        $text = array(
            'dead' => array(
                'action' => 'remove_dead_workers',
                'title' => __('Removing a dead worker.'),
                'change' => sprintf(__('Removing dead worker data. Worker was of type %s with pid %s'), $queue, $pid)
            ),
            'kill' => array(
                'action' => 'stop_worker',
                'title' => __('Stopping a worker.'),
                'change' => sprintf(__('Stopping a worker. Worker was of type %s with pid %s'), $queue, $pid)
            )
        );
        $this->Log->save(array(
            'org' => $user['Organisation']['name'],
            'model' => 'User',
            'model_id' => $user['id'],
            'email' => $user['email'],
            'action' => $text[$type]['action'],
            'user_id' => $user['id'],
            'title' => $text[$type]['title'],
            'change' => $text[$type]['change']
        ));
    }

    /* returns the version string of a connected instance
     * error codes:
     * 1: received non json response
     * 2: no route to host
     * 3: empty result set
     */
    public function getRemoteVersion($id)
    {
        $server = $this->find('first', array(
                'conditions' => array('Server.id' => $id),
        ));
        if (empty($server)) {
            return 2;
        }
        App::uses('SyncTool', 'Tools');
        $syncTool = new SyncTool();
        $HttpSocket = $syncTool->setupHttpSocket($server);
        $request = $this->setupSyncRequest($server);
        $response = $HttpSocket->get($server['Server']['url'] . '/servers/getVersion', $data = '', $request);
        if ($response->code == 200) {
            try {
                $data = json_decode($response->body, true);
            } catch (Exception $e) {
                return 1;
            }
            if (isset($data['version']) && !empty($data['version'])) {
                return $data['version'];
            } else {
                return 3;
            }
        }
        return 2;
    }

    /**
     * Returns an array with the events
     * @param int $id
     * @param $user - not used
     * @param array $passedArgs
     * @return array
     * @throws Exception
     */
    public function previewIndex($id, $user, array $passedArgs)
    {
        $validArgs = array_merge(array('sort', 'direction', 'page', 'limit'), $this->validEventIndexFilters);
        $urlParams = '';
        foreach ($validArgs as $v) {
            if (isset($passedArgs[$v])) {
                $urlParams .= '/' . $v . ':' . $passedArgs[$v];
            }
        }

        $relativeUri = '/events/index' . $urlParams;
        list($events, $response) = $this->serverGetRequest($id, $relativeUri);
        $totalCount = $response->getHeader('X-Result-Count') ?: 0;

        foreach ($events as $k => $event) {
            if (!isset($event['Orgc'])) {
                $event['Orgc']['name'] = $event['orgc'];
            }
            if (!isset($event['Org'])) {
                $event['Org']['name'] = $event['org'];
            }
            if (!isset($event['EventTag'])) {
                $event['EventTag'] = array();
            }
            $events[$k] = array('Event' => $event);
        }

        return array($events, $totalCount);
    }

    /**
     * Returns an array with the event.
     * @param int $serverId
     * @param int $eventId
     * @return array
     * @throws Exception
     */
    public function previewEvent($serverId, $eventId)
    {
        $relativeUri =  '/events/' . $eventId;
        list($event) = $this->serverGetRequest($serverId, $relativeUri);

        if (!isset($event['Event']['Orgc'])) {
            $event['Event']['Orgc']['name'] = $event['Event']['orgc'];
        }
        if (isset($event['Event']['Orgc'][0])) {
            $event['Event']['Orgc'] = $event['Event']['Orgc'][0];
        }
        if (!isset($event['Event']['Org'])) {
            $event['Event']['Org']['name'] = $event['Event']['org'];
        }
        if (isset($event['Event']['Org'][0])) {
            $event['Event']['Org'] = $event['Event']['Org'][0];
        }
        if (!isset($event['Event']['EventTag'])) {
            $event['Event']['EventTag'] = array();
        }

        return $event;
    }

    // Loops through all servers and checks which servers' push rules don't conflict with the given event.
    // returns the server objects that would allow the event to be pushed
    public function eventFilterPushableServers($event, $servers)
    {
        $eventTags = array();
        $validServers = array();
        foreach ($event['EventTag'] as $tag) {
            $eventTags[] = $tag['tag_id'];
        }
        foreach ($servers as $server) {
            $push_rules = json_decode($server['Server']['push_rules'], true);
            if (!empty($push_rules['tags']['OR'])) {
                $intersection = array_intersect($push_rules['tags']['OR'], $eventTags);
                if (empty($intersection)) {
                    continue;
                }
            }
            if (!empty($push_rules['tags']['NOT'])) {
                $intersection = array_intersect($push_rules['tags']['NOT'], $eventTags);
                if (!empty($intersection)) {
                    continue;
                }
            }
            if (!empty($push_rules['orgs']['OR'])) {
                if (!in_array($event['Event']['orgc_id'], $push_rules['orgs']['OR'])) {
                    continue;
                }
            }
            if (!empty($push_rules['orgs']['NOT'])) {
                if (in_array($event['Event']['orgc_id'], $push_rules['orgs']['NOT'])) {
                    continue;
                }
            }
            $validServers[] = $server;
        }
        return $validServers;
    }

    public function extensionDiagnostics()
    {
        try {
            $file = new File(APP . DS . 'composer.json');
            $composer = $this->jsonDecode($file->read());
            $extensions = [];
            foreach ($composer['require'] as $require => $foo) {
                if (substr($require, 0, 4) === 'ext-') {
                    $extensions[substr($require, 4)] = true;
                }
            }
            foreach ($composer['suggest'] as $suggest => $reason) {
                if (substr($suggest, 0, 4) === 'ext-') {
                    $extensions[substr($suggest, 4)] = $reason;
                }
            }
        } catch (Exception $e) {
            $extensions = ['redis' => '', 'gd' => '', 'ssdeep' => '', 'zip' => '', 'intl' => '']; // Default extensions
        }

        $results = array();
        foreach ($extensions as $extension => $reason) {
            $results['extensions'][$extension] = [
                'web_version' => phpversion($extension),
                'web_version_outdated' => false,
                'cli_version' => false,
                'cli_version_outdated' => false,
                'required' => $reason === true,
                'info' => $reason === true ? null : $reason,
            ];
        }
        if (!is_readable(APP . '/files/scripts/selftest.php')) {
            $results['cli'] = false;
        } else {
            $execResult = exec('php ' . APP . '/files/scripts/selftest.php ' . escapeshellarg(json_encode(array_keys($extensions))));
            $execResult = $this->jsonDecode($execResult);
            $results['cli']['phpversion'] = $execResult['phpversion'];
            foreach ($execResult['extensions'] as $extension => $loaded) {
                $results['extensions'][$extension]['cli_version'] = $loaded;
            }
        }

        $minimalVersions = [
            'redis' => '2.2.8', // because of sAddArray method
        ];
        foreach ($minimalVersions as $extension => $version) {
            if (!isset($results['extensions'][$extension])) {
                continue;
            }
            $results['extensions'][$extension]['required_version'] = $version;
            foreach (['web', 'cli'] as $type) {
                if ($results['extensions'][$extension][$type . '_version']) {
                    $outdated = version_compare($results['extensions'][$extension][$type . '_version'], $version, '<');
                    $results['extensions'][$extension][$type . '_version_outdated'] = $outdated;
                }
            }
        }
        return $results;
    }

    public function databaseEncodingDiagnostics(&$diagnostic_errors)
    {
        if (!isset($this->getDataSource()->config['encoding']) || strtolower($this->getDataSource()->config['encoding']) != 'utf8') {
            $diagnostic_errors++;
            return false;
        }
        return true;
    }

    public function getLatestGitRemote()
    {
        return exec('timeout 3 git ls-remote https://github.com/MISP/MISP | head -1 | sed "s/HEAD//"');
    }

    public function getCurrentGitStatus()
    {
        $status = array();
        $status['commit'] = exec('git rev-parse HEAD');
        $status['branch'] = $this->getCurrentBranch();
        $status['latestCommit'] = $this->getLatestGitremote();
        return $status;
    }

    public function getCurrentBranch()
    {
        return exec("git symbolic-ref HEAD | sed 's!refs\/heads\/!!'");
    }

    public function checkoutMain()
    {
        $mainBranch = '2.4';
        return exec('git checkout ' . $mainBranch);
    }

    public function getSubmodulesGitStatus()
    {
        exec('cd ' . APP . '../; git submodule status --cached | grep -v ^- | cut -b 2- | cut -d " " -f 1,2 ', $submodules_names);
        $status = array();
        foreach ($submodules_names as $submodule_name_info) {
            $submodule_name_info = explode(' ', $submodule_name_info);
            $superproject_submodule_commit_id = $submodule_name_info[0];
            $submodule_name = $submodule_name_info[1];
            $temp = $this->getSubmoduleGitStatus($submodule_name, $superproject_submodule_commit_id);
            if ( !empty($temp) ) {
                $status[$submodule_name] = $temp;
            }
        }
        return $status;
    }

    private function _isAcceptedSubmodule($submodule) {
        $accepted_submodules_names = array('PyMISP',
            'app/files/misp-galaxy',
            'app/files/taxonomies',
            'app/files/misp-objects',
            'app/files/noticelists',
            'app/files/warninglists',
            'app/files/misp-decaying-models',
            'cti-python-stix2'
        );
        return in_array($submodule, $accepted_submodules_names);
    }

    public function getSubmoduleGitStatus($submodule_name, $superproject_submodule_commit_id) {
        $status = array();
        if ($this->_isAcceptedSubmodule($submodule_name)) {
            $path = APP . '../' . $submodule_name;
            $submodule_name=(strpos($submodule_name, '/') >= 0 ? explode('/', $submodule_name) : $submodule_name);
            $submodule_name=end($submodule_name);
            $submoduleRemote=exec('cd ' . $path . '; git config --get remote.origin.url');
            exec(sprintf('cd %s; git rev-parse HEAD', $path), $submodule_current_commit_id);
            if (!empty($submodule_current_commit_id[0])) {
                $submodule_current_commit_id = $submodule_current_commit_id[0];
            } else {
                $submodule_current_commit_id = null;
            }
            $status = array(
                'moduleName' => $submodule_name,
                'current' => $submodule_current_commit_id,
                'currentTimestamp' => exec(sprintf('cd %s; git log -1 --pretty=format:%%ct', $path)),
                'remoteTimestamp' => exec(sprintf('cd %s; git show -s --pretty=format:%%ct %s', $path, $superproject_submodule_commit_id)),
                'remote' => $superproject_submodule_commit_id,
                'upToDate' => '',
                'isReadable' => is_readable($path) && is_readable($path . '/.git'),
            );

            if (!empty($status['remote'])) {
                if ($status['remote'] == $status['current']) {
                    $status['upToDate'] = 'same';
                } else if ($status['currentTimestamp'] < $status['remoteTimestamp']) {
                    $status['upToDate'] = 'older';
                } else {
                    $status['upToDate'] = 'younger';
                }
            } else {
                $status['upToDate'] = 'error';
            }

            if ($status['isReadable'] && !empty($status['remoteTimestamp']) && !empty($status['currentTimestamp'])) {
                $date1 = new DateTime();
                $date1->setTimestamp($status['remoteTimestamp']);
                $date2 = new DateTime();
                $date2->setTimestamp($status['currentTimestamp']);
                $status['timeDiff'] = $date1->diff($date2);
            } else {
                $status['upToDate'] = 'error';
            }
        }
        return $status;
    }

    public function updateSubmodule($user, $submodule_name=false) {
        $path = APP . '../';
        if ($submodule_name == false) {
            $command = sprintf('cd %s; git submodule update 2>&1', $path);
            exec($command, $output, $return_code);
            $output = implode("\n", $output);
            $res = array('status' => ($return_code==0 ? true : false), 'output' => $output);
            if ($return_code == 0) { // update all DB
                $res = array_merge($res, $this->updateDatabaseAfterPullRouter($submodule_name, $user));
            }
        } else if ($this->_isAcceptedSubmodule($submodule_name)) {
            $command = sprintf('cd %s; git submodule update -- %s 2>&1', $path, $submodule_name);
            exec($command, $output, $return_code);
            $output = implode("\n", $output);
            $res = array('status' => ($return_code==0 ? true : false), 'output' => $output);
            if ($return_code == 0) { // update DB if necessary
                $res = array_merge($res, $this->updateDatabaseAfterPullRouter($submodule_name, $user));
            }
        } else {
            $res = array('status' => false, 'output' => __('Invalid submodule.'), 'job_sent' => false, 'sync_result' => __('unknown'));
        }
        return $res;
    }

    public function updateDatabaseAfterPullRouter($submodule_name, $user) {
        if (Configure::read('MISP.background_jobs')) {
            $job = ClassRegistry::init('Job');
            $job->create();
            $eventModel = ClassRegistry::init('Event');
            $data = array(
                    'worker' => $eventModel->__getPrioWorkerIfPossible(),
                    'job_type' => __('update_after_pull'),
                    'job_input' => __('Updating: ' . $submodule_name),
                    'status' => 0,
                    'retries' => 0,
                    'org_id' => $user['org_id'],
                    'org' => $user['Organisation']['name'],
                    'message' => 'Update the database after PULLing the submodule(s).',
            );
            $job->save($data);
            $jobId = $job->id;
            $process_id = CakeResque::enqueue(
                    'prio',
                    'AdminShell',
                    array('updateAfterPull', $submodule_name, $jobId, $user['id']),
                    true
            );
            $job->saveField('process_id', $process_id);
            return array('job_sent' => true, 'sync_result' => __('unknown'));
        } else {
            $result = $this->updateAfterPull($submodule_name, $user['id']);
            return array('job_sent' => false, 'sync_result' => $result);
        }
    }

    public function updateAfterPull($submodule_name, $userId) {
        $user = $this->User->getAuthUser($userId);
        $result = array();
        if ($user['Role']['perm_site_admin']) {
            $updateAll = empty($submodule_name);
            if ($submodule_name == 'app/files/misp-galaxy' || $updateAll) {
                $this->Galaxy = ClassRegistry::init('Galaxy');
                $result[] = ($this->Galaxy->update() ? 'Update `' . h($submodule_name) . '` Sucessful.' : 'Update `'. h($submodule_name) . '` failed.') . PHP_EOL;
            }
            if ($submodule_name == 'app/files/misp-objects' || $updateAll) {
                $this->ObjectTemplate = ClassRegistry::init('ObjectTemplate');
                $result[] = ($this->ObjectTemplate->update($user, false, false) ? 'Update `' . h($submodule_name) . '` Sucessful.' : 'Update `'. h($submodule_name) . '` failed.') . PHP_EOL;
            }
            if ($submodule_name == 'app/files/noticelists' || $updateAll) {
                $this->Noticelist = ClassRegistry::init('Noticelist');
                $result[] = ($this->Noticelist->update() ? 'Update `' . h($submodule_name) . '` Sucessful.' : 'Update `'. h($submodule_name) . '` failed.') . PHP_EOL;
            }
            if ($submodule_name == 'app/files/taxonomies' || $updateAll) {
                $this->Taxonomy = ClassRegistry::init('Taxonomy');
                $result[] = ($this->Taxonomy->update() ? 'Update `' . h($submodule_name) . '` Sucessful.' : 'Update `'. h($submodule_name) . '` failed.') . PHP_EOL;
            }
            if ($submodule_name == 'app/files/warninglists' || $updateAll) {
                $this->Warninglist = ClassRegistry::init('Warninglist');
                $result[] = ($this->Warninglist->update() ? 'Update `' . h($submodule_name) . '` Sucessful.' : 'Update `'. h($submodule_name) . '` failed.') . PHP_EOL;
            }
        }
        return implode('\n', $result);
    }

    public function update(array $status, &$raw = array())
    {
        $final = '';
        $workingDirectoryPrefix = 'cd $(git rev-parse --show-toplevel) && ';
        $cleanup_commands = array(
            // (>^-^)> [hacky]
            $workingDirectoryPrefix . 'git checkout app/composer.json 2>&1'
        );
        foreach ($cleanup_commands as $cleanup_command) {
            $final .= $cleanup_command . "\n\n";
            $returnCode = false;
            exec($cleanup_command, $output, $returnCode);
            $raw[] = array(
                'input' => $cleanup_command,
                'output' => $output,
                'status' => $returnCode,
            );
            $final .= implode("\n", $output) . "\n\n";
        }
        $command1 = $workingDirectoryPrefix . 'git pull origin ' . $status['branch'] . ' 2>&1';
        $command2 = $workingDirectoryPrefix . 'git submodule update --init --recursive 2>&1';
        $final .= $command1 . "\n\n";
        $returnCode = false;
        exec($command1, $output, $returnCode);
        $raw[] = array(
            'input' => $command1,
            'output' => $output,
            'status' => $returnCode,
        );
        $final .= implode("\n", $output) . "\n\n=================================\n\n";
        $output = array();
        $final .= $command2 . "\n\n";
        $returnCode = false;
        exec($command2, $output, $returnCode);
        $raw[] = array(
            'input' => $command2,
            'output' => $output,
            'status' => $returnCode,
        );
        $final .= implode("\n", $output);
        return $final;
    }

    public function fetchServer($id)
    {
        if (empty($id)) {
            return false;
        }
        $conditions = array('Server.id' => $id);
        if (!is_numeric($id)) {
            $conditions = array('OR' => array(
                'LOWER(Server.name)' => strtolower($id),
                'LOWER(Server.url)' => strtolower($id)
            ));
        }
        $server = $this->find('first', array(
            'conditions' => $conditions,
            'recursive' => -1
        ));
        return (empty($server)) ? false : $server;
    }

    public function restartWorkers($user=false)
    {
        if (Configure::read('MISP.background_jobs')) {
            $this->workerRemoveDead($user);
            $prepend = '';
            shell_exec($prepend . APP . 'Console' . DS . 'worker' . DS . 'start.sh > /dev/null 2>&1 &');
        }
        return true;
    }

    public function restartDeadWorkers($user=false)
    {
        if (Configure::read('MISP.background_jobs')) {
            $killed = $this->workerRemoveDead($user);
            foreach ($killed as $queue => $count) {
                for ($i = 0; $i < $count; $i++) {
                    $this->startWorker($queue);
                }
            }
        }
        return true;
    }

    public function restartWorker($pid)
    {
        if (Configure::read('MISP.background_jobs')) {
            $this->ResqueStatus = new ResqueStatus\ResqueStatus(Resque::redis());
            $workers = $this->ResqueStatus->getWorkers();
            $pid = intval($pid);
            if (!isset($workers[$pid])) {
                return __('Invalid worker.');
            }
            $currentWorker = $workers[$pid];
            $this->killWorker($pid, false);
            $this->startWorker($currentWorker['queue']);
            return true;
        }
        return __('Background workers not enabled.');
    }

    public function startWorker($queue)
    {
        $validTypes = array('default', 'email', 'scheduler', 'cache', 'prio', 'update');
        if (!in_array($queue, $validTypes)) {
            return __('Invalid worker type.');
        }
        if ($queue != 'scheduler') {
            shell_exec(APP . 'Console' . DS . 'cake CakeResque.CakeResque start --interval 5 --queue ' . $queue .' > /dev/null 2>&1 &');
        } else {
            shell_exec(APP . 'Console' . DS . 'cake CakeResque.CakeResque startscheduler -i 5 > /dev/null 2>&1 &');
        }
        return true;
    }

    public function cacheServerInitiator($user, $id = 'all', $jobId = false)
    {
        $params = array(
            'conditions' => array('caching_enabled' => 1),
            'recursive' => -1
        );
        $redis = $this->setupRedis();
        if ($redis === false) {
            return 'Redis not reachable.';
        }
        if ($id !== 'all') {
            $params['conditions']['Server.id'] = $id;
        } else {
            $redis->del('misp:server_cache:combined');
            $redis->del($redis->keys('misp:server_cache:event_uuid_lookup:*'));
        }
        $servers = $this->find('all', $params);
        if ($jobId) {
            $job = ClassRegistry::init('Job');
            $job->id = $jobId;
            if (!$job->exists()) {
                $jobId = false;
            }
        }
        foreach ($servers as $k => $server) {
            $this->__cacheInstance($server, $redis, $jobId);
            if ($jobId) {
                $job->saveField('progress', 100 * $k / count($servers));
                $job->saveField('message', 'Server ' . $server['Server']['id'] . ' cached.');
            }
        }
        return true;
    }

    private function __cacheInstance($server, $redis, $jobId = false)
    {
        $continue = true;
        $i = 0;
        if ($jobId) {
            $job = ClassRegistry::init('Job');
            $job->id = $jobId;
        }
        $redis->del('misp:server_cache:' . $server['Server']['id']);
        $HttpSocket = null;
        $HttpSocket = $this->setupHttpSocket($server, $HttpSocket);
        while ($continue) {
            $i++;
            $pipe = $redis->multi(Redis::PIPELINE);
            $chunk_size = 50000;
            $data = $this->__getCachedAttributes($server, $HttpSocket, $chunk_size, $i);
            if (empty(trim($data))) {
                $continue = false;
            } else {
                $data = explode(PHP_EOL, trim($data));
                foreach ($data as $entry) {
                    list($value, $uuid) = explode(',', $entry);
                    if (!empty($value)) {
                        $redis->sAdd('misp:server_cache:' . $server['Server']['id'], $value);
                        $redis->sAdd('misp:server_cache:combined', $value);
                        $redis->sAdd('misp:server_cache:event_uuid_lookup:' . $value, $server['Server']['id'] . '/' . $uuid);
                    }
                }
            }
            if ($jobId) {
                $job->saveField('message', 'Server ' . $server['Server']['id'] . ': ' . ((($i -1) * $chunk_size) + count($data)) . ' attributes cached.');
            }
            $pipe->exec();
        }
        $redis->set('misp:server_cache_timestamp:' . $server['Server']['id'], time());
        return true;
    }

    private function __getCachedAttributes($server, $HttpSocket, $chunk_size, $i)
    {
        $filter_rules = array(
            'returnFormat' => 'cache',
            'includeEventUuid' => 1,
            'page' => $i,
            'limit' => $chunk_size
        );
        $request = $this->setupSyncRequest($server);
        try {
            $response = $HttpSocket->post($server['Server']['url'] . '/attributes/restSearch.json', json_encode($filter_rules), $request);
        } catch (SocketException $e) {
            return $e->getMessage();
        }
        return $response->body;
    }

    public function attachServerCacheTimestamps($data)
    {
        $redis = $this->setupRedis();
        if ($redis === false) {
            return $data;
        }
        foreach ($data as $k => $v) {
            $data[$k]['Server']['cache_timestamp'] = $redis->get('misp:server_cache_timestamp:' . $data[$k]['Server']['id']);
        }
        return $data;
    }

    public function updateJSON()
    {
        $toUpdate = array('Galaxy', 'Noticelist', 'Warninglist', 'Taxonomy', 'ObjectTemplate');
        $results = array();
        foreach ($toUpdate as $target) {
            $this->$target = ClassRegistry::init($target);
            $result = $this->$target->update();
            $results[$target] = $result === false ? false : true;
        }
        return $results;
    }

    public function resetRemoteAuthKey($id)
    {
        $server = $this->find('first', array(
            'recursive' => -1,
            'conditions' => array('Server.id' => $id)
        ));
        if (empty($server)) {
            return __('Invalid server');
        }
        $HttpSocket = $this->setupHttpSocket($server);
        $request = $this->setupSyncRequest($server);
        $uri = $server['Server']['url'] . '/users/resetauthkey/me';
        try {
            $response = $HttpSocket->post($uri, '{}', $request);
        } catch (Exception $e) {
            $this->Log = ClassRegistry::init('Log');
            $this->Log->create();
            $message = 'Could not reset the remote authentication key.';
            $this->Log->save(array(
                    'org' => 'SYSTEM',
                    'model' => 'Server',
                    'model_id' => $id,
                    'email' => 'SYSTEM',
                    'action' => 'error',
                    'user_id' => 0,
                    'title' => 'Error: ' . $message,
            ));
            return $message;
        }
        if ($response->isOk()) {
            try {
                $response = $this->jsonDecode($response->body);
            } catch (Exception $e) {
                $message = 'Invalid response received from the remote instance.';

                $this->logException($message, $e);

                $this->Log = ClassRegistry::init('Log');
                $this->Log->create();
                $this->Log->save(array(
                        'org' => 'SYSTEM',
                        'model' => 'Server',
                        'model_id' => $id,
                        'email' => 'SYSTEM',
                        'action' => 'error',
                        'user_id' => 0,
                        'title' => 'Error: ' . $message,
                ));
                return $message;
            }
            if (!empty($response['message'])) {
                $authkey = $response['message'];
            }
            if (substr($authkey, 0, 17) === 'Authkey updated: ') {
                $authkey = substr($authkey, 17, 57);
            }
            $server['Server']['authkey'] = $authkey;
            $this->save($server);
            return true;
        } else {
            return __('Could not reset the remote authentication key.');
        }
    }

    public function reprioritise($id = false, $direction = 'up')
    {
        $servers = $this->find('all', array(
            'recursive' => -1,
            'order' => array('Server.priority ASC', 'Server.id ASC')
        ));
        $success = true;
        if ($id) {
            foreach ($servers as $k => $server) {
                if ($server['Server']['id'] && $server['Server']['id'] == $id) {
                    if (
                        !($k === 0 && $direction === 'up') &&
                        !(empty($servers[$k+1]) && $direction === 'down')
                    ) {
                        $temp = $servers[$k];
                        $destination = $direction === 'up' ? $k-1 : $k+1;
                        $servers[$k] = $servers[$destination];
                        $servers[$destination] = $temp;
                    } else {
                        $success = false;
                    }
                }
            }
        }
        foreach ($servers as $k => $server) {
            $server['Server']['priority'] = $k + 1;
            $result = $this->save($server);
            $success = $success && $result;
        }
        return $success;
    }

    /**
     * @param int $serverId
     * @param string $relativeUri
     * @param HttpSocket|null $HttpSocket
     * @return array
     * @throws Exception
     */
    private function serverGetRequest($serverId, $relativeUri, HttpSocket $HttpSocket = null)
    {
        $server = $this->find('first', array(
            'conditions' => array('Server.id' => $serverId),
        ));
        if ($server === null) {
            throw new Exception(__("Server with ID '$serverId' not found."));
        }

        if (!$HttpSocket) {
            $HttpSocket = $this->setupHttpSocket($server);
        }
        $request = $this->setupSyncRequest($server);

        $uri = $server['Server']['url'] . $relativeUri;
        $response = $HttpSocket->get($uri, array(), $request);

        if ($response === false) {
            throw new Exception(__("Could not reach '$uri'."));
        } else if ($response->code == 404) { // intentional !=
            throw new NotFoundException(__("Fetching the '$uri' failed with HTTP error 404: Not Found"));
        } else if ($response->code == 405) { // intentional !=
            $responseText = json_decode($response->body, true);
            if ($responseText !== null) {
                throw new Exception(sprintf(__("Fetching the '$uri' failed with HTTP error %s: %s"), $response->code, $responseText['message']));
            }
        }

        if ($response->code != 200) { // intentional !=
            throw new Exception(sprintf(__("Fetching the '$uri' failed with HTTP error %s: %s"), $response->code, $response->reasonPhrase));
        }

        $data = json_decode($response->body, true);
        if ($data === null) {
            throw new Exception(__('Could not parse JSON: ') . json_last_error_msg(), json_last_error());
        }

        return array($data, $response);
    }

    public function getRemoteUser($id)
    {
        $server = $this->find('first', array(
            'conditions' => array('Server.id' => $id),
            'recursive' => -1
        ));
        $HttpSocket = $this->setupHttpSocket($server);
        $request = $this->setupSyncRequest($server);
        $uri = $server['Server']['url'] . '/users/view/me.json';
        try {
            $response = $HttpSocket->get($uri, false, $request);
        } catch (Exception $e) {
            $this->Log = ClassRegistry::init('Log');
            $this->Log->create();
            $message = __('Could not reset fetch remote user account.');
            $this->Log->save(array(
                    'org' => 'SYSTEM',
                    'model' => 'Server',
                    'model_id' => $id,
                    'email' => 'SYSTEM',
                    'action' => 'error',
                    'user_id' => 0,
                    'title' => 'Error: ' . $message,
            ));
            return $message;
        }
        if ($response->isOk()) {
            $user = json_decode($response->body, true);
            if (!empty($user['User'])) {
                $result = array(
                    'Email' => $user['User']['email'],
                    'Role name' => isset($user['Role']['name']) ? $user['Role']['name'] : 'Unknown, outdated instance',
                    'Sync flag' => isset($user['Role']['perm_sync']) ? ($user['Role']['perm_sync'] ? 1 : 0) : 'Unknown, outdated instance'
                );
                return $result;
            } else {
                return __('No user object received in response.');
            }
        } else {
            return $response->code;
        }
    }
}
