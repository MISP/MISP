<?php
App::uses('AppModel', 'Model');

class Server extends AppModel {

	public $name = 'Server';

	public $actsAs = array('SysLogLogable.SysLogLogable' => array(	// TODO Audit, logable, check: 'userModel' and 'userKey' can be removed given default
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
		'url' => array( // TODO add extra validation to refuse multiple time the same url from the same org
			'url' => array(
				'rule' => array('url'),
				'message' => 'Please enter a valid base-url.',
				//'allowEmpty' => false,
				//'required' => false,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			)
		),
		'authkey' => array(
			'minlength' => array(
				'rule' => array('minlength', 40),
				'message' => 'A authkey of a minimum length of 40 is required.',
				'required' => true,
			),
			'valueNotEmpty' => array(
				'rule' => array('valueNotEmpty'),
			),
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

	public $serverSettings = array(
			'MISP' => array(
					'branch' => 1,
					'baseurl' => array(
							'level' => 0,
							'description' => 'The base url of the application (in the format https://www.mymispinstance.com). Several features depend on this setting being correctly set to function.',
							'value' => '',
							'errorMessage' => 'The currenty set baseurl does not match the URL through which you have accessed the page. Disregard this if you are accessing the page via an alternate URL (for example via IP address).',
							'test' => 'testBaseURL',
							'type' => 'string',
					),
					'live' => array(
							'level' => 0,
							'description' => 'Unless set to true, the instance will only be accessible by site admins.',
							'value' => false,
							'errorMessage' => '',
							'test' => 'testLive',
							'type' => 'boolean',
					),
					'enable_advanced_correlations' => array(
							'level' => 0,
							'description' => 'Enable some performance heavy correlations (currently CIDR correlation)',
							'value' => false,
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean',
							'null' => true
					),
					'max_correlations_per_event' => array(
							'level' => 1,
							'description' => 'Sets the maximum number of correlations that can be fetched with a single event. For extreme edge cases this can prevent memory issues. The default value is 5k.',
							'value' => 5000,
							'errorMessage' => '',
							'test' => 'testForNumeric',
							'type' => 'numeric',
							'null' => true
					),
					'maintenance_message' => array(
							'level' => 2,
							'description' => 'The message that users will see if the instance is not live.',
							'value' => 'Great things are happening! MISP is undergoing maintenance, but will return shortly. You can contact the administration at $email.',
							'errorMessage' => 'If this is not set the default value will be used.',
							'test' => 'testForEmpty',
							'type' => 'string',
					),
					'name' => array(
							'level' => 3,
							'description' => 'This setting is deprecated and can be safely removed.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
					),
					'version' => array(
							'level' => 3,
							'description' => 'This setting is deprecated and can be safely removed.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
					),
					'disable_cached_exports' => array(
							'level' => 1,
							'description' => 'Cached exports can take up a considerable amount of space and can be disabled instance wide using this setting. Disabling the cached exports is not recommended as it\'s a valuable feature, however, if your server is having free space issues it might make sense to take this step.',
							'value' => false,
							'null' => true,
							'errorMessage' => '',
							'test' => 'testDisableCache',
							'type' => 'boolean',
							'afterHook' => 'disableCacheAfterHook',
					),
					'header' => array(
							'level' => 3,
							'description' => 'This setting is deprecated and can be safely removed.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
					),
					'footermidleft' => array(
							'level' => 2,
							'description' => 'Footer text prepending the "Powered by MISP" text.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
					),
					'footermidright' => array(
							'level' => 2,
							'description' => 'Footer text following the "Powered by MISP" text.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
					),
					'footerpart1' => array(
							'level' => 3,
							'description' => 'This setting is deprecated and can be safely removed.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
					),
					'footerpart2' => array(
							'level' => 3,
							'description' => 'This setting is deprecated and can be safely removed.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
					),
					'footer' => array(
							'level' => 3,
							'description' => 'This setting is deprecated and can be safely removed.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
					),
					'footerversion' => array(
							'level' => 3,
							'description' => 'This setting is deprecated and can be safely removed.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
					),
					'footer_logo' => array(
							'level' => 2 ,
							'description' => 'If set, this setting allows you to display a logo on the right side of the footer. Upload it as a custom image in the file management tool.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForCustomImage',
							'type' => 'string',
					),
					'home_logo' => array(
							'level' => 2 ,
							'description' => 'If set, this setting allows you to display a logo as the home icon. Upload it as a custom image in the file management tool.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForCustomImage',
							'type' => 'string',
					),
					'main_logo' => array(
							'level' => 2 ,
							'description' => 'If set, the image specified here will replace the main MISP logo on the login screen. Upload it as a custom image in the file management tool.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForCustomImage',
							'type' => 'string',
					),
					'org' => array(
							'level' => 1,
							'description' => 'The organisation tag of the hosting organisation. This is used in the e-mail subjects.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
					),
					'host_org_id' => array(
							'level' => 0,
							'description' => 'The hosting organisation of this instance. If this is not selected then replication instances cannot be added.',
							'value' => '0',
							'errorMessage' => '',
							'test' => 'testLocalOrg',
							'type' => 'numeric',
							'optionsSource' => 'LocalOrgs',
					),
					'uuid' => array(
							'level' => 0,
							'description' => 'The MISP instance UUID. This UUID is used to identify this instance.',
							'value' => '0',
							'errorMessage' => 'No valid UUID set',
							'test' => 'testUuid',
							'type' => 'string'
					),
					'logo' => array(
							'level' => 3,
							'description' => 'This setting is deprecated and can be safely removed.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
					),
					'showorg' => array(
							'level' => 0,
							'description' => 'Setting this setting to \'false\' will hide all organisation names / logos.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean',
					),
					'threatlevel_in_email_subject' => array(
							'level' => 2,
							'description' => 'Put the event threat level in the notification E-mail subject.',
							'value' => true,
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean',
						),
					'email_subject_TLP_string' => array(
							'level' => 2,
							'description' => 'This is the TLP string for e-mails when email_subject_tag is not found.',
							'value' => 'TLP Amber',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
						),
					'email_subject_tag' => array(
							'level' => 2,
							'description' => "If this tag is set on an event it's value will be sent in the E-mail subject. If the tag is not set the email_subject_TLP_string will be used.",
							'value' => 'tlp',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
						),
					'email_subject_include_tag_name' => array(
							'level' => 2,
							'description' => 'Include in name of the email_subject_tag in the subject. When false only the tag value is used.',
							'value' => true,
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean',
						),
					'taxii_sync' => array(
							'level' => 3,
							'description' => 'This setting is deprecated and can be safely removed.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
					),
					'taxii_client_path' => array(
							'level' => 3,
							'description' => 'This setting is deprecated and can be safely removed.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
					),
					'background_jobs' => array(
							'level' => 1,
							'description' => 'Enables the use of MISP\'s background processing.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean',
					),
					'attachments_dir' => array(
							'level' => 2,
							'description' => 'Directory where attachments are stored. MISP will NOT migrate the existing data if you change this setting. The only safe way to change this setting is in config.php, when MISP is not running, and after having moved/copied the existing data to the new location. This directory must already exist and be writable and readable by the MISP application.',
							'value' =>  'app/files', # GUI display purpose only. Default value defined in func getDefaultAttachments_dir()
							'errorMessage' => '',
							'null' => false,
							'test' => 'testForWritableDir',
							'type' => 'string',
					),
					'cached_attachments' => array(
							'level' => 1,
							'description' => 'Allow the XML caches to include the encoded attachments.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean',
					),
					'email' => array(
							'level' => 0,
							'description' => 'The e-mail address that MISP should use for all notifications',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
					),
					'disable_emailing' => array(
							'level' => 0,
							'description' => 'You can disable all e-mailing using this setting. When enabled, no outgoing e-mails will be sent by MISP.',
							'value' => false,
							'errorMessage' => '',
							'null' => true,
							'test' => 'testDisableEmail',
							'type' => 'boolean',
					),
					'contact' => array(
							'level' => 1,
							'description' => 'The e-mail address that MISP should include as a contact address for the instance\'s support team.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
					),
					'dns' => array(
							'level' => 3,
							'description' => 'This setting is deprecated and can be safely removed.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
					),
					'cveurl' => array(
							'level' => 1,
							'description' => 'Turn Vulnerability type attributes into links linking to the provided CVE lookup',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
					),
					'disablerestalert' => array(
							'level' => 1,
							'description' => 'This setting controls whether notification e-mails will be sent when an event is created via the REST interface. It might be a good idea to disable this setting when first setting up a link to another instance to avoid spamming your users during the initial pull. Quick recap: True = Emails are NOT sent, False = Emails are sent on events published via sync / REST.',
							'value' => true,
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean',
					),
					'extended_alert_subject' => array(
							'level' => 1,
							'description' => 'enabling this flag will allow the event description to be transmitted in the alert e-mail\'s subject. Be aware that this is not encrypted by PGP, so only enable it if you accept that part of the event description will be sent out in clear-text.',
							'value' => false,
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean'
					),
					'default_event_distribution' => array(
							'level' => 0,
							'description' => 'The default distribution setting for events (0-3).',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
							'options' => array('0' => 'Your organisation only', '1' => 'This community only', '2' => 'Connected communities', '3' => 'All communities'),
					),
					'default_attribute_distribution' => array(
							'level' => 0,
							'description' => 'The default distribution setting for attributes, set it to \'event\' if you would like the attributes to default to the event distribution level. (0-3 or "event")',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
							'options' => array('0' => 'Your organisation only', '1' => 'This community only', '2' => 'Connected communities', '3' => 'All communities', 'event' => 'Inherit from event'),
					),
					'default_event_threat_level' => array(
							'level' => 1,
							'description' => 'The default threat level setting when creating events.',
							'value' => '4',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
							'options' => array('1' => 'High', '2' => 'Medium', '3' => 'Low', '4' => 'undefined'),
					),
					'tagging' => array(
							'level' => 1,
							'description' => 'Enable the tagging feature of MISP. This is highly recommended.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean',
					),
					'full_tags_on_event_index' => array(
							'level' => 2,
							'description' =>'Show the full tag names on the event index.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
							'options' => array(0 => 'Minimal tags', 1 => 'Full tags', 2 => 'Shortened tags'),
					),
					'welcome_text_top' => array(
							'level' => 2,
							'description' => 'Used on the login page, before the MISP logo',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
					),
					'welcome_text_bottom' => array(
							'level' => 2,
							'description' => 'Used on the login page, after the MISP logo',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
					),
					'welcome_logo' => array(
							'level' => 2,
							'description' => 'Used on the login page, to the left of the MISP logo, upload it as a custom image in the file management tool.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForCustomImage',
							'type' => 'string',
					),
					'welcome_logo2' => array(
							'level' => 2,
							'description' => 'Used on the login page, to the right of the MISP logo, upload it as a custom image in the file management tool.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForCustomImage',
							'type' => 'string',
					),
					'title_text' => array(
						'level' => 2,
						'description' => 'Used in the page title, after the name of the page',
						'value' => 'MISP',
						'errorMessage' => '',
						'test' => 'testForEmpty',
						'type' => 'string',
					),
					'take_ownership_xml_import' => array(
							'level' => 2,
							'description' => 'Allows users to take ownership of an event uploaded via the "Add MISP XML" button. This allows spoofing the creator of a manually imported event, also breaking possibly breaking the original intended releasability. Synchronising with an instance that has a different creator for the same event can lead to unwanted consequences.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean',
					),
					'terms_download' => array(
							'level' => 2,
							'description' => 'Choose whether the terms and conditions should be displayed inline (false) or offered as a download (true)',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean'
					),
					'terms_file' => array(
							'level' => 2,
							'description' => 'The filename of the terms and conditions file. Make sure that the file is located in your MISP/app/files/terms directory',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForTermsFile',
							'type' => 'string'
					),
					'showorgalternate' => array(
							'level' => 2,
							'description' => 'True enables the alternate org fields for the event index (source org and member org) instead of the traditional way of showing only an org field. This allows users to see if an event was uploaded by a member organisation on their MISP instance, or if it originated on an interconnected instance.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean'
					),
					'unpublishedprivate' => array(
							'level' => 2,
							'description' => 'True will deny access to unpublished events to users outside the organization of the submitter except site admins.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean'
					),
					'newUserText' => array(
							'level' => 1,
							'bigField' => true,
							'description' => 'The message sent to the user after account creation (has to be sent manually from the administration interface). Use \\n for line-breaks. The following variables will be automatically replaced in the text: $password = a new temporary password that MISP generates, $username = the user\'s e-mail address, $misp = the url of this instance, $org = the organisation that the instance belongs to, as set in MISP.org, $contact = the e-mail address used to contact the support team, as set in MISP.contact. For example, "the password for $username is $password" would appear to a user with the e-mail address user@misp.org as "the password for user@misp.org is hNamJae81".',
							'value' => 'Dear new MISP user,\n\nWe would hereby like to welcome you to the $org MISP community.\n\n Use the credentials below to log into MISP at $misp, where you will be prompted to manually change your password to something of your own choice.\n\nUsername: $username\nPassword: $password\n\nIf you have any questions, don\'t hesitate to contact us at: $contact.\n\nBest regards,\nYour $org MISP support team',
							'errorMessage' => '',
							'test' => 'testPasswordResetText',
							'type' => 'string'
					),
					'passwordResetText' => array(
							'level' => 1,
							'bigField' => true,
							'description' => 'The message sent to the users when a password reset is triggered. Use \\n for line-breaks. The following variables will be automatically replaced in the text: $password = a new temporary password that MISP generates, $username = the user\'s e-mail address, $misp = the url of this instance, $contact = the e-mail address used to contact the support team, as set in MISP.contact. For example, "the password for $username is $password" would appear to a user with the e-mail address user@misp.org as "the password for user@misp.org is hNamJae81".',
							'value' => 'Dear MISP user,\n\nA password reset has been triggered for your account. Use the below provided temporary password to log into MISP at $misp, where you will be prompted to manually change your password to something of your own choice.\n\nUsername: $username\nYour temporary password: $password\n\nIf you have any questions, don\'t hesitate to contact us at: $contact.\n\nBest regards,\nYour $org MISP support team',
							'errorMessage' => '',
							'test' => 'testPasswordResetText',
							'type' => 'string'
					),
					'enableEventBlacklisting' => array(
							'level' => 1,
							'description' => 'Since version 2.3.107 you can start blacklisting event UUIDs to prevent them from being pushed to your instance. This functionality will also happen silently whenever an event is deleted, preventing a deleted event from being pushed back from another instance.',
							'value' => true,
							'type' => 'boolean',
							'test' => 'testBool'
					),
					'enableOrgBlacklisting' => array(
							'level' => 1,
							'description' => 'Blacklisting organisation UUIDs to prevent the creation of any event created by the blacklisted organisation.',
							'value' => true,
							'type' => 'boolean',
							'test' => 'testBool'
					),
					'log_client_ip' => array(
							'level' => 1,
							'description' => 'If enabled, all log entries will include the IP address of the user.',
							'value' => false,
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean',
							'beforeHook' => 'ipLogBeforeHook'
					),
					'log_auth' => array(
							'level' => 1,
							'description' => 'If enabled, MISP will log all successful authentications using API keys. The requested URLs are also logged.',
							'value' => false,
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean',
					),
					'delegation' => array(
							'level' => 1,
							'description' => 'This feature allows users to created org only events and ask another organisation to take owenership of the event. This allows organisations to remain anonymous by asking a partner to publish an event for them.',
							'value' => false,
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean',
							'null' => true
					),
					'showCorrelationsOnIndex' => array(
							'level' => 1,
							'description' => 'When enabled, the number of correlations visible to the currently logged in user will be visible on the event index UI. This comes at a performance cost but can be very useful to see correlating events at a glance.',
							'value' => false,
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean',
							'null' => true
					),
					'showProposalsCountOnIndex' => array(
							'level' => 1,
							'description' => 'When enabled, the number of proposals for the events are shown on the index.',
							'value' => false,
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean',
							'null' => true
					),
					'showSightingsCountOnIndex' => array(
							'level' => 1,
							'description' => 'When enabled, the aggregate number of attribute sightings within the event becomes visible to the currently logged in user on the event index UI.',
							'value' => false,
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean',
							'null' => true
					),
					'showDiscussionsCountOnIndex' => array(
							'level' => 1,
							'description' => 'When enabled, the aggregate number of discussion posts for the event becomes visible to the currently logged in user on the event index UI.',
							'value' => false,
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean',
							'null' => true
					),
					'disableUserSelfManagement' => array(
							'level' => 1,
							'description' => 'When enabled only Org and Site admins can edit a user\'s profile.',
							'value' => false,
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean',
							'null' => false,

					),
					'block_event_alert' => array(
							'level' => 1,
							'description' => 'Enable this setting to start blocking alert e-mails for events with a certain tag. Define the tag in MISP.block_event_alert_tag.',
							'value' => false,
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean',
							'null' => false,
					),
					'block_event_alert_tag' => array(
							'level' => 1,
							'description' => 'If the MISP.block_event_alert setting is set, alert e-mails for events tagged with the tag defined by this setting will be blocked.',
							'value' => 'no-alerts="true"',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
							'null' => false,
					),
					'block_old_event_alert' => array(
							'level' => 1,
							'description' => 'Enable this setting to start blocking alert e-mails for old events. The exact timing of what constitutes an old event is defined by MISP.block_old_event_alert_age.',
							'value' => false,
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean',
							'null' => false,
					),
					'block_old_event_alert_age' => array(
							'level' => 1,
							'description' => 'If the MISP.block_old_event_alert setting is set, this setting will control how old an event can be for it to be alerted on. The "Date" field of the event is used. Expected format: integer, in days',
							'value' => false,
							'errorMessage' => '',
							'test' => 'testForNumeric',
							'type' => 'numeric',
							'null' => false,
					),
					'rh_shell_fix' => array(
							'level' => 1,
							'description' => 'If you are running CentOS or RHEL using SCL and are having issues with the Background workers not responding to start/stop/restarts via the worker interface, enable this setting. This will pre-pend the shell execution commands with the default path to rh-php56 (/opt/rh/rh-php56/root/usr/bin:/opt/rh/rh-php56/root/usr/sbin).',
							'value' => false,
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean',
							'null' => true,
					),
					'rh_shell_fix_path' => array(
							'level' => 1,
							'description' => 'If you have rh_shell_fix enabled, the default PATH for rh-php56 is added (/opt/rh/rh-php56/root/usr/bin:/opt/rh/rh-php56/root/usr/sbin). If you prefer to use a different path, you can set it here.',
							'value' => '/opt/rh/rh-php56/root/usr/bin:/opt/rh/rh-php56/root/usr/sbin',
							'errorMessage' => '',
							'test' => 'testForPath',
							'type' => 'string',
							'null' => true,
					),
					'tmpdir' => array(
							'level' => 1,
							'description' => 'Please indicate the temp directory you wish to use for certain functionalities in MISP. By default this is set to /tmp and will be used among others to store certain temporary files extracted from imports during the import process.',
							'value' => '/tmp',
							'errorMessage' => '',
							'test' => 'testForPath',
							'type' => 'string',
							'null' => true,
					),
					'custom_css' => array(
							'level' => 2,
							'description' => 'If you would like to customise the css, simply drop a css file in the /var/www/MISP/webroot/css directory and enter the name here.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForStyleFile',
							'type' => 'string',
							'null' => true,
					),
					'proposals_block_attributes' => array(
							'level' => 0,
							'description' => 'Enable this setting to allow blocking attributes from to_ids sensitive exports if a proposal has been made to it to remove the IDS flag or to remove the attribute altogether. This is a powerful tool to deal with false-positives efficiently.',
							'value' => false,
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean',
							'null' => false,
					),
					'incoming_tags_disabled_by_default' => array(
							'level' => 1,
							'description' => 'Enable this settings if new tags synced / added via incoming events from any source should not be selectable by users by default.',
							'value' => false,
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean',
							'null' => false
					),
					'completely_disable_correlation' => array(
							'level' => 0,
							'description' => '*WARNING* This setting will completely disable the correlation on this instance and remove any existing saved correlations. Enabling this will trigger a full recorrelation of all data which is an extremely long and costly procedure. Only enable this if you know what you\'re doing.',
							'value' => false,
							'errorMessage' => '',
							'test' => 'testBoolFalse',
							'type' => 'boolean',
							'null' => true,
							'afterHook' => 'correlationAfterHook',
					),
					'allow_disabling_correlation' => array(
							'level' => 0,
							'description' => '*WARNING* This setting will give event creators the possibility to disable the correlation of individual events / attributes that they have created.',
							'value' => false,
							'errorMessage' => '',
							'test' => 'testBoolFalse',
							'type' => 'boolean',
							'null' => true
					),
					'redis_host' => array(
						'level' => 0,
						'description' => 'The host running the redis server to be used for generic MISP tasks such as caching. This is not to be confused by the redis server used by the background processing.',
						'value' => '127.0.0.1',
						'errorMessage' => '',
						'test' => 'testForEmpty',
						'type' => 'string'
					),
					'redis_port' => array(
						'level' => 0,
						'description' => 'The port used by the redis server to be used for generic MISP tasks such as caching. This is not to be confused by the redis server used by the background processing.',
						'value' => 6379,
						'errorMessage' => '',
						'test' => 'testForNumeric',
						'type' => 'numeric'
					),
					'redis_database' => array(
						'level' => 0,
						'description' => 'The database on the redis server to be used for generic MISP tasks. If you run more than one MISP instance, please make sure to use a different database on each instance.',
						'value' => 13,
						'errorMessage' => '',
						'test' => 'testForNumeric',
						'type' => 'numeric'
					),
					'redis_password' => array(
						'level' => 0,
						'description' => 'The password on the redis server (if any) to be used for generic MISP tasks.',
						'value' => '',
						'errorMessage' => '',
						'test' => null,
						'type' => 'string',
						'redacted' => true
					),
					'event_view_filter_fields' => array(
						'level' => 2,
						'description' => 'Specify which fields to filter on when you search on the event view. Default values are : "id, uuid, value, comment, type, category, Tag.name"',
						'value' => 'id, uuid, value, comment, type, category, Tag.name',
						'errorMessage' => '',
						'test' => null,
						'type' => 'string',
					)
			),
			'GnuPG' => array(
					'branch' => 1,
					'binary' => array(
							'level' => 2,
							'description' => 'The location of the GPG executable. If you would like to use a different gpg executable than /usr/bin/gpg, you can set it here. If the default is fine, just keep the setting suggested by MISP.',
							'value' => '/usr/bin/gpg',
							'errorMessage' => '',
							'test' => 'testForGPGBinary',
							'type' => 'string',
					),
					'onlyencrypted' => array(
							'level' => 0,
							'description' => 'Allow (false) unencrypted e-mails to be sent to users that don\'t have a PGP key.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean',
					),
					'bodyonlyencrypted' => array(
							'level' => 2,
							'description' => 'Allow (false) the body of unencrypted e-mails to contain details about the event.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean',
					),
					'email' => array(
							'level' => 0,
							'description' => 'The e-mail address that the instance\'s PGP key is tied to.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
					),
					'password' => array(
							'level' => 1,
							'description' => 'The password (if it is set) of the PGP key of the instance.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
							'redacted' => true
					),
					'homedir' => array(
							'level' => 0,
							'description' => 'The location of the GPG homedir.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
					)
			),
			'SMIME' => array(
					'branch' => 1,
					'enabled' => array(
							'level' => 2,
							'description' => 'Enable SMIME encryption. The encryption posture of the GnuPG.onlyencrypted and GnuPG.bodyonlyencrypted settings are inherited if SMIME is enabled.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean',
					),
					'email' => array(
							'level' => 2,
							'description' => 'The e-mail address that the instance\'s SMIME key is tied to.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
					),
					'cert_public_sign' => array(
							'level' => 2,
							'description' => 'The location of the public half of the signing certificate.',
							'value' => '/var/www/MISP/.smime/email@address.com.pem',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
					),
					'key_sign' => array(
							'level' => 2,
							'description' => 'The location of the private half of the signing certificate.',
							'value' => '/var/www/MISP/.smime/email@address.com.key',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
					),
					'password' => array(
							'level' => 2,
							'description' => 'The password (if it is set) of the SMIME key of the instance.',
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
							'description' => 'The hostname of an HTTP proxy for outgoing sync requests. Leave empty to not use a proxy.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
					),
					'port' => array(
							'level' => 2,
							'description' => 'The TCP port for the HTTP proxy.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForNumeric',
							'type' => 'numeric',
					),
					'method' => array(
							'level' => 2,
							'description' => 'The authentication method for the HTTP proxy. Currently supported are Basic or Digest. Leave empty for no proxy authentication.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
					),
					'user' => array(
							'level' => 2,
							'description' => 'The authentication username for the HTTP proxy.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
					),
					'password' => array(
							'level' => 2,
							'description' => 'The authentication password for the HTTP proxy.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
					),
			),
			'Security' => array(
					'branch' => 1,
					'salt' => array(
							'level' => 0,
							'description' => 'The salt used for the hashed passwords. You cannot reset this from the GUI, only manually from the settings.php file. Keep in mind, this will invalidate all passwords in the database.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testSalt',
							'type' => 'string',
							'editable' => false,
					),
					'syslog' => array(
						'level' => 0,
						'description' => 'Enable this setting to pass all audit log entries directly to syslog. Keep in mind, this is verbose and will include user, organisation, event data.',
						'value' => false,
						'errorMessage' => '',
						'test' => 'testBool',
						'type' => 'boolean',
						'null' => true
					),
					'password_policy_length' => array(
							'level' => 2,
							'description' => 'Password length requirement. If it is not set or it is set to 0, then the default value is assumed (12).',
							'value' => '12',
							'errorMessage' => '',
							'test' => 'testPasswordLength',
							'type' => 'numeric',
					),
					'password_policy_complexity' => array(
							'level' => 2,
							'description' => 'Password complexity requirement. Leave it empty for the default setting (3 out of 4, with either a digit or a special char) or enter your own regex. Keep in mind that the length is checked in another key. Default (simple 3 out of 4 or minimum 16 characters): /^((?=.*\d)|(?=.*\W+))(?![\n])(?=.*[A-Z])(?=.*[a-z]).*$|.{16,}/',
							'value' => '/^((?=.*\d)|(?=.*\W+))(?![\n])(?=.*[A-Z])(?=.*[a-z]).*$|.{16,}/',
							'errorMessage' => '',
							'test' => 'testPasswordRegex',
							'type' => 'string',
					),
					'require_password_confirmation' => array(
						'level' => 1,
						'description' => 'Enabling this setting will require users to submit their current password on any edits to their profile (including a triggered password change). For administrators, the confirmation will be required when changing the profile of any user. Could potentially mitigate an attacker trying to change a compromised user\'s password in order to establish persistance, however, enabling this feature will be highly annoying to users.',
						'value' => false,
						'errorMessage' => '',
						'test' => 'testBool',
						'type' => 'boolean',
						'null' => true
					),
					'sanitise_attribute_on_delete' => array(
						'level' => 1,
						'description' => 'Enabling this setting will sanitise the contents of an attribute on a soft delete',
						'value' => false,
						'errorMessage' => '',
						'test' => 'testBool',
						'type' => 'boolean',
						'null' => true
					),
					'hide_organisation_index_from_users' => array(
						'level' => 1,
						'description' => 'Enabling this setting will block the organisation index from being visible to anyone besides site administrators on the current instance. Keep in mind that users can still see organisations that produce data via events, proposals, event history log entries, etc.',
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
							'description' => 'The number of tries a user can try to login and fail before the bruteforce protection kicks in.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForNumeric',
							'type' => 'string',
					),
					'expire' => array(
							'level' => 0,
							'description' => 'The duration (in seconds) of how long the user will be locked out when the allowed number of login attempts are exhausted.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForNumeric',
							'type' => 'string',
					),
			),
			'Session' => array(
					'branch' => 1,
					'autoRegenerate' => array(
							'level' => 1,
							'description' => 'Set to true to automatically regenerate sessions on activity. (Recommended)',
							'value' => false,
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean',
					),
					'defaults' => array(
							'level' => 0,
							'description' => 'The session type used by MISP. The default setting is php, which will use the session settings configured in php.ini for the session data (supported options: php, database). The recommended option is php and setting your PHP up to use redis sessions via your php.ini. Just add \'session.save_handler = redis\' and "session.save_path = \'tcp://localhost:6379\'" (replace the latter with your redis connection) to ',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForSessionDefaults',
							'type' => 'string',
							'options' => array('php' => 'php', 'database' => 'database', 'cake' => 'cake', 'cache' => 'cache'),
					),
					'timeout' => array(
							'level' => 0,
							'description' => 'The timeout duration of sessions (in MINUTES). Keep in mind that autoregenerate can be used to extend the session on user activity.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForNumeric',
							'type' => 'string',
					)
			),
			'Plugin' => array(
					'branch' => 1,
					'RPZ_policy' => array(
						'level' => 2,
						'description' => 'The default policy action for the values added to the RPZ.',
						'value' => 0,
						'errorMessage' => '',
						'test' => 'testForRPZBehaviour',
						'type' => 'numeric',
						'options' => array(0 => 'DROP', 1 => 'NXDOMAIN', 2 => 'NODATA', 3 => 'walled-garden'),
					),
					'RPZ_walled_garden' => array(
						'level' => 2,
						'description' => 'The default walled garden used by the RPZ export if the walled garden setting is picked for the export.',
						'value' => '127.0.0.1',
						'errorMessage' => '',
						'test' => 'testForEmpty',
						'type' => 'string',
					),
					'RPZ_serial' => array(
							'level' => 2,
							'description' => 'The serial in the SOA portion of the zone file. (numeric, best practice is yyyymmddrr where rr is the two digit sub-revision of the file. $date will automatically get converted to the current yyyymmdd, so $date00 is a valid setting).',
							'value' => '$date00',
							'errorMessage' => '',
							'test' => 'testForRPZSerial',
							'type' => 'string',
					),
					'RPZ_refresh' => array(
							'level' => 2,
							'description' => 'The refresh specified in the SOA portion of the zone file. (in seconds, or shorthand duration such as 15m)',
							'value' => '2h',
							'errorMessage' => '',
							'test' => 'testForRPZDuration',
							'type' => 'string',
					),
					'RPZ_retry' => array(
							'level' => 2,
							'description' => 'The retry specified in the SOA portion of the zone file. (in seconds, or shorthand duration such as 15m)',
							'value' => '30m',
							'errorMessage' => '',
							'test' => 'testForRPZDuration',
							'type' => 'string',
					),
					'RPZ_expiry' => array(
							'level' => 2,
							'description' => 'The expiry specified in the SOA portion of the zone file. (in seconds, or shorthand duration such as 15m)',
							'value' => '30d',
							'errorMessage' => '',
							'test' => 'testForRPZDuration',
							'type' => 'string',
					),
					'RPZ_minimum_ttl' => array(
							'level' => 2,
							'description' => 'The minimum TTL specified in the SOA portion of the zone file. (in seconds, or shorthand duration such as 15m)',
							'value' => '1h',
							'errorMessage' => '',
							'test' => 'testForRPZDuration',
							'type' => 'string',
					),
					'RPZ_ttl' => array(
							'level' => 2,
							'description' => 'The TTL of the zone file. (in seconds, or shorthand duration such as 15m)',
							'value' => '1w',
							'errorMessage' => '',
							'test' => 'testForRPZDuration',
							'type' => 'string',
					),
					'RPZ_ns' => array(
							'level' => 2,
							'description' => '',
							'value' => 'localhost.',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
					),
					'RPZ_ns_alt' => array(
						'level' => 2,
						'description' => 'Alternate nameserver',
						'value' => '',
						'errorMessage' => '',
						'test' => 'testForEmpty',
						'type' => 'string',
				),
					'RPZ_email' => array(
						'level' => 2,
						'description' => 'The e-mail address specified in the SOA portion of the zone file.',
						'value' => 'root.localhost',
						'errorMessage' => '',
						'test' => 'testForEmpty',
						'type' => 'string',
					),
					'ZeroMQ_enable' => array(
						'level' => 2,
						'description' => 'Enables or disables the pub/sub feature of MISP. Make sure that you install the requirements for the plugin to work. Refer to the installation instructions for more information.',
						'value' => false,
						'errorMessage' => '',
						'test' => 'testBool',
						'type' => 'boolean',
						'afterHook' => 'zmqAfterHook',
					),
					'ZeroMQ_port' => array(
						'level' => 2,
						'description' => 'The port that the pub/sub feature will use.',
						'value' => 50000,
						'errorMessage' => '',
						'test' => 'testForZMQPortNumber',
						'type' => 'numeric',
						'afterHook' => 'zmqAfterHook',
					),
					'ZeroMQ_redis_host' => array(
						'level' => 2,
						'description' => 'Location of the Redis db used by MISP and the Python PUB script to queue data to be published.',
						'value' => 'localhost',
						'errorMessage' => '',
						'test' => 'testForEmpty',
						'type' => 'string',
						'afterHook' => 'zmqAfterHook',
					),
					'ZeroMQ_redis_port' => array(
						'level' => 2,
						'description' => 'The port that Redis is listening on.',
						'value' => 6379,
						'errorMessage' => '',
						'test' => 'testForPortNumber',
						'type' => 'numeric',
						'afterHook' => 'zmqAfterHook',
					),
					'ZeroMQ_redis_password' => array(
						'level' => 2,
						'description' => 'The password, if set for Redis.',
						'value' => '',
						'errorMessage' => '',
						'test' => 'testForEmpty',
						'type' => 'string',
						'afterHook' => 'zmqAfterHook',
					),
					'ZeroMQ_redis_database' => array(
						'level' => 2,
						'description' => 'The database to be used for queuing messages for the pub/sub functionality.',
						'value' => '1',
						'errorMessage' => '',
						'test' => 'testForEmpty',
						'type' => 'string',
						'afterHook' => 'zmqAfterHook',
					),
					'ZeroMQ_redis_namespace' => array(
						'level' => 2,
						'description' => 'The namespace to be used for queuing messages for the pub/sub functionality.',
						'value' => 'mispq',
						'errorMessage' => '',
						'test' => 'testForEmpty',
						'type' => 'string',
						'afterHook' => 'zmqAfterHook',
					),
					'ZeroMQ_event_notifications_enable' => array(
						'level' => 2,
						'description' => 'Enables or disables the publishing of any event creations/edits/deletions.',
						'value' => false,
						'errorMessage' => '',
						'test' => 'testBool',
						'type' => 'boolean'
					),
					'ZeroMQ_object_notifications_enable' => array(
						'level' => 2,
						'description' => 'Enables or disables the publishing of any object creations/edits/deletions.',
						'value' => false,
						'errorMessage' => '',
						'test' => 'testBool',
						'type' => 'boolean'
					),
					'ZeroMQ_object_reference_notifications_enable' => array(
						'level' => 2,
						'description' => 'Enables or disables the publishing of any object reference creations/deletions.',
						'value' => false,
						'errorMessage' => '',
						'test' => 'testBool',
						'type' => 'boolean'
					),
					'ZeroMQ_attribute_notifications_enable' => array(
						'level' => 2,
						'description' => 'Enables or disables the publishing of any attribute creations/edits/soft deletions.',
						'value' => false,
						'errorMessage' => '',
						'test' => 'testBool',
						'type' => 'boolean'
					),
					'ZeroMQ_sighting_notifications_enable' => array(
						'level' => 2,
						'description' => 'Enables or disables the publishing of new sightings to the ZMQ pubsub feed.',
						'value' => false,
						'errorMessage' => '',
						'test' => 'testBool',
						'type' => 'boolean'
					),
					'ZeroMQ_user_notifications_enable' => array(
						'level' => 2,
						'description' => 'Enables or disables the publishing of new/modified users to the ZMQ pubsub feed.',
						'value' => false,
						'errorMessage' => '',
						'test' => 'testBool',
						'type' => 'boolean'
					),
					'ZeroMQ_organisation_notifications_enable' => array(
						'level' => 2,
						'description' => 'Enables or disables the publishing of new/modified organisations to the ZMQ pubsub feed.',
						'value' => false,
						'errorMessage' => '',
						'test' => 'testBool',
						'type' => 'boolean'
					),
					'ZeroMQ_audit_notifications_enable' => array(
						'level' => 2,
						'description' => 'Enables or disables the publishing of log entries to the ZMQ pubsub feed. Keep in mind, this can get pretty verbose depending on your logging settings.',
						'value' => false,
						'errorMessage' => '',
						'test' => 'testBool',
						'type' => 'boolean'
					),
					'Sightings_enable' => array(
						'level' => 1,
						'description' => 'Enables or disables the sighting functionality. When enabled, users can use the UI or the appropriate APIs to submit sightings data about indicators.',
						'value' => true,
						'errorMessage' => '',
						'test' => 'testBool',
						'type' => 'boolean',
					),
					'Sightings_policy' => array(
						'level' => 1,
						'description' => 'This setting defines who will have access to seeing the reported sightings. The default setting is the event owner alone (in addition to everyone seeing their own contribution) with the other options being Sighting reporters (meaning the event owner and anyone that provided sighting data about the event) and Everyone (meaning anyone that has access to seeing the event / attribute).',
						'value' => 0,
						'errorMessage' => '',
						'test' => 'testForSightingVisibility',
						'type' => 'numeric',
						'options' => array(0 => 'Event Owner', 1 => 'Sighting reporters', 2 => 'Everyone'),
					),
					'Sightings_anonymise' => array(
						'level' => 1,
						'description' => 'Enabling the anonymisation of sightings will simply aggregate all sightings instead of showing the organisations that have reported a sighting. Users will be able to tell the number of sightings their organisation has submitted and the number of sightings for other organisations',
						'value' => false,
						'errorMessage' => '',
						'test' => 'testBool',
						'type' => 'boolean',
					),
					'Sightings_range' => array(
						'level' => 1,
						'description' => 'Set the range in which sightings will be taken into account when generating graphs. For example a sighting with a sighted_date of 7 years ago might not be relevant anymore. Setting given in number of days, default is 365 days',
						'value' => 365,
						'errorMessage' => '',
						'test' => 'testForNumeric',
						'type' => 'numeric'
					),
					'CustomAuth_enable' => array(
							'level' => 2,
							'description' => 'Enable this functionality if you would like to handle the authentication via an external tool and authenticate with MISP using a custom header.',
							'value' => false,
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean',
							'null' => true,
							'beforeHook' => 'customAuthBeforeHook'
					),
					'CustomAuth_header' => array(
							'level' => 2,
							'description' => 'Set the header that MISP should look for here. If left empty it will default to the Authorization header.',
							'value' => 'Authorization',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
							'null' => true
					),
					'CustomAuth_use_header_namespace' => array(
							'level' => 2,
							'description' => 'Use a header namespace for the auth header - default setting is enabled',
							'value' => true,
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean',
							'null' => true
					),
					'CustomAuth_header_namespace' => array(
							'level' => 2,
							'description' => 'The default header namespace for the auth header - default setting is HTTP_',
							'value' => 'HTTP_',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
							'null' => true
					),
					'CustomAuth_required' => array(
							'level' => 2,
							'description' => 'If this setting is enabled then the only way to authenticate will be using the custom header. Altnertatively you can run in mixed mode that will log users in via the header if found, otherwise users will be redirected to the normal login page.',
							'value' => false,
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean',
							'null' => true
					),
					'CustomAuth_only_allow_source' => array(
							'level' => 2,
							'description' => 'If you are using an external tool to authenticate with MISP and would like to only allow the tool\'s url as a valid point of entry then set this field. ',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
							'null' => true
					),
					'CustomAuth_name' => array(
							'level' => 2,
							'description' => 'The name of the authentication method, this is cosmetic only and will be shown on the user creation page and logs.',
							'value' => 'External authentication',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
							'null' => true
					),
					'CustomAuth_disable_logout' => array(
							'level' => 2,
							'description' => 'Disable the logout button for users authenticate with the external auth mechanism.',
							'value' => false,
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean'
					),
					'Enrichment_services_enable' => array(
						'level' => 0,
						'description' => 'Enable/disable the enrichment services',
						'value' => false,
						'errorMessage' => '',
						'test' => 'testBool',
						'type' => 'boolean'
					),
					'Enrichment_timeout' => array(
							'level' => 1,
							'description' => 'Set a timeout for the enrichment services',
							'value' => 10,
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'numeric'
					),
					'Import_services_enable' => array(
							'level' => 0,
							'description' => 'Enable/disable the import services',
							'value' => false,
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean'
					),
					'Import_timeout' => array(
							'level' => 1,
							'description' => 'Set a timeout for the import services',
							'value' => 10,
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'numeric'
					),
					'Import_services_url' => array(
							'level' => 1,
							'description' => 'The url used to access the import services. By default, it is accessible at http://127.0.0.1:6666',
							'value' => 'http://127.0.0.1',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string'
					),
					'Import_services_port' => array(
							'level' => 1,
							'description' => 'The port used to access the import services. By default, it is accessible at 127.0.0.1:6666',
							'value' => '6666',
							'errorMessage' => '',
							'test' => 'testForPortNumber',
							'type' => 'numeric'
					),
					'Export_services_url' => array(
							'level' => 1,
							'description' => 'The url used to access the export services. By default, it is accessible at http://127.0.0.1:6666',
							'value' => 'http://127.0.0.1',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string'
					),
					'Export_services_port' => array(
							'level' => 1,
							'description' => 'The port used to access the export services. By default, it is accessible at 127.0.0.1:6666',
							'value' => '6666',
							'errorMessage' => '',
							'test' => 'testForPortNumber',
							'type' => 'numeric'
					),
					'Export_services_enable' => array(
							'level' => 0,
							'description' => 'Enable/disable the export services',
							'value' => false,
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean'
					),
					'Export_timeout' => array(
							'level' => 1,
							'description' => 'Set a timeout for the export services',
							'value' => 10,
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'numeric'
					),
					'Enrichment_hover_enable' => array(
							'level' => 0,
							'description' => 'Enable/disable the hover over information retrieved from the enrichment modules',
							'value' => false,
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean'
					),
					'Enrichment_hover_timeout' => array(
							'level' => 1,
							'description' => 'Set a timeout for the hover services',
							'value' => 5,
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'numeric'
					),
					'Enrichment_services_url' => array(
							'level' => 1,
							'description' => 'The url used to access the enrichment services. By default, it is accessible at http://127.0.0.1:6666',
							'value' => 'http://127.0.0.1',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string'
					),
					'Enrichment_services_port' => array(
							'level' => 1,
							'description' => 'The port used to access the enrichment services. By default, it is accessible at 127.0.0.1:6666',
							'value' => '6666',
							'errorMessage' => '',
							'test' => 'testForPortNumber',
							'type' => 'numeric'
					),
					'Cortex_services_url' => array(
							'level' => 1,
							'description' => 'The url used to access Cortex. By default, it is accessible at http://cortex-url',
							'value' => 'http://127.0.0.1',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string'
					),
					'Cortex_services_port' => array(
							'level' => 1,
							'description' => 'The port used to access Cortex. By default, this is port 9000',
							'value' => '9000',
							'errorMessage' => '',
							'test' => 'testForPortNumber',
							'type' => 'numeric'
					),
					'Cortex_services_enable' => array(
							'level' => 0,
							'description' => 'Enable/disable the import services',
							'value' => false,
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean'
					),
					'Cortex_timeout' => array(
							'level' => 1,
							'description' => 'Set a timeout for the import services',
							'value' => 120,
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'numeric'
					),
					'CustomAuth_custom_password_reset' => array(
							'level' => 2,
							'description' => 'Provide your custom authentication users with an external URL to the authentication system to reset their passwords.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
							'null' => true
					),
					'CustomAuth_custom_logout' => array(
							'level' => 2,
							'description' => 'Provide a custom logout URL for your users that will log them out using the authentication system you use.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
							'null' => true
					)
			),
			'debug' => array(
					'level' => 0,
					'description' => 'The debug level of the instance, always use 0 for production instances.',
					'value' => '',
					'errorMessage' => '',
					'test' => 'testDebug',
					'type' => 'numeric',
					'options' => array(0 => 'Debug off', 1 => 'Debug on', 2 => 'Debug + SQL dump'),
			),
			'site_admin_debug' => array(
					'level' => 0,
					'description' => 'The debug level of the instance for site admins. This feature allows site admins to run debug mode on a live instance without exposing it to other users. The most verbose option of debug and site_admin_debug is used for site admins.',
					'value' => '',
					'errorMessage' => '',
					'test' => 'testDebugAdmin',
					'type' => 'boolean',
					'null' => true
			),
	);

	private $__settingTabMergeRules = array(
			'GnuPG' => 'Encryption',
			'SMIME' => 'Encryption',
			'misc' => 'Security',
			'Security' => 'Security',
			'Session' => 'Security'
	);

	public $validEventIndexFilters = array('searchall', 'searchpublished', 'searchorg', 'searchtag', 'searcheventid', 'searchdate', 'searcheventinfo', 'searchthreatlevel', 'searchdistribution', 'searchanalysis', 'searchattribute');

	public function isOwnedByOrg($serverid, $org) {
		return $this->field('id', array('id' => $serverid, 'org' => $org)) === $serverid;
	}

	public function beforeSave($options = array()) {
		$this->data['Server']['url'] = rtrim($this->data['Server']['url'], '/');
		return true;
	}

	public function pull($user, $id = null, $technique=false, $server, $jobId = false, $percent = 100, $current = 0) {
		if ($jobId) {
			$job = ClassRegistry::init('Job');
			$job->read(null, $jobId);
			$email = "Scheduled job";
		} else {
			$email = $user['email'];
		}
		$eventModel = ClassRegistry::init('Event');
		App::uses('HttpSocket', 'Network/Http');
		$eventIds = array();
		$conditions = array();
		if ("full" === $technique) {
			// get a list of the event_ids on the server
			$eventIds = $this->getEventIdsFromServer($server);
			// FIXME this is not clean at all ! needs to be refactored with try catch error handling/communication
			if ($eventIds === 403) {
				return array (1, null);
			} else if (is_string($eventIds)) {
				return array(2, $eventIds);
			}

			// reverse array of events, to first get the old ones, and then the new ones
			if (!empty($eventIds)) {
				$eventIds = array_reverse($eventIds);
			}
		} else if ("update" === $technique) {
			$eventIds = $this->getEventIdsFromServer($server, false, null, true, true);
			if ($eventIds === 403) {
				return array (1, null);
			} else if (is_string($eventIds)) {
				return array(2, $eventIds);
			}
			$local_event_ids = $eventModel->find('list', array(
					'fields' => array('uuid'),
					'recursive' => -1,
			));
			$eventIds = array_intersect($eventIds, $local_event_ids);
		} else if ("incremental" === $technique) {
			// TODO incremental pull
			return array (3, null);
		} else if (is_numeric($technique)) {
			$eventIds[] = intval($technique);
			// if we are downloading a single event, don't fetch all proposals
			$conditions = array('Event.id' => $technique);
		} else {
			return array (4, null);
		}
		$successes = array();
		$fails = array();
		$pulledProposals = array();
		// now process the $eventIds to pull each of the events sequentially
		if (!empty($eventIds)) {
			// download each event
			if (null != $eventIds) {
				App::uses('SyncTool', 'Tools');
				$syncTool = new SyncTool();
				$HttpSocket = $syncTool->setupHttpSocket($server);
				foreach ($eventIds as $k => $eventId) {
					$event = $eventModel->downloadEventFromServer(
							$eventId,
							$server);
					if (null != $event) {
						$blocked = false;
						if (Configure::read('MISP.enableEventBlacklisting') !== false) {
							$this->EventBlacklist = ClassRegistry::init('EventBlacklist');
							$r = $this->EventBlacklist->find('first', array('conditions' => array('event_uuid' => $event['Event']['uuid'])));
							if (!empty($r))	{
								$blocked = true;
								$fails[$eventId] = 'Event blocked by local blocklist.';
							}
						}
						if (!$blocked) {
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
							}
						} else {
							$fails[$eventId] = 'Event blocked by blacklist.';
							continue;
						}
						// Distribution, set reporter of the event, being the admin that initiated the pull
						$event['Event']['user_id'] = $user['id'];
						// check if the event already exist (using the uuid)
						$existingEvent = null;
						$existingEvent = $eventModel->find('first', array('conditions' => array('Event.uuid' => $event['Event']['uuid'])));
						if (!$existingEvent) {
							// add data for newly imported events
							$passAlong = $server['Server']['id'];
							$result = $eventModel->_add($event, true, $user, $server['Server']['org_id'], $passAlong, true, $jobId);
							if ($result) $successes[] = $eventId;
							else {
								$fails[$eventId] = 'Failed (partially?) because of validation errors: '. print_r($eventModel->validationErrors, true);

							}
						} else {
							$tempUser = $user;
							$tempUser['Role']['perm_site_admin'] = 0;
							$result = $eventModel->_edit($event, $tempUser, $existingEvent['Event']['id'], $jobId);
							if ($result === true) $successes[] = $eventId;
							else if (isset($result['error'])) $fails[$eventId] = $result['error'];
							else $fails[$eventId] = json_encode($result);
						}
					} else {
						// error
						$fails[$eventId] = 'failed downloading the event';
					}
					if ($jobId) {
						if ($k % 10 == 0) {
							$job->id = $jobId;
							$job->saveField('progress', 50 * (($k + 1) / count($eventIds)));
						}
					}
				}
				if (count($fails) > 0) {
					// there are fails, take the lowest fail
					$lastpulledid = min(array_keys($fails));
				} else {
					// no fails, take the highest success
					$lastpulledid = count($successes) > 0 ? max($successes) : 0;
				}
			}
		}
		if ($jobId) {
			$job->saveField('message', 'Pulling proposals.');
		}
		$events = $eventModel->find('list', array(
				'fields' => array('uuid'),
				'recursive' => -1,
				'conditions' => $conditions
		));
		$shadowAttribute = ClassRegistry::init('ShadowAttribute');
		$shadowAttribute->recursive = -1;
		if (!empty($events)) {
			$proposals = $eventModel->downloadProposalsFromServer($events, $server);
			if (!empty($proposals)) {
				$uuidEvents = array_flip($events);
				foreach ($proposals as $k => &$proposal) {
					$proposal = $proposal['ShadowAttribute'];
					$oldsa = $shadowAttribute->findOldProposal($proposal);
					$proposal['event_id'] = $uuidEvents[$proposal['event_uuid']];
					if (!$oldsa || $oldsa['timestamp'] < $proposal['timestamp']) {
						if ($oldsa) $shadowAttribute->delete($oldsa['id']);
						if (!isset($pulledProposals[$proposal['event_id']])) $pulledProposals[$proposal['event_id']] = 0;
						$pulledProposals[$proposal['event_id']]++;
						if (isset($proposal['old_id'])) {
							$oldAttribute = $eventModel->Attribute->find('first', array('recursive' => -1, 'conditions' => array('uuid' => $proposal['uuid'])));
							if ($oldAttribute) $proposal['old_id'] = $oldAttribute['Attribute']['id'];
							else $proposal['old_id'] = 0;
						}
						// check if this is a proposal from an old MISP instance
						if (!isset($proposal['Org']) && isset($proposal['org']) && !empty($proposal['org'])) {
							$proposal['Org'] = $proposal['org'];
							$proposal['EventOrg'] = $proposal['event_org'];
						} else if (!isset($proposal['Org']) && !isset($proposal['EventOrg'])) {
							continue;
						}
						$proposal['org_id'] = $this->Organisation->captureOrg($proposal['Org'], $user);
						$proposal['event_org_id'] = $this->Organisation->captureOrg($proposal['EventOrg'], $user);
						unset($proposal['Org']);
						unset($proposal['EventOrg']);
						$shadowAttribute->create();
						if (!isset($proposal['deleted']) || !$proposal['deleted']) {
							if ($shadowAttribute->save($proposal)) $shadowAttribute->sendProposalAlertEmail($proposal['event_id']);
						}
					}
					if ($jobId) {
						if ($k % 50 == 0) {
							$job->id = $jobId;
							$job->saveField('progress', 50 * (($k + 1) / count($proposals)));
						}
					}
				}
			}
		}
		if ($jobId) {
			$job->saveField('progress', 100);
			$job->saveField('message', 'Pull completed.');
			$job->saveField('status', 4);
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
			'change' => count($successes) . ' events and ' . count($pulledProposals) . ' proposals pulled or updated. ' . count($fails) . ' events failed or didn\'t need an update.'
		));
		if (!isset($lastpulledid)) $lastpulledid = 0;
		return array($successes, $fails, $pulledProposals, $lastpulledid);
	}

	public function filterRuleToParameter($filter_rules) {
		$final = array();
		if (empty($filter_rules)) return $final;
		$filter_rules = json_decode($filter_rules, true);
		foreach ($filter_rules as $field => $rules) {
			$temp = array();
			foreach ($rules as $operator => $elements) {
				foreach ($elements as $k => $element) {
					if ($operator === 'NOT') $element = '!' . $element;
					if (!empty($element)) $temp[] = $element;
				}
			}
			if (!empty($temp)) {
				$temp = implode('|', $temp);
				$final[substr($field, 0, strlen($field) -1)] = $temp;
			}
		}
		return $final;
	}


	// Get an array of event_ids that are present on the remote server
	public function getEventIdsFromServer($server, $all = false, $HttpSocket=null, $force_uuid=false, $ignoreFilterRules = false) {
		$url = $server['Server']['url'];
		$authkey = $server['Server']['authkey'];
		if ($ignoreFilterRules) $filter_rules = array();
		else $filter_rules = $this->filterRuleToParameter($server['Server']['pull_rules']);
		if (null == $HttpSocket) {
			App::uses('SyncTool', 'Tools');
			$syncTool = new SyncTool();
			$HttpSocket = $syncTool->setupHttpSocket($server);
		}
		$request = array(
				'header' => array(
						'Authorization' => $authkey,
						'Accept' => 'application/json',
						'Content-Type' => 'application/json',
						//'Connection' => 'keep-alive' // LATER followup cakephp issue about this problem: https://github.com/cakephp/cakephp/issues/1961
				)
		);
		$uri = $url . '/events/index';
		$filter_rules['minimal'] = 1;
		try {
			$response = $HttpSocket->post($uri, json_encode($filter_rules), $request);
			if ($response->isOk()) {
				$eventArray = json_decode($response->body, true);
				// correct $eventArray if just one event
				if (is_array($eventArray) && isset($eventArray['id'])) {
					$tmp = $eventArray;
					unset($eventArray);
					$eventArray[0] = $tmp;
					unset($tmp);
				}
				$eventIds = array();
				if ($all) {
					if (!empty($eventArray)) foreach ($eventArray as $event) {
						$eventIds[] = $event['uuid'];
					}
				} else {
					// multiple events, iterate over the array
					$this->Event = ClassRegistry::init('Event');
					foreach ($eventArray as $k => $event) {
						if (1 != $event['published']) {
							unset($eventArray[$k]); // do not keep non-published events
						}
					}
					$this->Event->removeOlder($eventArray);
					if (!empty($eventArray)) {
						foreach ($eventArray as $event) {
							if ($force_uuid) $eventIds[] = $event['uuid'];
							else $eventIds[] = $event['id'];
						}
					}
				}
				return $eventIds;
			}
			if ($response->code == '403') {
				return 403;
			}
		} catch (SocketException $e) {
			// FIXME refactor this with clean try catch over all http functions
			return $e->getMessage();
		}
		// error, so return error message, since that is handled and everything is expecting an array
		return "Error: got response code " . $response->code;
	}

	public function push($id = null, $technique=false, $jobId = false, $HttpSocket, $user) {
		if ($jobId) {
			$job = ClassRegistry::init('Job');
			$job->read(null, $jobId);
		}
		$this->Event = ClassRegistry::init('Event');
		$this->read(null, $id);
		$url = $this->data['Server']['url'];
		$push = $this->checkVersionCompatibility($id, $user)['canPush'];
		if (!isset($push) || !$push) {
			if ($jobId) {
				$job->id = $jobId;
				$job->saveField('progress', 100);
				$job->saveField('message', 'Push to server ' . $id . ' failed. Remote instance is outdated.');
				$job->saveField('status', 4);
			}
			return false;
		}
		if ("full" == $technique) {
			$eventid_conditions_key = 'Event.id >';
			$eventid_conditions_value = 0;
		} else if ("incremental" == $technique) {
			$eventid_conditions_key = 'Event.id >';
			$eventid_conditions_value = $this->data['Server']['lastpushedid'];
		} else if (true == $technique) {
			$eventid_conditions_key = 'Event.id';
			$eventid_conditions_value = intval($technique);
		} else {
			$this->redirect(array('action' => 'index'));
		}
		$sgs = $this->Event->SharingGroup->find('all', array(
			'recursive' => -1,
			'contain' => array('Organisation', 'SharingGroupOrg', 'SharingGroupServer')
		));
		$sgIds = array();
		foreach ($sgs as $k => $sg) {
			if (!$this->Event->SharingGroup->checkIfServerInSG($sg, $this->data)) {
				unset($sgs[$k]);
				continue;
			}
			$sgIds[] = $sg['SharingGroup']['id'];
		}
		if (!isset($sgIds) || empty($sgIds)) {
			$sgIds = array(-1);
		}
		$findParams = array(
				'conditions' => array(
						$eventid_conditions_key => $eventid_conditions_value,
						'Event.published' => 1,
						'Event.attribute_count >' => 0,
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
				'fields' => array('Event.id', 'Event.timestamp', 'Event.uuid', 'Event.orgc_id'), // array of field names
		);
		$eventIds = $this->Event->find('all', $findParams);
		$eventUUIDsFiltered = $this->getEventIdsForPush($id, $HttpSocket, $eventIds, $user);
		if ($eventUUIDsFiltered === false || empty($eventUUIDsFiltered)) $pushFailed = true;
		if (!empty($eventUUIDsFiltered)) {
			$eventCount = count($eventUUIDsFiltered);
			// now process the $eventIds to pull each of the events sequentially
			if (!empty($eventUUIDsFiltered)) {
				$successes = array();
				$fails = array();
				$lowestfailedid = null;
				foreach ($eventUUIDsFiltered as $k => $eventUuid) {
					$event = $this->Event->fetchEvent($user, array(
						'event_uuid' => $eventUuid,
						'includeAttachments' => true,
						'includeAllTags' => true
					));
					$event = $event[0];
					$event['Event']['locked'] = true;
					$result = $this->Event->uploadEventToServer(
							$event,
							$this->data,
							$HttpSocket);
					if ('Success' === $result) {
						$successes[] = $event['Event']['id'];
					} else {
						$fails[$event['Event']['id']] = $result;
					}
					if ($jobId && $k%10 == 0) {
						$job->saveField('progress', 100 * $k / $eventCount);
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
				$this->data['Server']['lastpushedid'] = $lastpushedid;
				$this->save($this->data);
			}
		}

		$this->syncProposals($HttpSocket, $this->data, null, null, $this->Event);

		if (!isset($successes)) $successes = null;
		if (!isset($fails)) $fails = null;
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
			$job->id = $jobId;
			$job->saveField('progress', 100);
			$job->saveField('message', 'Push to server ' . $id . ' complete.');
			$job->saveField('status', 4);
		} else {
			return array($successes, $fails);
		}
	}

	public function getEventIdsForPush($id, $HttpSocket, $eventIds, $user) {
		$server = $this->read(null, $id);
		$this->Event = ClassRegistry::init('Event');

		foreach ($eventIds as $k => $event) {
			if (empty($this->eventFilterPushableServers($event, array($server)))) {
				unset($eventIds[$k]);
				continue;
			}
			unset($eventIds[$k]['Event']['id']);
		}
		if (null == $HttpSocket) {
			App::uses('SyncTool', 'Tools');
			$syncTool = new SyncTool();
			$HttpSocket = $syncTool->setupHttpSocket($server);
		}
		$data = json_encode($eventIds);
		$request = array(
				'header' => array(
						'Authorization' => $server['Server']['authkey'],
						'Accept' => 'application/json',
						'Content-Type' => 'application/json',
				)
		);
		$uri = $server['Server']['url'] . '/events/filterEventIdsForPush';
		$response = $HttpSocket->post($uri, $data, $request);
		if ($response->code == '200') {
			$uuidList = json_decode($response->body());
		} else {
			return false;
		}
		return $uuidList;
	}

	public function syncProposals($HttpSocket, $server, $sa_id = null, $event_id = null, $eventModel) {
		$saModel = ClassRegistry::init('ShadowAttribute');
		if (null == $HttpSocket) {
			App::uses('SyncTool', 'Tools');
			$syncTool = new SyncTool();
			$HttpSocket = $syncTool->setupHttpSocket($server);
		}
		if ($sa_id == null) {
			if ($event_id == null) {
				// event_id is null when we are doing a push
				$ids = $this->getEventIdsFromServer($server, true, $HttpSocket, false, true);
				// error return strings or ints or throw exceptions
				if (!is_array($ids)) return false;
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
					$request = array(
							'header' => array(
									'Authorization' => $server['Server']['authkey'],
									'Accept' => 'application/json',
									'Content-Type' => 'application/json',
							)
					);
					$uri = $server['Server']['url'] . '/events/pushProposals/' . $event['Event']['uuid'];
					$response = $HttpSocket->post($uri, $data, $request);
					if ($response->code == '200') {
						$result = json_decode($response->body(), true);
						if ($result['success']) {
							$success += intval($result['counter']);
						} else {
							$fails++;
							if ($error_message == "") $result['message'];
							else $error_message .= " --- " . $result['message'];
						}
					} else {
						$fails++;
					}
				}
			}
		} else {
			// connect to checkuuid($uuid)
			$request = array(
					'header' => array(
							'Authorization' => $server['Server']['authkey'],
							'Accept' => 'application/json',
							'Content-Type' => 'application/json',
					)
			);
			$uri = $server['Server']['url'] . '/events/checkuuid/' . $sa_id;
			$response = $HttpSocket->get($uri, '', $request);
			if ($response->code != '200') {
				return false;
			}
		}
		return true;
	}

	public function getCurrentServerSettings() {
		$this->Module = ClassRegistry::init('Module');
		$serverSettings = $this->serverSettings;
		$moduleTypes = array('Enrichment', 'Import', 'Export', 'Cortex');
		$orgs = $this->Organisation->find('list', array(
			'conditions' => array(
				'Organisation.local' => 1
			),
			'fields' => array(
				'Organisation.id', 'Organisation.name'
			)
		));
		$orgs = array_merge(array('Unrestricted'), $orgs);
		foreach ($moduleTypes as $moduleType) {
			if (Configure::read('Plugin.' . $moduleType . '_services_enable')) {
				$results = $this->Module->getModuleSettings($moduleType);
				foreach ($results as $module => $data) {
					foreach ($data as $result) {
						$setting = array('level' => 1, 'errorMessage' => '');
						if ($result['type'] == 'boolean') {
							$setting['test'] = 'testBool';
							$setting['type'] = 'boolean';
							$setting['description'] = 'Enable or disable the ' . $module . ' module.';
							$setting['value'] = false;
						} else if ($result['type'] == 'orgs') {
							$setting['description'] = 'Restrict the ' . $module . ' module to the given organisation.';
							$setting['value'] = 0;
							$setting['test'] = 'testLocalOrg';
							$setting['type'] = 'numeric';
							$setting['optionsSource'] = 'LocalOrgs';
						} else {
							$setting['test'] = 'testForEmpty';
							$setting['type'] = 'string';
							$setting['description'] = 'Set this required module specific setting.';
							$setting['value'] = '';
						}
						$serverSettings['Plugin'][$moduleType . '_' . $module . '_' .  $result['name']] = $setting;
					}
				}
			}
		}
		return $serverSettings;
	}

	public function serverSettingsRead($unsorted = false) {
		$this->Module = ClassRegistry::init('Module');
		$serverSettings = $this->getCurrentServerSettings();
		$currentSettings = Configure::read();
		if (Configure::read('Plugin.Enrichment_services_enable')) {
			$results = $this->Module->getModuleSettings();
			foreach ($results as $module => $data) {
				foreach ($data as $result) {
					$setting = array('level' => 1, 'errorMessage' => '');
					if ($result['type'] == 'boolean') {
						$setting['test'] = 'testBool';
						$setting['type'] = 'boolean';
						$setting['description'] = 'Enable or disable the ' . $module . ' module.';
						$setting['value'] = false;
					} else if ($result['type'] == 'orgs') {
						$setting['description'] = 'Restrict the ' . $module . ' module to the given organisation.';
						$setting['value'] = 0;
						$setting['test'] = 'testLocalOrg';
						$setting['type'] = 'numeric';
						$setting['optionsSource'] = 'LocalOrgs';
					} else {
						$setting['test'] = 'testForEmpty';
						$setting['type'] = 'string';
						$setting['description'] = 'Set this required module specific setting.';
						$setting['value'] = '';
					}
					$serverSettings['Plugin']['Enrichment_' . $module . '_' .  $result['name']] = $setting;
				}
			}
		}
		$finalSettingsUnsorted = array();
		foreach ($serverSettings as $branchKey => &$branchValue) {
			if (isset($branchValue['branch'])) {
				foreach ($branchValue as $leafKey => &$leafValue) {
					if ($leafValue['level'] == 3 && !(isset($currentSettings[$branchKey][$leafKey]))) continue;
					$setting = null;
					if (isset($currentSettings[$branchKey][$leafKey])) $setting = $currentSettings[$branchKey][$leafKey];
					$leafValue = $this->__evaluateLeaf($leafValue, $leafKey, $setting);
					if ($leafKey != 'branch') {
						if ($branchKey == 'Plugin') {
							$pluginData = explode('_', $leafKey);
							$leafValue['subGroup'] = $pluginData[0];
						}
						if (strpos($branchKey, 'Secur') === 0) $leafValue['tab'] = 'Security';
						else $leafValue['tab'] = $branchKey;
						$finalSettingsUnsorted[$branchKey . '.' . $leafKey] = $leafValue;
					}
				}
			} else {
					$setting = null;
					if (isset($currentSettings[$branchKey])) $setting = $currentSettings[$branchKey];
					$branchValue = $this->__evaluateLeaf($branchValue, $branchKey, $setting);
					$branchValue['tab'] = 'misc';
					$finalSettingsUnsorted[$branchKey] = $branchValue;
			}
		}
		foreach ($finalSettingsUnsorted as $key => $temp) if (in_array($temp['tab'], array_keys($this->__settingTabMergeRules))) {
			$finalSettingsUnsorted[$key]['tab'] = $this->__settingTabMergeRules[$temp['tab']];
		}
		if ($unsorted) return $finalSettingsUnsorted;
		$finalSettings = array();
		for ($i = 0; $i < 4; $i++) {
			foreach ($finalSettingsUnsorted as $k => $s) {
				$s['setting'] = $k;
				if ($s['level'] == $i) $finalSettings[] = $s;
			}
		}
		return $finalSettings;
	}

	public function serverSettingReadSingle($settingObject, $settingName, $leafKey) {
		// invalidate config.php from php opcode cache
		if (function_exists('opcache_reset')) opcache_reset();

		$setting = Configure::read($settingName);
		$result = $this->__evaluateLeaf($settingObject, $leafKey, $setting);
		$result['setting'] = $settingName;
		return $result;
	}

	private function __evaluateLeaf($leafValue, $leafKey, $setting) {
		if (isset($setting)) {
			if (!empty($leafValue['test'])) {
				$result = $this->{$leafValue['test']}($setting);
				if ($result !== true) {
					$leafValue['error'] = 1;
					if ($result !== false) $leafValue['errorMessage'] = $result;
				}
			}
			if ($setting !== '') $leafValue['value'] = $setting;
		} else {
			if ($leafKey != 'branch' && (!isset($leafValue['null']) || !$leafValue['null'])) {
				$leafValue['error'] = 1;
				$leafValue['errorMessage'] = 'Value not set.';
			}
		}
		return $leafValue;
	}

	public function testForNumeric($value) {
		if (!is_numeric($value)) return 'This setting has to be a number.';
		return true;
	}

	public function testUuid($value) {
		if (empty($value) || !preg_match('/^\{?[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}\}?$/', $value)) {
			return 'Invalid UUID.';
		}
		return true;
	}

	public function testForSessionDefaults($value) {
		if (empty($value) || !in_array($value, array('php', 'database', 'cake', 'cache'))) {
			return 'Please choose a valid session handler. Recommended values: php or database. Alternate options are cake (cakephp file based sessions) and cache.';
		} else {
			return true;
		}
	}

	public function testLocalOrg($value) {
		$this->Organisation = ClassRegistry::init('Organisation');
		if ($value == 0) return 'No organisation selected';
		$local_orgs = $this->Organisation->find('list', array(
			'conditions' => array('local' => 1),
			'recursive' => -1,
			'fields' => array('Organisation.id', 'Organisation.name')
		));
		if (in_array($value, array_keys($local_orgs))) return true;
		return 'Invalid organisation';
	}

	public function testForEmpty($value) {
		$value = trim($value);
		if ($value === '') return 'Value not set.';
		return true;
	}

	public function testForPath($value) {
		if ($value === '') return true;
		if (preg_match('@^\/?(([a-z0-9_.]+[a-z0-9_.\-.\:]*[a-z0-9_.\-.\:]|[a-z0-9_.])+\/?)+$@i', $value)) return true;
		return 'Invalid characters in the path.';
	}

	public function testForWritableDir($value) {
		if (!is_dir($value)) return 'Not a valid directory.';
		if (!is_writeable($value)) return 'Not a writable directory.';
		return true;
	}

	public function testDebug($value) {
		if ($this->testForEmpty($value) !== true) return $this->testForEmpty($value);
		if ($this->testForNumeric($value) !== true) return 'This setting has to be a number between 0 and 2, with 0 disabling debug mode.';
		if ($value === 0) return true;
		return 'This setting has to be set to 0 on production systems. Ignore this warning if this is not the case.';
	}

	public function testDebugAdmin($value) {
		if ($this->testBool($value) !== true) return 'This setting has to be either true or false.';
		if (!$value) return true;
		return 'Enabling debug is not recommended. Turn this on temporarily if you need to see a stack trace to debug an issue, but make sure this is not left on.';
	}

	public function testDate($date) {
		if ($this->testForEmpty($date) !== true) return $this->testForEmpty($date);
		if (!strtotime($date)) return 'The date that you have entered is invalid. Expected: yyyy-mm-dd';
		return true;
	}


	public function getHost() {
		if (function_exists('apache_request_headers')){
				 $headers = apache_request_headers();
		} else {
				 $headers = $_SERVER;
		}

		if ( array_key_exists( 'X-Forwarded-Host', $headers ) ) {
				 $host = $headers['X-Forwarded-Host'];
		} else {
				 $host = $_SERVER['HTTP_HOST'];
		}
		return $host;
	}

	public function getProto() {
		if (function_exists('apache_request_headers')){
				 $headers = apache_request_headers();
		} else {
				 $headers = $_SERVER;
		}

		if (array_key_exists('X-Forwarded-Proto',$headers)){
				 $proto = $headers['X-Forwarded-Proto'];
		} else {
				 $proto = ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || $_SERVER['SERVER_PORT'] == 443) === true ? 'HTTPS' : 'HTTP';
		}
		return $proto;
	}

	public function testBaseURL($value) {
		if ($this->testForEmpty($value) !== true) return $this->testForEmpty($value);
		if ($value != strtolower($this->getProto()) . '://' . $this->getHost()) return false;
		return true;
	}

	public function testDisableEmail($value) {
		if (isset($value) && $value) return 'E-mailing is blocked.';
		return true;
	}

	public function testDisableCache($value) {
		if (isset($value) && $value) return 'Export caches are disabled.';
		return true;
	}

	public function testLive($value) {
		if ($this->testBool($value) !== true) return $this->testBool($value);
		if (!$value) return 'MISP disabled.';
		return true;
	}

	public function testBool($value) {
		if ($value !== true && $value !== false) return 'Value is not a boolean, make sure that you convert \'true\' to true for example.';
		return true;
	}

	public function testBoolFalse($value) {
		if (!$this->testBool($value)) {
			return $this->testBool($value);
		}
		if ($value !== false) {
			return 'It is highly recommended that this setting is disabled. Make sure you understand the impact of having this setting turned on.';
		} else {
			return true;
		}
	}

	public function testSalt($value) {
		if ($this->testForEmpty($value) !== true) return $this->testForEmpty($value);
		if (strlen($value) < 32) return 'The salt has to be an at least 32 byte long string.';
		if ($value == "Rooraenietu8Eeyo<Qu2eeNfterd-dd+") return 'This is the default salt shipped with the application and is therefore unsecure.';
		return true;
	}

	public function testForTermsFile($value) {
		return $this->__testForFile($value, APP . 'files' . DS . 'terms');
	}

	public function testForStyleFile($value) {
		if (empty($value)) return true;
		return $this->__testForFile($value, APP . 'webroot' . DS . 'css');
	}

	public function testForCustomImage($value) {
		return $this->__testForFile($value, APP . 'webroot' . DS . 'img' . DS . 'custom');
	}

	public function testPasswordLength($value) {
		$numeric = $this->testForNumeric($value);
		if ($numeric !== true) return $numeric;
		if ($value < 0) return 'Length cannot be negative, set a positive integer or 0 (to choose the default option).';
		return true;
	}

	public function testForPortNumber($value) {
		$numeric = $this->testForNumeric($value);
		if ($numeric !== true) return $numeric;
		if ($value < 21 || $value > 65535) return 'Make sure that you pick a valid port number.';
		return true;
	}

	public function testForZMQPortNumber($value) {
		$numeric = $this->testForNumeric($value);
		if ($numeric !== true) return $numeric;
		if ($value < 49152 || $value > 65535) return 'It is recommended that you pick a port number in the dynamic range (49152-65535). However, if you have a valid reason to use a different port, ignore this message.';
		return true;
	}

	public function testPasswordRegex($value) {
		if (!empty($value) && @preg_match($value, 'test') === false) return 'Invalid regex.';
		return true;
	}

	public function testPasswordResetText($value) {
		if (strpos($value, '$password') === false || strpos($value, '$username') === false || strpos($value, '$misp') === false) return 'The text served to the users must include the following replacement strings: "$username", "$password", "$misp"';
		return true;
	}

	public function testForGPGBinary($value) {
		if (empty($value)) $value = $this->serverSettings['GnuPG']['binary']['value'];
		if (file_exists($value)) return true;
		return 'Could not find the gnupg executable at the defined location.';
	}

	public function testForRPZDuration($value) {
		if (($this->testForNumeric($value) !== true && preg_match('/^[0-9]*[mhdw]$/i', $value)) || $value >= 0) {
			return true;
		} else {
			return 'Negative seconds found. The following formats are accepted: seconds (positive integer), or duration (positive integer) followed by a letter denoting scale (such as m, h, d, w for minutes, hours, days, weeks)';
		}
	}

	public function testForRPZBehaviour($value) {
		$numeric = $this->testForNumeric($value);
		if ($numeric !== true) return $numeric;
		if ($value < 0 || $value > 3) return 'Invalid setting, valid range is 0-3 (0 = DROP, 1 = NXDOMAIN, 2 = NODATA, 3 = walled garden.';
		return true;
	}

	public function testForSightingVisibility($value) {
		$numeric = $this->testForNumeric($value);
		if ($numeric !== true) return $numeric;
		if ($value < 0 || $value > 2) return 'Invalid setting, valid range is 0-2 (0 = Event owner, 1 = Sighting reporters, 2 = Everyone.';
		return true;
	}

	public function sightingsBeforeHook($setting, $value) {
		if ($value == true) {
			$this->updateDatabase('addSightings');
		}
		return true;
	}

	public function testForRPZSerial($value) {
		if ($this->testForEmpty($value) !== true) return $this->testForEmpty($value);
		if (!preg_match('/^((\$date(\d*)|\d*))$/', $value)) return 'Invalid format.';
		return true;
	}

	public function testForRPZNS($value) {
		if ($this->testForEmpty($value) !== true) return $this->testForEmpty($value);
		if (!preg_match('/^\w+(\.\w+)*(\.?) \w+(\.\w+)*$/', $value)) return 'Invalid format.';
		return true;
	}

	public function zmqAfterHook($setting, $value) {
		$pubSubTool = $this->getPubSubTool();
		// If we are trying to change the enable setting to false, we don't need to test anything, just kill the server and return true.
		if ($setting == 'Plugin.ZeroMQ_enable') {
			if ($value == false || $value == 0) {
				$pubSubTool->killService();
				return true;
			}
		} else if (!Configure::read('Plugin.ZeroMQ_enable')) {
			// If we are changing any other ZeroMQ settings but the feature is disabled, don't reload the service
			return true;
		}
		$pubSubTool->reloadServer();
		return true;
	}

	public function disableCacheAfterHook($setting, $value) {
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

	public function correlationAfterHook($setting, $value) {
		if (!Configure::read('MISP.background_jobs')) {
			$this->Attribute = ClassRegistry::init('Attribute');
			if ($value) {
				$k = $this->Attribute->purgeCorrelations();
			} else {
				$k = $this->Attribute->generateCorrelation();
			}
		} else {
			$job = ClassRegistry::init('Job');
			$job->create();
			if ($value == true) {
				$jobType = 'jobPurgeCorrelation';
				$jobTypeText = 'purge correlations';
			} else {
				$jobType = 'jobGenerateCorrelation';
				$jobTypeText = 'generate correlation';
			}
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

	public function ipLogBeforeHook($setting, $value) {
		if ($setting == 'MISP.log_client_ip') {
			if ($value == true) {
				$this->updateDatabase('addIPLogging');
			}
		}
		return true;
	}

	public function customAuthBeforeHook($setting, $value) {
		if ($value) $this->updateDatabase('addCustomAuth');
		$this->cleanCacheFiles();
		return true;
	}

	// never come here directly, always go through a secondary check like testForTermsFile in order to also pass along the expected file path
	private function __testForFile($value, $path) {
		if ($this->testForEmpty($value) !== true) return $this->testForEmpty($value);
		if (!$this->checkFilename($value)) return 'Invalid filename.';
		$file = $path . DS . $value;
		if (!file_exists($file)) return 'Could not find the specified file. Make sure that it is uploaded into the following directory: ' . $path;
		return true;
	}

	public function serverSettingsSaveValue($setting, $value) {
		Configure::write($setting, $value);
		$arrayFix = array(
			'Security.auth',
			'ApacheSecureAuth.ldapFilter'
		);
		foreach ($arrayFix as $settingFix) {
			if (Configure::read($settingFix) && is_array(Configure::read($settingFix)) && !empty(Configure::read($settingFix))) {
				$arrayElements = array();
				foreach (Configure::read($settingFix) as $array) {
					if (!in_array($array, $arrayElements)) $arrayElements[] = $array;
				}
				Configure::write($settingFix, $arrayElements);
			}
		}
		$settingsToSave = array('debug', 'MISP', 'GnuPG', 'SMIME', 'Proxy', 'SecureAuth', 'Security', 'Session.defaults', 'Session.timeout', 'Session.autoRegenerate', 'site_admin_debug', 'Plugin', 'CertAuth', 'ApacheShibbAuth', 'ApacheSecureAuth');
		$settingsArray = array();
		foreach ($settingsToSave as $setting) {
			$settingsArray[$setting] = Configure::read($setting);
		}
		$settingsString = var_export($settingsArray, true);
		$settingsString = '<?php' . "\n" . '$config = ' . $settingsString . ';';
		if (function_exists('opcache_reset')) opcache_reset();
		file_put_contents(APP . 'Config' . DS . 'config.php', $settingsString);
	}

	public function checkVersion($newest) {
		$version_array = $this->checkMISPVersion();
		$current = 'v' . $version_array['major'] . '.' . $version_array['minor'] . '.' . $version_array['hotfix'];
		$newest_array = $this->__dissectVersion($newest);
		$upToDate = $this->__compareVersions(array($version_array['major'], $version_array['minor'], $version_array['hotfix']), $newest_array, 0);
		return array ('current' => $current, 'newest' => $newest, 'upToDate' => $upToDate);
	}

	private function __dissectVersion($version) {
		$version = substr($version, 1);
		return explode('.', $version);
	}

	private function __compareVersions($current, $newest, $i) {
		if ($current[$i] == $newest[$i]) {
			if ($i < 2) {
				return $this->__compareVersions($current, $newest, $i+1);
			} else {
				return 'same';
			}
		} else if ($current[$i] < $newest[$i]) {
			return 'older';
		} else {
			return 'newer';
		}
	}

	public function getFileRules() {
		$validItems = array(
				'orgs' => array(
						'name' => 'Organisation logos',
						'description' => 'The logo used by an organisation on the event index, event view, discussions, proposals, etc. Make sure that the filename is in the org.png format, where org is the case-sensitive organisation name.',
						'expected' => array(),
						'valid_format' => '48x48 pixel .png files',
						'path' => APP . 'webroot' . DS . 'img' . DS . 'orgs',
						'regex' => '.*\.(png|PNG)$',
						'regex_error' => 'Filename must be in the following format: *.png',
						'files' => array(),
				),
				'img' => array(
						'name' => 'Additional image files',
						'description' => 'Image files uploaded into this directory can be used for various purposes, such as for the login page logos',
						'expected' => array(
								'MISP.footer_logo' => Configure::read('MISP.footer_logo'),
								'MISP.home_logo' => Configure::read('MISP.home_logo'),
								'MISP.welcome_logo' => Configure::read('MISP.welcome_logo'),
								'MISP.welcome_logo2' => Configure::read('MISP.welcome_logo2'),
						),
						'valid_format' => 'text/html if served inline, anything that conveys the terms of use if served as download',
						'path' => APP . 'webroot' . DS . 'img' . DS . 'custom',
						'regex' => '.*\.(png|PNG)$',
						'regex_error' => 'Filename must be in the following format: *.png',
						'files' => array(),
				),
		);
		return $validItems;
	}

	public function grabFiles() {
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

	public function runConnectionTest($id) {
		$server = $this->find('first', array('conditions' => array('Server.id' => $id)));
		App::uses('SyncTool', 'Tools');
		$syncTool = new SyncTool();
		$HttpSocket = $syncTool->setupHttpSocket($server);
		$request = array(
			'header' => array(
				'Authorization' => $server['Server']['authkey'],
				'Accept' => 'application/json',
				'Content-Type' => 'application/json',
			)
		);
		$uri = $server['Server']['url'] . '/servers/getVersion';
		try {
			$response = $HttpSocket->get($uri, false, $request);
		} catch (Exception $e) {
			$this->Log = ClassRegistry::init('Log');
			$this->Log->create();
			$this->Log->save(array(
					'org' => 'SYSTEM',
					'model' => 'Server',
					'model_id' => $id,
					'email' => 'SYSTEM',
					'action' => 'error',
					'user_id' => 0,
					'title' => 'Error: Connection test failed. Reason: ' . json_encode($e->getMessage()),
			));
			return array('status' => 2);
		}
		if ($response->isOk()) {
			return array('status' => 1, 'message' => $response->body());
		} else {
			if ($response->code == '403') return array('status' => 4);
			if ($response->code == '405') {
				try {
					$responseText = json_decode($response->body, true)['message'];
				} catch (Exception $e) {
					return array('status' => 3);
				}
				if ($responseText === 'Your user account is expecting a password change, please log in via the web interface and change it before proceeding.') return array('status' => 5);
				else if ($responseText === 'You have not accepted the terms of use yet, please log in via the web interface and accept them.') return array('status' => 6);
			}
			return array('status' => 3);
		}
	}

	public function runPOSTtest($id) {
		$server = $this->find('first', array('conditions' => array('Server.id' => $id)));
		App::uses('SyncTool', 'Tools');
		$syncTool = new SyncTool();
		$HttpSocket = $syncTool->setupHttpSocket($server);
		$request = array(
			'header' => array(
				'Authorization' => $server['Server']['authkey'],
				'Accept' => 'application/json',
				'Content-Type' => 'application/json',
			)
		);
		$testFile = file_get_contents(APP . 'files/scripts/test_payload.txt');
		$uri = $server['Server']['url'] . '/servers/postTest';
		$this->Log = ClassRegistry::init('Log');
		try {
			$response = $HttpSocket->post($uri, json_encode(array('testString' => $testFile)), $request);
			$response = json_decode($response, true);
		} catch (Exception $e) {
			$this->Log->create();
			$this->Log->save(array(
					'org' => 'SYSTEM',
					'model' => 'Server',
					'model_id' => $id,
					'email' => 'SYSTEM',
					'action' => 'error',
					'user_id' => 0,
					'title' => 'Error: POST connection test failed. Reason: ' . json_encode($e->getMessage()),
			));
			return 8;
		}
		if (!isset($response['body']['testString']) || $response['body']['testString'] !== $testFile) {
			$responseString = isset($response['body']['testString']) ? $response['body']['testString'] : 'Response was empty.';
			$this->Log->create();
			$this->Log->save(array(
					'org' => 'SYSTEM',
					'model' => 'Server',
					'model_id' => $id,
					'email' => 'SYSTEM',
					'action' => 'error',
					'user_id' => 0,
					'title' => 'Error: POST connection test failed due to the message body not containing the expected data. Response: ' . PHP_EOL . PHP_EOL . $responseString,
			));
			return 9;
		}
		$headers = array('Accept', 'Content-type');
		foreach ($headers as $header) {
			if (!isset($response['headers'][$header]) || $response['headers'][$header] != 'application/json') {
				$responseHeader = isset($response['headers'][$header]) ? $response['headers'][$header] : 'Header was not set.';
				$this->Log->create();
				$this->Log->save(array(
						'org' => 'SYSTEM',
						'model' => 'Server',
						'model_id' => $id,
						'email' => 'SYSTEM',
						'action' => 'error',
						'user_id' => 0,
						'title' => 'Error: POST connection test failed due to a header not matching the expected value. Expected: "application/json", received "' . $responseHeader,
				));
				return 10;
			}
		}
		return 1;
	}

	public function checkVersionCompatibility($id, $user = array(), $HttpSocket = false) {
		// for event publishing when we don't have a user.
		if (empty($user)) $user = array('Organisation' => array('name' => 'SYSTEM'), 'email' => 'SYSTEM', 'id' => 0);
		App::uses('Folder', 'Utility');
		$file = new File(ROOT . DS . 'VERSION.json', true);
		$localVersion = json_decode($file->read(), true);
		$file->close();
		$server = $this->find('first', array('conditions' => array('Server.id' => $id)));
		if (!$HttpSocket) {
			App::uses('SyncTool', 'Tools');
			$syncTool = new SyncTool();
			$HttpSocket = $syncTool->setupHttpSocket($server);
		}
		$uri = $server['Server']['url'] . '/servers/getVersion';
		$request = array(
				'header' => array(
						'Authorization' => $server['Server']['authkey'],
						'Accept' => 'application/json',
						'Content-Type' => 'application/json',
				)
		);
		try {
			$response = $HttpSocket->get($uri, '', $request);
		} catch (Exception $e) {
			if (!isset($response) || $response->code != '200') {
				$this->Log = ClassRegistry::init('Log');
				$this->Log->create();
				if (isset($response->code)) {
					$title = 'Error: Connection to the server has failed.' . isset($response->code) ? ' Returned response code: ' . $response->code : '';
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
						'title' => $title,
				));
			}
		}
		if (!isset($response) || $response->code != '200') {
			return 1;
		}
		$remoteVersion = json_decode($response->body, true);
		$canPush = isset($remoteVersion['perm_sync']) ? $remoteVersion['perm_sync'] : false;
		$remoteVersion = explode('.', $remoteVersion['version']);
		if (!isset($remoteVersion[0])) {
			$this->Log = ClassRegistry::init('Log');
			$this->Log->create();
			$this->Log->save(array(
					'org' => $user['Organisation']['name'],
					'model' => 'Server',
					'model_id' => $id,
					'email' => $user['email'],
					'action' => 'error',
					'user_id' => $user['id'],
					'title' => 'Error: Server didn\'t send the expected response. This may be because the remote server version is outdated.',
			));
			return 2;
		}
		$response = false;
		$success = false;
		$issueLevel = "warning";
		if ($localVersion['major'] > $remoteVersion[0]) $response = "Sync to Server ('" . $id . "') aborted. The remote instance's MISP version is behind by a major version.";
		if ($response === false && $localVersion['major'] < $remoteVersion[0]) {
			$response = "Sync to Server ('" . $id . "') aborted. The remote instance is at least a full major version ahead - make sure you update your MISP instance!";
		}
		if ($response === false && $localVersion['minor'] > $remoteVersion[1]) $response = "Sync to Server ('" . $id . "') aborted. The remote instance's MISP version is behind by a minor version.";
		if ($response === false && $localVersion['minor'] < $remoteVersion[1]) {
			$response = "Sync to Server ('" . $id . "') aborted. The remote instance is at least a full minor version ahead - make sure you update your MISP instance!";
		}

		// if we haven't set a message yet, we're good to go. We are only behind by a hotfix version
		if ($response === false) {
			$success = true;
		}
		else $issueLevel = "error";
		if ($response === false && $localVersion['hotfix'] > $remoteVersion[2]) $response = "Sync to Server ('" . $id . "') initiated, but the remote instance is a few hotfixes behind.";
		if ($response === false && $localVersion['hotfix'] < $remoteVersion[2]) $response = "Sync to Server ('" . $id . "') initiated, but the remote instance is a few hotfixes ahead. Make sure you keep your instance up to date!";

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
		return array('success' => $success, 'response' => $response, 'canPush' => $canPush, 'version' => $remoteVersion);
	}

	/* This is a fallback for legacy remote instances that don't report back the current user's sync permission.
	 *
	 * The idea is simple: If we have no way of determining the perm_sync flag from the remote instance, request
	 * /servers/testConnection from the remote. This API is used to check the remote connectivity and expects an ID to be passed
	 * In this case however we are not passing an ID so ideally it will return 404, meaning that the instance is invalid.
	 * We are abusing the fact that only sync users can use this functionality, if we don't have sync permission we'll get a 403
	 * instead of the 404. It's hacky but it works fine and serves the purpose.
	 */
	public function checkLegacyServerSyncPrivilege($id, $HttpSocket = false) {
		$server = $this->find('first', array('conditions' => array('Server.id' => $id)));
		if (!$HttpSocket) {
			App::uses('SyncTool', 'Tools');
			$syncTool = new SyncTool();
			$HttpSocket = $syncTool->setupHttpSocket($server);
		}
		$uri = $server['Server']['url'] . '/servers/testConnection';
		$request = array(
				'header' => array(
						'Authorization' => $server['Server']['authkey'],
						'Accept' => 'application/json',
						'Content-Type' => 'application/json',
				)
		);
		try {
			$response = $HttpSocket->get($uri, '', $request);
		} catch (Exception $e) {
			return false;
		}
		if ($response->code == '404') {
			return true;
		}
		return false;
	}

	public function isJson($string) {
		return (json_last_error() == JSON_ERROR_NONE);
	}

	public function captureServer($server, $user) {
		if (isset($server[0])) $server = $server[0];
		if ($server['url'] == Configure::read('MISP.baseurl')) return 0;
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

	public function writeableDirsDiagnostics(&$diagnostic_errors) {
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
			if (is_null($dir->path)) $error = 1;
			$file = new File($path . DS . 'test.txt', true);
			if ($error == 0 && !$file->write('test')) $error = 2;
			if ($error != 0) $diagnostic_errors++;
			$file->delete();
			$file->close();
		}
		return $writeableDirs;
	}

	public function writeableFilesDiagnostics(&$diagnostic_errors) {
		$writeableFiles = array(
				APP . 'Config' . DS . 'config.php' => 0,
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

	public function readableFilesDiagnostics(&$diagnostic_errors) {
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

	public function stixDiagnostics(&$diagnostic_errors, &$stixVersion, &$cyboxVersion, &$mixboxVersion) {
		$result = array();
		$expected = array('stix' => '1.1.1.4', 'cybox' => '2.1.0.12', 'mixbox' => '1.0.2');
		// check if the STIX and Cybox libraries are working using the test script stixtest.py
		$scriptResult = shell_exec('python ' . APP . 'files' . DS . 'scripts' . DS . 'stixtest.py');
		$scriptResult = json_decode($scriptResult, true);
		if ($scriptResult !== null) {
			$scriptResult['operational'] = $scriptResult['success'];
			if ($scriptResult['operational'] == 0) {
				$diagnostic_errors++;
				return array('operational' => 0, 'stix' => array('expected' => $expected['stix']), 'cybox' => array('expected' => $expected['cybox']), 'mixbox' => array('expected' => $expected['mixbox']));
			}
		} else {
			return array('operational' => 0, 'stix' => array('expected' => $expected['stix']), 'cybox' => array('expected' => $expected['cybox']), 'mixbox' => array('expected' => $expected['mixbox']));
		}
		$result['operational'] = $scriptResult['operational'];
		foreach ($expected as $package => $version) {
			$result[$package]['version'] = $scriptResult[$package];
			$result[$package]['expected'] = $expected[$package];
			$result[$package]['status'] = $result[$package]['version'] == $result[$package]['expected'] ? 1 : 0;
			if ($result[$package]['status'] == 0) $diagnostic_errors++;
			${$package . 'Version'}[0] = str_replace('$current', $result[$package]['version'], ${$package . 'Version'}[0]);
			${$package . 'Version'}[0] = str_replace('$expected', $result[$package]['expected'], ${$package . 'Version'}[0]);
		}
		return $result;
	}

	public function gpgDiagnostics(&$diagnostic_errors) {
		$gpgStatus = 0;
		if (Configure::read('GnuPG.email') && Configure::read('GnuPG.homedir')) {
			$continue = true;
			try {
				require_once 'Crypt/GPG.php';
				$gpg = new Crypt_GPG(array('homedir' => Configure::read('GnuPG.homedir'), 'binary' => (Configure::read('GnuPG.binary') ? Configure::read('GnuPG.binary') : '/usr/bin/gpg')));
			} catch (Exception $e) {
				$gpgStatus = 2;
				$continue = false;
			}
			if ($continue) {
				try {
					$key = $gpg->addSignKey(Configure::read('GnuPG.email'), Configure::read('GnuPG.password'));
				} catch (Exception $e) {
					$gpgStatus = 3;
					$continue = false;
				}
			}
			if ($continue) {
				try {
					$gpgStatus = 0;
					$signed = $gpg->sign('test', Crypt_GPG::SIGN_MODE_CLEAR);
				} catch (Exception $e) {
					$gpgStatus = 4;
				}
			}
		} else {
			$gpgStatus = 1;
		}
		if ($gpgStatus != 0) $diagnostic_errors++;
		return $gpgStatus;
	}

	public function zmqDiagnostics(&$diagnostic_errors) {
		if (!Configure::read('Plugin.ZeroMQ_enable')) return 1;
		$pubSubTool = $this->getPubSubTool();
		if (!$pubSubTool->checkIfPythonLibInstalled()) {
			$diagnostic_errors++;
			return 2;
		}
		if ($pubSubTool->checkIfRunning()) return 0;
		$diagnostic_errors++;
		return 3;
	}

	public function moduleDiagnostics(&$diagnostic_errors, $type = 'Enrichment') {
		$this->Module = ClassRegistry::init('Module');
		$types = array('Enrichment', 'Import', 'Export', 'Cortex');
		$diagnostic_errors++;
		if (Configure::read('Plugin.' . $type . '_services_enable')) {
			$exception = false;
			$result = $this->Module->getModules(false, $type, $exception);
			if ($exception) return $exception;
			if (empty($result)) return 2;
			$diagnostic_errors--;
			return 0;
		}
		return 1;
	}

	public function proxyDiagnostics(&$diagnostic_errors) {
		$proxyStatus = 0;
		$proxy = Configure::read('Proxy');
		if (!empty($proxy['host'])) {
			App::uses('SyncTool', 'Tools');
			$syncTool = new SyncTool();
			try {
				$HttpSocket = $syncTool->setupHttpSocket();
				$proxyResponse = $HttpSocket->get('http://www.example.com/');
			} catch (Exception $e) {
				$proxyStatus = 2;
			}
			if (empty($proxyResponse) || $proxyResponse->code > 399) {
				$proxyStatus = 2;
			}
		} else {
			$proxyStatus = 1;
		}
		if ($proxyStatus > 1) $diagnostic_errors++;
		return $proxyStatus;
	}

	public function sessionDiagnostics(&$diagnostic_errors = 0, &$sessionCount = '') {
		if (Configure::read('Session.defaults') !== 'database') {
			$sessionCount = 'N/A';
			return 2;
		}
		$sql = 'SELECT COUNT(id) AS session_count FROM cake_sessions WHERE expires < ' . time() . ';';
		$sqlResult = $this->query($sql);
		if (isset($sqlResult[0][0])) $sessionCount = $sqlResult[0][0]['session_count'];
		else {
			$sessionCount = 'Error';
			return 3;
		}
		if ($sessionCount > 1000) {
			$diagnostic_errors++;
			return 1;
		}
		return 0;
	}

	public function workerDiagnostics(&$workerIssueCount) {
		try {
			$this->ResqueStatus = new ResqueStatus\ResqueStatus(Resque::redis());
		} catch (Exception $e) {
			// redis connection failed
			return array(
					'cache' => array('ok' => false),
					'default' => array('ok' => false),
					'email' => array('ok' => false),
					'prio' => array('ok' => false),
					'scheduler' => array('ok' => false)
			);
		}
		$workers = $this->ResqueStatus->getWorkers();
		if (function_exists('posix_getpwuid')) {
			$currentUser = posix_getpwuid(posix_geteuid());
			$currentUser = $currentUser['name'];
		} else {
			$currentUser = trim(shell_exec('whoami'));
		}
		$worker_array = array(
				'cache' => array('ok' => true),
				'default' => array('ok' => true),
				'email' => array('ok' => true),
				'prio' => array('ok' => true),
				'scheduler' => array('ok' => true)
		);
		$procAccessible = file_exists('/proc');
		foreach ($workers as $pid => $worker) {
			$entry = ($worker['type'] == 'regular') ? $worker['queue'] : $worker['type'];
			$correct_user = ($currentUser === $worker['user']);
			if (!is_numeric($pid)) throw new MethodNotAllowedException('Non numeric PID found.');
			if ($procAccessible) {
				$alive = $correct_user ? (file_exists('/proc/' . addslashes($pid))) : false;
			} else {
				$alive = 'N/A';
			}
			$ok = true;
			if (!$alive || !$correct_user) {
				$ok = false;
				$workerIssueCount++;
				$worker_array[$entry]['ok'] = false;
			}
			$worker_array[$entry]['workers'][] = array('pid' => $pid, 'user' => $worker['user'], 'alive' => $alive, 'correct_user' => $correct_user, 'ok' => $ok);
		}
		foreach ($worker_array as $k => $queue) {
			if ($k != 'scheduler') $worker_array[$k]['jobCount'] = CakeResque::getQueueSize($k);
			if (!isset($queue['workers'])) {
				$workerIssueCount++;
				$worker_array[$k]['ok'] = false;
			}
		}
		$worker_array['proc_accessible'] = $procAccessible;
		return $worker_array;
	}

	public function retrieveCurrentSettings($branch, $subString) {
		$settings = array();
		foreach ($this->serverSettings[$branch] as $settingName => $setting) {
			if (strpos($settingName, $subString) !== false) {
				$settings[$settingName] = $setting['value'];
				if (Configure::read('Plugin.' . $settingName)) $settings[$settingName] = Configure::read('Plugin.' . $settingName);
				if (isset($setting['options'])) $settings[$settingName] = $setting['options'][$settings[$settingName]];
			}
		}
		return $settings;
	}

	public function killWorker($pid, $user) {
		if (!is_numeric($pid)) throw new MethodNotAllowedException('Non numeric PID found!');
		$this->ResqueStatus = new ResqueStatus\ResqueStatus(Resque::redis());
		$workers = $this->ResqueStatus->getWorkers();
		$this->Log = ClassRegistry::init('Log');
		if (isset($workers[$pid])) {
			$worker = $workers[$pid];
			if (substr_count(trim(shell_exec('ps -p ' . $pid)), PHP_EOL) > 0 ? true : false) {
				shell_exec('kill ' . $pid . ' > /dev/null 2>&1 &');
				$this->Log->create();
				$this->Log->save(array(
						'org' => $user['Organisation']['name'],
						'model' => 'User',
						'model_id' => $user['id'],
						'email' => $user['email'],
						'action' => 'stop_worker',
						'user_id' => $user['id'],
						'title' => 'Stopping a worker.',
						'change' => 'Stopping a worker. Worker was of type ' . $worker['queue'] . ' with pid ' . $pid
				));
			} else {
				$this->ResqueStatus->removeWorker($pid);
				$this->Log->create();
				$this->Log->save(array(
						'org' => $user['Organisation']['name'],
						'model' => 'User',
						'model_id' => $user['id'],
						'email' => $user['email'],
						'action' => 'remove_dead_workers',
						'user_id' => $user['id'],
						'title' => 'Removing a dead worker.',
						'change' => 'Removing dead worker data. Worker was of type ' . $worker['queue'] . ' with pid ' . $pid
				));
			}
			$this->ResqueStatus->removeWorker($pid);
		}
	}

	public function workerRemoveDead($user) {
		$this->ResqueStatus = new ResqueStatus\ResqueStatus(Resque::redis());
		$workers = $this->ResqueStatus->getWorkers();
		$this->Log = ClassRegistry::init('Log');
		if (function_exists('posix_getpwuid')) {
			$currentUser = posix_getpwuid(posix_geteuid());
			$currentUser = $currentUser['name'];
		} else $currentUser = trim(shell_exec('whoami'));
		foreach ($workers as $pid => $worker) {
			if (!is_numeric($pid)) throw new MethodNotAllowedException('Non numeric PID found!');
			$pidTest = substr_count(trim(shell_exec('ps -p ' . $pid)), PHP_EOL) > 0 ? true : false;
			if ($worker['user'] == $currentUser && !$pidTest) {
				$this->ResqueStatus->removeWorker($pid);
				$this->Log->create();
				$this->Log->save(array(
						'org' => $user['Organisation']['name'],
						'model' => 'User',
						'model_id' => $user['id'],
						'email' => $user['email'],
						'action' => 'remove_dead_workers',
						'user_id' => $user['id'],
						'title' => 'Removing a dead worker.',
						'change' => 'Removing dead worker data. Worker was of type ' . $worker['queue'] . ' with pid ' . $pid
				));
			}
		}
	}

	public function upgrade2324($user_id, $jobId = false) {
		$this->cleanCacheFiles();
		if (Configure::read('MISP.background_jobs') && $jobId) {
			$this->Job = ClassRegistry::init('Job');
			$this->Job->id = $jobId;
		}
		$this->Log = ClassRegistry::init('Log');
		$this->Organisation = ClassRegistry::init('Organisation');
		$this->Attribute = ClassRegistry::init('Attribute');
		$this->Log->create();
		$this->Log->save(array(
				'org' => 'SYSTEM',
				'model' => 'Server',
				'model_id' => 0,
				'email' => 'SYSTEM',
				'action' => 'upgrade_24',
				'user_id' => 0,
				'title' => 'Upgrade initiated',
				'change' => 'Starting the migration of the database to 2.4',
		));
		if (Configure::read('MISP.background_jobs') && $jobId) {
			$this->Job->saveField('progress', 10);
			$this->Job->saveField('message', 'Starting the migration of the database to 2.4');
		}
		$this->query('UPDATE roles SET perm_template = 1 WHERE perm_site_admin = 1 OR perm_admin = 1');
		$this->query('UPDATE roles SET perm_sharing_group = 1 WHERE perm_site_admin = 1 OR perm_sync = 1');
		$orgs = array('local' => array(), 'external' => array());
		$captureRules = array(
				'events_org' => array('table' => 'events', 'old' => 'org', 'new' => 'org_id'),
				'events_orgc' => array('table' => 'events', 'old' => 'orgc', 'new' => 'orgc_id'),
				'jobs_org' => array('table' => 'jobs', 'old' => 'org', 'new' => 'org_id'),
				'servers_org' => array('table' => 'servers', 'old' => 'org', 'new' => 'org_id'),
				'servers_organization' => array('table' => 'servers', 'old' => 'organization', 'new' => 'remote_org_id'),
				'shadow_attributes_org' => array('table' => 'shadow_attributes', 'old' => 'org', 'new' => 'org_id'),
				'shadow_attributes_event_org' => array('table' => 'shadow_attributes', 'old' => 'event_org', 'new' => 'event_org_id'),
				'threads_org' => array('table' => 'threads', 'old' => 'org', 'new' => 'org_id'),
				'users_org' => array('table' => 'users', 'old' => 'org', 'new' => 'org_id'),
		);
		$rules = array(
				'local' => array(
						$captureRules['users_org'],
				),
				'external' => array(
						$captureRules['events_org'],
						$captureRules['events_orgc'],
						$captureRules['shadow_attributes_event_org'],
						$captureRules['shadow_attributes_org'],
						$captureRules['servers_organization'],
						$captureRules['threads_org'],
						$captureRules['jobs_org'],
						$captureRules['servers_org'],
				)
		);
		foreach ($rules as $k => $type) {
			foreach ($type as $rule) {
				$temp = ($this->query('SELECT DISTINCT(`' . $rule['old'] . '`) from `' . $rule['table'] . '` WHERE ' . $rule['new'] . '= "";'));
				foreach ($temp as $t) {
					// in case we have something in the db with a missing org, let's hop over that
					if ($t[$rule['table']][$rule['old']] !== '') {
						if ($k == 'local' && !in_array($t[$rule['table']][$rule['old']], $orgs[$k])) $orgs[$k][] = $t[$rule['table']][$rule['old']];
						else if ($k == 'external' && !in_array($t[$rule['table']][$rule['old']], $orgs['local']) && !in_array($t[$rule['table']][$rule['old']], $orgs[$k])) $orgs[$k][] = $t[$rule['table']][$rule['old']];
					} else {
						$this->Log->create();
						$this->Log->save(array(
								'org' => 'SYSTEM',
								'model' => 'Server',
								'model_id' => 0,
								'email' => 'SYSTEM',
								'action' => 'upgrade_24',
								'user_id' => 0,
								'title' => '[ERROR] - Detected empty string organisation identifier during the upgrade',
								'change' => 'Detected entries in table `' . $rule['table'] . '` where `' . $rule['old'] . '` was blank. This has to be resolved manually!',
						));
					}
				}
			}
		}
		$this->Log->create();
		$this->Log->save(array(
				'org' => 'SYSTEM',
				'model' => 'Server',
				'model_id' => 0,
				'email' => 'SYSTEM',
				'action' => 'upgrade_24',
				'user_id' => 0,
				'title' => 'Organisation creation',
				'change' => 'Detected ' . count($orgs['local']) . ' local organisations and ' . count($orgs['external']) . ' external organisations. Starting organisation creation.',
		));
		if (Configure::read('MISP.background_jobs') && $jobId) {
			$this->Job->saveField('progress', 20);
			$this->Job->saveField('message', 'Starting organisation creation');
		}
		$orgMapping = array();
		foreach ($orgs as $k => $orgArray) {
			foreach ($orgArray as $org) {
				$orgMapping[$org] = $this->Organisation->createOrgFromName($org, $user_id, $k == 'local' ? true : false);
			}
		}
		$this->Log->create();
		$this->Log->save(array(
				'org' => 'SYSTEM',
				'model' => 'Server',
				'model_id' => 0,
				'email' => 'SYSTEM',
				'action' => 'upgrade_24',
				'user_id' => 0,
				'title' => 'Organisations created and / or mapped',
				'change' => 'Captured all missing organisations and created a mapping between the old organisation tag and the organisation IDs. ',
		));
		if (Configure::read('MISP.background_jobs') && $jobId) {
			$this->Job->saveField('progress', 30);
			$this->Job->saveField('message', 'Updating all current entries');
		}
		foreach ($orgMapping as $old => $new) {
			foreach ($captureRules as $rule) {
				$this->query('UPDATE `' . $rule['table'] . '` SET `' . $rule['new'] . '`="' . $new . '" WHERE (`' . $rule['old'] . '`="' . $old . '" AND `' . $rule['new'] . '`="");');
			}
		}
		if (Configure::read('MISP.background_jobs') && $jobId) {
			$this->Job->saveField('progress', 40);
			$this->Job->saveField('message', 'Rebuilding all correlations.');
		}
		//$this->Attribute->generateCorrelation($jobId, 40);
		// upgrade correlations. No need to recorrelate, we can be a bit trickier here
		// Private = 0 attributes become distribution 1 for both the event and attribute.
		// For all intents and purposes, this oversimplification works fine when upgrading from 2.3
		// Even though the distribution values stored in the correlation won't be correct, they will provide the exact same realeasability
		// Event1 = distribution 0 and Attribute1 distribution 3 would lead to private = 1, so setting distribution = 0 and a_distribution = 0
		// will result in the same visibility, etc. Once events / attributes get put into a sharing group this will get recorrelated anyway
		// Also by unsetting the org field after the move the changes we ensure that these correlations won't get hit again by the script if we rerun it
		// and that we don't accidentally "upgrade" a 2.4 correlation
		$this->query('UPDATE correlations SET distribution = 1, a_distribution = 1 WHERE org != "" AND private = 0');
		foreach ($orgMapping as $old => $new) {
			$this->query('UPDATE correlations SET org_id = "' . $new . '", org = "" WHERE org = "' . $old . '";');
		}
		if (Configure::read('MISP.background_jobs') && $jobId) {
			$this->Job->saveField('progress', 60);
			$this->Job->saveField('message', 'Correlations rebuilt. Indexing all tables.');
		}
		$this->updateDatabase('indexTables');
		if (Configure::read('MISP.background_jobs') && $jobId) {
			$this->Job->saveField('progress', 100);
			$this->Job->saveField('message', 'Upgrade complete.');
		}
	}

	/* returns the version string of a connected instance
	 * error codes:
	 * 1: received non json response
	 * 2: no route to host
	 * 3: empty result set
	 */
	public function getRemoteVersion($id) {
		$server = $this->find('first', array(
				'conditions' => array('Server.id' => $id),
		));
		if (empty($server)) {
			return 2;
		}
		App::uses('SyncTool', 'Tools');
		$syncTool = new SyncTool();
		$HttpSocket = $syncTool->setupHttpSocket($server);
		$response = $HttpSocket->get($server['Server']['url'] . '/servers/getVersion', $data = '', $request);
		if ($response->code == 200) {
			try {
				$data = json_decode($response->body, true);
			} catch (Exception $e) {
				return 1;
			}
			if (isset($data['version']) && !empty($data['version'])) {
				return $data['version'];
			} else return 3;
		} return 2;
	}


	/* returns an array with the events
	 * error codes:
	 * 1: received non json response
	 * 2: no route to host
	 * 3: empty result set
	 */
	public function previewIndex($id, $user, $passedArgs) {
		$server = $this->find('first', array(
			'conditions' => array('Server.id' => $id),
		));
		if (empty($server)) {
			return 2;
		}
		App::uses('SyncTool', 'Tools');
		$syncTool = new SyncTool();
		$HttpSocket = $syncTool->setupHttpSocket($server);
		$request = array(
				'header' => array(
						'Authorization' => $server['Server']['authkey'],
						'Accept' => 'application/json',
						'Content-Type' => 'application/json',
						//'Connection' => 'keep-alive' // // LATER followup cakephp issue about this problem: https://github.com/cakephp/cakephp/issues/1961
				)
		);
		$validArgs = array_merge(array('sort', 'direction'), $this->validEventIndexFilters);
		$urlParams = '';
		foreach ($validArgs as $v) {
			if (isset($passedArgs[$v])) $urlParams .= '/' . $v . ':' . $passedArgs[$v];
		}
		$uri = $server['Server']['url'] . '/events/index' . $urlParams;
		$response = $HttpSocket->get($uri, $data = '', $request);
		if ($response->code == 200) {
			try {
				$events = json_decode($response->body, true);
			} catch (Exception $e) {
				return 1;
			}
			if (!empty($events)) foreach ($events as $k => $event) {
				if (!isset($event['Orgc'])) $event['Orgc']['name'] = $event['orgc'];
				if (!isset($event['Org'])) $event['Org']['name'] = $event['org'];
				if (!isset($event['EventTag'])) $event['EventTag'] = array();
				$events[$k] = array('Event' => $event);
			} else return 3;
			return $events;
		}
		return 2;
	}

	/* returns an array with the events
	 * error codes:
	 * 1: received non-json response
	 * 2: no route to host
	 */
	public function previewEvent($serverId, $eventId) {
		$server = $this->find('first', array(
				'conditions' => array('Server.id' => $serverId),
		));
		if (empty($server)) {
			return 2;
		}
		App::uses('SyncTool', 'Tools');
		$syncTool = new SyncTool();
		$HttpSocket = $syncTool->setupHttpSocket($server);
		$request = array(
				'header' => array(
						'Authorization' => $server['Server']['authkey'],
						'Accept' => 'application/json',
						'Content-Type' => 'application/json',
						//'Connection' => 'keep-alive' // // LATER followup cakephp issue about this problem: https://github.com/cakephp/cakephp/issues/1961
				)
		);
		$uri = $server['Server']['url'] . '/events/' . $eventId;
		$response = $HttpSocket->get($uri, $data = '', $request);
		if ($response->code == 200) {
			try {
				$event = json_decode($response->body, true);
			} catch (Exception $e) {
				return 1;
			}
			if (!isset($event['Event']['Orgc'])) $event['Event']['Orgc']['name'] = $event['Event']['orgc'];
			if (isset($event['Event']['Orgc'][0])) $event['Event']['Orgc'] = $event['Event']['Orgc'][0];
			if (!isset($event['Event']['Org'])) $event['Event']['Org']['name'] = $event['Event']['org'];
			if (isset($event['Event']['Org'][0])) $event['Event']['Org'] = $event['Event']['Org'][0];
			if (!isset($event['Event']['EventTag'])) $event['Event']['EventTag'] = array();
			return $event;
		}
		return 2;
	}

	// Loops through all servers and checks which servers' push rules don't conflict with the given event.
	// returns the server objects that would allow the event to be pushed
	public function eventFilterPushableServers($event, $servers) {
		$eventTags = array();
		$validServers = array();
		foreach ($event['EventTag'] as $tag) $eventTags[] = $tag['tag_id'];
		foreach ($servers as $server) {
			$push_rules = json_decode($server['Server']['push_rules'], true);
			if (!empty($push_rules['tags']['OR'])) {
				$intersection = array_intersect($push_rules['tags']['OR'], $eventTags);
				if (empty($intersection)) continue;
			}
			if (!empty($push_rules['tags']['NOT'])) {
				$intersection = array_intersect($push_rules['tags']['NOT'], $eventTags);
				if (!empty($intersection)) continue;
			}
			if (!empty($push_rules['orgs']['OR'])) {
				if (!in_array($event['Event']['orgc_id'], $push_rules['orgs']['OR'])) continue;
			}
			if (!empty($push_rules['orgs']['NOT'])) {
				if (in_array($event['Event']['orgc_id'], $push_rules['orgs']['NOT'])) continue;
			}
			$validServers[] = $server;
		}

		return $validServers;
	}

	public function extensionDiagnostics() {
		$results = array();
		$extensions = array('redis');
		foreach ($extensions as $extension) {
			$results['web']['extensions'][$extension] = extension_loaded($extension);
		}
		if (!is_readable(APP . '/files/scripts/selftest.php')) {
			$results['cli'] = false;
		} else {
			$results['cli'] = exec('php ' . APP . '/files/scripts/selftest.php');
			$results['cli'] = json_decode($results['cli'], true);
		}
		return $results;
	}

	public function databaseEncodingDiagnostics(&$diagnostic_errors) {
		if (!isset($this->getDataSource()->config['encoding']) || strtolower($this->getDataSource()->config['encoding']) != 'utf8') {
			$diagnostic_errors++;
			return false;
		}
		return true;
	}

	public function getLatestGitRemote() {
		return exec('timeout 3 git ls-remote https://github.com/MISP/MISP | head -1 | sed "s/HEAD//"');
	}

	public function getCurrentGitStatus() {
		$status = array();
		$status['commit'] = exec('git rev-parse HEAD');
		$status['branch'] = $this->getCurrentBranch();
		$status['latestCommit'] = $this->getLatestGitremote();
		return $status;
	}

	public function getCurrentBranch() {
		return exec("git symbolic-ref HEAD | sed 's!refs\/heads\/!!'");
	}

	public function checkoutMain() {
		$mainBranch = '2.4';
		return exec('git checkout ' . $mainBranch);
	}

	public function update($status) {
		$final = '';
		$command1 = 'git pull origin ' . $status['branch'] . ' 2>&1';
		$command2 = 'git submodule init && git submodule update 2>&1';
		$final = $command1 . "\n\n";
		exec($command1, $output);
		$final .= implode("\n", $output) . "\n\n=================================\n\n";
		$output = array();
		$final .= $command2 . "\n\n";
		exec($command2, $output);
		$final .= implode("\n", $output);
		return $final;
	}

	public function getDefaultAttachments_dir() {
		return APP . 'files';
	}
}
