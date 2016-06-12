<?php
App::uses('AppModel', 'Model');
/**
 * Server Model
 *
 */
class Server extends AppModel {

	public $name = 'Server';					// TODO general

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

/**
 * Display field
 *
 * @var string
 */
	public $displayField = 'url';

/**
 * Validation rules
 *
 * @var array
 */
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
					'email_subject_TLP_string' => array(
							'level' => 2,
							'description' => 'This is the TLP string in alert e-mail sent when an event is published.',
							'value' => 'TLP Amber',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
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
							'value' => '1',
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
							'value' => false,
							'type' => 'boolean',
							'test' => 'testBool',
							'beforeHook' => 'eventBlacklistingBeforeHook'
					),
					'enableOrgBlacklisting' => array(
							'level' => 1,
							'description' => 'Blacklisting organisation UUIDs to prevent the creation of any event created by the blacklisted organisation.',
							'value' => false,
							'type' => 'boolean',
							'test' => 'testBool',
							'beforeHook' => 'orgBlacklistingBeforeHook'
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
					'ManglePushTo23' => array(
							'level' => 0,
							'description' => 'When enabled, your 2.4+ instance can push events to MISP 2.3 installations. This is highly advised against and will result in degraded events and lost information. Use this at your own risk.',
							'value' => false,
							'errorMessage' => '',
							'test' => 'testMangle',
							'type' => 'boolean',
							'null' => true
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
					'disableUserSelfManagement' => array(
							'level' => 1,
							'description' => 'When enabled only Org and Site admins can edit a user\'s profile.',
							'value' => false,
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean',
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
					'custom_css' => array(
							'level' => 2,
							'description' => 'If you would like to customise the css, simply drop a css file in the /var/www/MISP/webroot/css directory and enter the name here.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForStyleFile',
							'type' => 'string',
							'null' => true,
					),
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
					'password_policy_length' => array(
							'level' => 2,
							'description' => 'Password length requirement. If it is not set or it is set to 0, then the default value is assumed (6).',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testPasswordLength',
							'type' => 'numeric',
					),
					'password_policy_complexity' => array(
							'level' => 2,
							'description' => 'Password complexity requirement. Leave it empty for the default setting (3 out of 4, with either a digit or a special char) or enter your own regex. Keep in mind that the length is checked in another key. Example (simple 4 out of 4): /((?=.*\d)|(?=.*\W+))(?![\n])(?=.*[A-Z])(?=.*[a-z]).*$/',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testPasswordRegex',
							'type' => 'string',
					),
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
						'test' => 'testForPortNumber',
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
					'Sightings_enable' => array(
						'level' => 1,
						'description' => 'Enables or disables the sighting functionality. When enabled, users can use the UI or the appropriate APIs to submit sightings data about indicators.',
						'value' => false,
						'errorMessage' => '',
						'test' => 'testBool',
						'type' => 'boolean',
						'beforeHook' => 'sightingsBeforeHook',
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
					'Enrichment_hover_enable' => array(
							'level' => 0,
							'description' => 'Enable/disable the hover over information retrieved from the enrichment modules',
							'value' => false,
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean'
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
			),
	);

	private $__settingTabMergeRules = array(
			'GnuPG' => 'Encryption',
			'SMIME' => 'Encryption',
			'misc' => 'Security',
			'Security' => 'Security'
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
				foreach ($eventIds as $k => &$eventId) {
					$event = $eventModel->downloadEventFromServer(
							$eventId,
							$server);
					if (null != $event) {
						$blocked = false;
						if (Configure::read('MISP.enableEventBlacklisting')) {
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
							switch ($event['Event']['distribution']) {
								case 1:
								case 'This community only': // backwards compatibility
									// if community only, downgrade to org only after pull
									$event['Event']['distribution'] = '0';
									break;
								case 2:
								case 'Connected communities': // backwards compatibility
									// if connected communities downgrade to community only
									$event['Event']['distribution'] = '1';
									break;
								case 'All communities': // backwards compatibility
									$event['Event']['distribution'] = '3';
									break;
								case 'Your organisation only': // backwards compatibility
									$event['Event']['distribution'] = '0';
									break;
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
							$result = $eventModel->_add($event, $fromXml = true, $user, $server['Server']['org_id'], $passAlong, true, $jobId);
							if ($result) $successes[] = $eventId;
							else {
								$fails[$eventId] = 'Failed (partially?) because of validation errors: '. print_r($eventModel->validationErrors, true);

							}
						} else {
							$tempUser = $user;
							$tempUser['Role']['perm_site_admin'] = false;
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
			if ($proposals !== null) {
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
			} else {
				// Fallback for < 2.4.7 instances
				$k = 0;
				foreach ($events as $eid => &$event) {
					$proposals = $eventModel->downloadEventFromServer($event, $server, null, true);
					if (null != $proposals) {
						if (isset($proposals['ShadowAttribute']['id'])) {
							$temp = $proposals['ShadowAttribute'];
							$proposals['ShadowAttribute'] = array(0 => $temp);
						}
						foreach ($proposals['ShadowAttribute'] as &$proposal) {
							$oldsa = $shadowAttribute->findOldProposal($proposal);
							$proposal['event_id'] = $eid;
							if (!$oldsa || $oldsa['timestamp'] < $proposal['timestamp']) {
								if ($oldsa) $shadowAttribute->delete($oldsa['id']);
								if (!isset($pulledProposals[$eid])) $pulledProposals[$eid] = 0;
								$pulledProposals[$eid]++;
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
									if ($shadowAttribute->save($proposal)) $shadowAttribute->sendProposalAlertEmail($eid);
								}

							}
						}
					}
					if ($jobId) {
						if ($k % 10 == 0) {
							$job->id = $jobId;
							$job->saveField('progress', 50 * (($k + 1) / count($events)));
						}
					}
					$k++;
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
				foreach ($elements as $k => &$element) {
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


	/**
	 * Get an array of event_ids that are present on the remote server
	 * TODO move this to a component
	 * @return array of event_ids
	 */
	public function getEventIdsFromServer($server, $all = false, $HttpSocket=null, $force_uuid=false, $ignoreFilterRules = false) {
		$start = microtime(true);
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
					foreach ($eventArray as $k => &$event) {
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

		if ($push !== 'mangle') {
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
					$event = $this->Event->fetchEvent($user, array('event_uuid' => $eventUuid, 'includeAttachments' => true));
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
			return;
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
				$ids = $this->getEventIdsFromServer($server, true, $HttpSocket);
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

	private function __getEnrichmentSettings() {
		$modules = $this->getEnrichmentModules();
		$result = array();
		if (!empty($modules['modules'])) {
			foreach ($modules['modules'] as $module) {
				$result[$module['name']][0] = array('name' => 'enabled', 'type' => 'boolean');
				if (isset($module['meta']['config'])) {
					foreach ($module['meta']['config'] as $conf) {
						$result[$module['name']][] = array('name' => $conf, 'type' => 'string');
					}
				}
			}
		}
		return $result;
	}

	public function getCurrentServerSettings() {
		$serverSettings = $this->serverSettings;
		$results = array();
		$currentSettings = Configure::read();
		if (Configure::read('Plugin.Enrichment_services_enable')) {
			$results = $this->__getEnrichmentSettings();
			foreach ($results as $module => $data) {
				foreach ($data as $result) {
					$setting = array('level' => 1, 'errorMessage' => '');
					if ($result['type'] == 'boolean') {
						$setting['test'] = 'testBool';
						$setting['type'] = 'boolean';
						$setting['description'] = 'Enable or disable the ' . $module . ' module.';
						$setting['value'] = false;
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
		return $serverSettings;
	}

	public function serverSettingsRead($unsorted = false) {
		$serverSettings = $this->getCurrentServerSettings();
		$results = array();
		$currentSettings = Configure::read();
		if (Configure::read('Plugin.Enrichment_services_enable')) {
			$results = $this->__getEnrichmentSettings();
			foreach ($results as $module => $data) {
				foreach ($data as $result) {
					$setting = array('level' => 1, 'errorMessage' => '');
					if ($result['type'] == 'boolean') {
						$setting['test'] = 'testBool';
						$setting['type'] = 'boolean';
						$setting['description'] = 'Enable or disable the ' . $module . ' module.';
						$setting['value'] = false;
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
		foreach ($finalSettingsUnsorted as &$temp) if (in_array($temp['tab'], array_keys($this->__settingTabMergeRules))) {
			$temp['tab'] = $this->__settingTabMergeRules[$temp['tab']];
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
		$setting = Configure::read($settingName);
		$result = $this->__evaluateLeaf($settingObject, $leafKey, $setting);
		$result['setting'] = $settingName;
		return $result;
	}

	private function __evaluateLeaf($leafValue, $leafKey, $setting) {
		if (isset($setting)) {
			$result = $this->{$leafValue['test']}($setting);
			if ($result !== true) {
				$leafValue['error'] = 1;
				if ($result !== false) $leafValue['errorMessage'] = $result;
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

	public function testForEmpty($value) {
		if ($value === '') return 'Value not set.';
		return true;
	}

	public function testForPath($value) {
		if ($value === '') return true;
		if (preg_match('/^[a-z0-9\-\_\:\/]+$/i', $value)) return true;
		return 'Invalid characters in the path.';
	}

	public function testDebug($value) {
		if ($this->testForEmpty($value) !== true) return $this->testForEmpty($value);
		if ($this->testForNumeric($value) !== true) return 'This setting has to be a number between 0 and 2, with 0 disabling debug mode.';
		if ($value === 0) return true;
		return 'This setting has to be set to 0 on production systems. Ignore this warning if this is not the case.';
	}

	public function testDebugAdmin($value) {
		if ($this->testForEmpty($value) !== true) return $this->testForEmpty($value);
		if ($this->testBool($value) !== true) return 'This setting has to be either true or false.';
		if (!$value) return true;
		return 'Enabling debug is not recommended. Turn this on temporarily if you need to see a stack trace to debug an issue, but make sure this is not left on.';
	}

	public function testDate($date) {
		if ($this->testForEmpty($date) !== true) return $this->testForEmpty($date);
		if (!strtotime($date)) return 'The date that you have entered is invalid. Expected: yyyy-mm-dd';
		return true;
	}

	public function testBaseURL($value) {
		if ($this->testForEmpty($value) !== true) return $this->testForEmpty($value);
		$protocol = ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || $_SERVER['SERVER_PORT'] == 443) === true ? 'HTTPS' : 'HTTP';
		if ($value != strtolower($protocol) . '://' . $_SERVER['HTTP_HOST']) return false;
		return true;
	}

	public function testMangle($value) {
		if ($this->testBool($value) !== true) return $this->testBool($value);
		if ($value) return 'Enabled, expect issues.';
		return true;
	}

	public function testDisableEmail($value) {
		if (isset($value) && $value) return 'E-mailing is blocked.';
		return true;
	}

	public function testLive($value) {
		if ($this->testBool($value) !== true) return $this->testBool($value);
		if (!$value) return 'MISP disabled.';
		return true;
	}

	public function testBool($value) {
		if ($this->testForEmpty($value) !== true) return $this->testForEmpty($value);
		if ($value !== true && $value !== false) return 'Value is not a boolean, make sure that you convert \'true\' to true for example.';
		return true;
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
		App::uses('PubSubTool', 'Tools');
		$pubSubTool = new PubSubTool();
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

	public function ipLogBeforeHook($setting, $value) {
		if ($setting == 'MISP.log_client_ip') {
			if ($value == true) {
				$this->updateDatabase('addIPLogging');
			}
		}
		return true;
	}

	public function eventBlacklistingBeforeHook($setting, $value) {
		$this->cleanCacheFiles();
		if ($value) {
			try {
				$this->EventBlacklist = ClassRegistry::init('EventBlacklist');
				$schema = $this->EventBlacklist->schema();
				if (!isset($schema['event_info'])) $this->updateDatabase('addEventBlacklistsContext');
			} catch (Exception $e) {
				$this->updateDatabase('addEventBlacklists');
			}
		}
		return true;
	}

	public function customAuthBeforeHook($setting, $value) {
		if ($value) $this->updateDatabase('addCustomAuth');
		$this->cleanCacheFiles();
		return true;
	}

	public function orgBlacklistingBeforeHook($setting, $value) {
		$this->cleanCacheFiles();
		if ($value) {
			try {
				$this->OrgBlacklist = ClassRegistry::init('OrgBlacklist');
				$schema = $this->OrgBlacklist->schema();
			} catch (Exception $e) {
				$this->updateDatabase('addOrgBlacklists');
			}
		}
		return true;
	}


	// never come here directly, always go through a secondary check like testForTermsFile in order to also pass along the expected file path
	private function __testForFile($value, $path) {
		if ($this->testForEmpty($value) !== true) return $this->testForEmpty($value);
		if (!preg_match('/^[\w,\s-]+(\.)?[A-Za-z0-9]+$/', $value)) return 'Invalid filename. Valid filenames can only include characters between a-z, A-Z or 0-9. They can also include - and _ and can optionally have an extension.';
		$file = $path . DS . $value;
		if (!file_exists($file)) return 'Could not find the specified file. Make sure that it is uploaded into the following directory: ' . $path;
		return true;
	}

	public function serverSettingsSaveValue($setting, $value) {
		Configure::write($setting, $value);
		Configure::dump('config.php', 'default', array('MISP', 'GnuPG', 'SMIME', 'Proxy', 'SecureAuth', 'Security', 'debug', 'site_admin_debug', 'Plugin'));
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
		foreach ($validItems as $k => &$item) {
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
			$this->Log = ClassRegistry::init('Log');
			$this->Log->create();
			$this->Log->save(array(
					'org' => $user['Organisation']['name'],
					'model' => 'Server',
					'model_id' => $id,
					'email' => $user['email'],
					'action' => 'error',
					'user_id' => $user['id'],
					'title' => 'Error: Connection to the server has failed.',
			));
			return 1;
		}
		$remoteVersion = json_decode($response->body, true);
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
		$canPush = false;
		$issueLevel = "warning";
		if ($localVersion['major'] > $remoteVersion[0]) $response = "Sync to Server ('" . $id . "') aborted. The remote instance's MISP version is behind by a major version.";
		if ($response === false && $localVersion['major'] < $remoteVersion[0]) {
			$response = "Sync to Server ('" . $id . "') aborted. The remote instance is at least a full major version ahead - make sure you update your MISP instance!";
			$canPush = true;
		}
		if ($response === false && $localVersion['minor'] > $remoteVersion[1]) $response = "Sync to Server ('" . $id . "') aborted. The remote instance's MISP version is behind by a minor version.";
		if ($response === false && $localVersion['minor'] < $remoteVersion[1]) {
			$response = "Sync to Server ('" . $id . "') aborted. The remote instance is at least a full minor version ahead - make sure you update your MISP instance!";
			$canPush = true;
		}

		// if we haven't set a message yet, we're good to go. We are only behind by a hotfix version
		if ($response === false) {
			$success = true;
			$canPush = true;
		}
		else $issueLevel = "error";
		if ($response === false && $localVersion['hotfix'] > $remoteVersion[2]) $response = "Sync to Server ('" . $id . "') initiated, but the remote instance is a few hotfixes behind.";
		if ($response === false && $localVersion['hotfix'] < $remoteVersion[2]) $response = "Sync to Server ('" . $id . "') initiated, but the remote instance is a few hotfixes ahead. Make sure you keep your instance up to date!";

		if (Configure::read('MISP.ManglePushTo23') && !$canPush) {
			$canPush = 'mangle';
			$response = "Sync to Server ('" . $id . "') should have been blocked, but mangle sync override is enabled. A downgraded synchronisation is highly advised again, please upgrade your instance as soon as possible.";
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
		return array('success' => $success, 'response' => $response, 'canPush' => $canPush, 'version' => $remoteVersion);
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
				'tmp' => 0,
				'files' => 0,
				'files' . DS . 'scripts' . DS . 'tmp' => 0,
				'tmp' . DS . 'csv_all' => 0,
				'tmp' . DS . 'csv_sig' => 0,
				'tmp' . DS . 'md5' => 0,
				'tmp' . DS . 'sha1' => 0,
				'tmp' . DS . 'snort' => 0,
				'tmp' . DS . 'suricata' => 0,
				'tmp' . DS . 'text' => 0,
				'tmp' . DS . 'xml' => 0,
				'tmp' . DS . 'files' => 0,
				'tmp' . DS . 'logs' => 0,
		);
		foreach ($writeableDirs as $path => &$error) {
			$dir = new Folder(APP . $path);
			if (is_null($dir->path)) $error = 1;
			$file = new File(APP . $path . DS . 'test.txt', true);
			if ($error == 0 && !$file->write('test')) $error = 2;
			if ($error != 0) $diagnostic_errors++;
			$file->delete();
			$file->close();
		}
		return $writeableDirs;
	}

	public function writeableFilesDiagnostics(&$diagnostic_errors) {
		$writeableFiles = array(
				'Config' . DS . 'config.php' => 0,
		);
		foreach ($writeableFiles as $path => &$error) {
			if (!file_exists(APP . $path)) {
				$error = 1;
				continue;
			}
			if (!is_writeable(APP . $path)) {
				$error = 2;
				$diagnostic_errors++;
			}
		}
		return $writeableFiles;
	}

	public function stixDiagnostics(&$diagnostic_errors, &$stixVersion, &$cyboxVersion) {
		$result = array();
		$expected = array('stix' => '1.1.1.4', 'cybox' => '2.1.0.12');
		// check if the STIX and Cybox libraries are working using the test script stixtest.py
		$scriptResult = shell_exec('python ' . APP . 'files' . DS . 'scripts' . DS . 'stixtest.py');
		$scriptResult = json_decode($scriptResult, true);
		if ($scriptResult !== null) {
			$scriptResult['operational'] = $scriptResult['success'];
			if ($scriptResult['operational'] == 0) {
				$diagnostic_errors++;
				return $scriptResult;
			}
		} else {
			return array('operational' => 0, 'stix' => array('expected' => $expected['stix']), 'cybox' => array('expected' => $expected['cybox']));
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
		App::uses('PubSubTool', 'Tools');
		$pubSubTool = new PubSubTool();
		if (!$pubSubTool->checkIfPythonLibInstalled()) {
			$diagnostic_errors++;
			return 2;
		}
		if ($pubSubTool->checkIfRunning()) return 0;
		$diagnostic_errors++;
		return 3;
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

	public function sessionDiagnostics(&$diagnostic_errors, &$sessionCount) {
		if (Configure::read('Session.defaults') !== 'database') {
			$sessionCount = 'N/A';
			return 2;
		}
		$sql = 'SELECT COUNT(id) FROM `cake_sessions` WHERE `expires` < ' . time() . ';';
		$sqlResult = $this->query($sql);
		if (isset($sqlResult[0][0])) $sessionCount = $sqlResult[0][0]['COUNT(id)'];
		else {
			$sessionCount = 'Error';
			return 3;
		}
		$sessionStatus = 0;
		if ($sessionCount > 100) {
			$sessionStatus = 1;
			$diagnostic_errors++;
		}
		return $sessionStatus;
	}

	public function workerDiagnostics(&$workerIssueCount) {
		$this->ResqueStatus = new ResqueStatus\ResqueStatus(Resque::redis());
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
		foreach ($worker_array as $k => &$queue) {
			if ($k != 'scheduler') $worker_array[$k]['jobCount'] = CakeResque::getQueueSize($k);
			if (!isset($queue['workers'])) {
				$workerIssueCount++;
				$queue['ok'] = false;
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
						'change' => 'Removind dead worker data. Worker was of type ' . $worker['queue'] . ' with pid ' . $pid
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
						'change' => 'Removind dead worker data. Worker was of type ' . $worker['queue'] . ' with pid ' . $pid
				));
			}
		}
	}

	// currently unused, but let's keep it in the code-base in case we need it in the future.
	private function __dropIndex($table, $field) {
		$this->Log = ClassRegistry::init('Log');
		$indexCheck = "SELECT INDEX_NAME FROM INFORMATION_SCHEMA.STATISTICS WHERE table_schema=DATABASE() AND table_name='" . $table . "' AND index_name LIKE '" . $field . "%'";
		$indexCheckResult = $this->query($indexCheck);
		foreach ($indexCheckResult as $icr) {
			$dropIndex = 'ALTER TABLE ' . $table . ' DROP INDEX ' . $icr['STATISTICS']['INDEX_NAME'];
			$result = true;
			try {
				$this->query($dropIndex);
			} catch (Exception $e) {
				$result = false;
			}
			$this->Log->create();
			$this->Log->save(array(
					'org' => 'SYSTEM',
					'model' => 'Server',
					'model_id' => 0,
					'email' => 'SYSTEM',
					'action' => 'update_database',
					'user_id' => 0,
					'title' => ($result ? 'Removed index ' : 'Failed to remove index ') . $icr['STATISTICS']['INDEX_NAME'] . ' from ' . $table,
					'change' => ($result ? 'Removed index ' : 'Failed to remove index ') . $icr['STATISTICS']['INDEX_NAME'] . ' from ' . $table,
			));
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
		$this->query('UPDATE `roles` SET `perm_template` = 1 WHERE `perm_site_admin` = 1 OR `perm_admin` = 1');
		$this->query('UPDATE `roles` SET `perm_sharing_group` = 1 WHERE `perm_site_admin` = 1 OR `perm_sync` = 1');
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
		foreach ($orgs as $k => &$orgArray) {
			foreach ($orgArray as &$org) {
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
		$this->query('UPDATE `correlations` SET `distribution` = 1, `a_distribution` = 1 WHERE `org` != "" AND `private` = 0');
		foreach ($orgMapping as $old => $new) {
			$this->query('UPDATE `correlations` SET `org_id` = "' . $new . '", `org` = "" WHERE `org` = "' . $old . '";');
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
			if (!empty($events)) foreach ($events as &$event) {
				if (!isset($event['Orgc'])) $event['Orgc']['name'] = $event['orgc'];
				if (!isset($event['Org'])) $event['Org']['name'] = $event['org'];
				if (!isset($event['EventTag'])) $event['EventTag'] = array();
				$event = array('Event' => $event);
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

	public function getEnrichmentModules() {
		if (!Configure::read('Plugin.Enrichment_services_enable')) return 'Enrichment service not enabled.';
		$url = Configure::read('Plugin.Enrichment_services_url') ? Configure::read('Plugin.Enrichment_services_url') : $this->serverSettings['Plugin']['Enrichment_services_url']['value'];
		$port = Configure::read('Plugin.Enrichment_services_port') ? Configure::read('Plugin.Enrichment_services_port') : $this->serverSettings['Plugin']['Enrichment_services_port']['value'];
		App::uses('HttpSocket', 'Network/Http');
		$httpSocket = new HttpSocket();
		try {
			$response = $httpSocket->get($url . ':' . $port . '/modules');
		} catch (Exception $e) {
			return 'Enrichment service not reachable.';
		}
		$modules = json_decode($response->body, true);
		if (!empty($modules)) {
			$result = array('modules' => $modules);
			foreach ($modules as &$module) {
				if ($module['type'] !== 'expansion') continue;
				foreach ($module['mispattributes']['input'] as $attribute) {
					$result['types'][$attribute][] = $module['name'];
				}
			}
			return $result;
		} else return 'The enrichment service reports that it found no enrichment modules.';
	}

	public function getEnabledModules() {
		$modules = $this->getEnrichmentModules();
		if (is_array($modules)) {
			foreach ($modules['modules'] as $k => &$module) {
				if (!Configure::read('Plugin.Enrichment_' . $module['name'] . '_enabled')) {
					unset($modules['modules'][$k]);
				}
			}
		}
		if (!isset($modules) || empty($modules)) $modules = array();
		if (isset($modules['modules']) && !empty($modules['modules'])) $modules['modules'] = array_values($modules['modules']);
		$types = array();
		$hover_types = array();
		if (!is_array($modules)) return array();
		foreach ($modules['modules'] as $temp) {
			foreach ($temp['mispattributes']['input'] as $input) {
				if (!isset($temp['meta']['module-type']) || in_array('expansion', $temp['meta']['module-type'])) $types[$input][] = $temp['name'];
				if (isset($temp['meta']['module-type']) && in_array('hover', $temp['meta']['module-type'])) $hover_types[$input][] = $temp['name'];
			}
		}
		$modules['types'] = $types;
		$modules['hover_type'] = $hover_types;
		return $modules;
	}
}
