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
	), 'Trim');

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
			'notempty' => array(
				'rule' => array('notempty'),
				'message' => 'Please enter a valid authentication key.',
				//'allowEmpty' => false,
				//'required' => false,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
		),
		'org' => array(
			'notempty' => array(
				'rule' => array('notempty'),
				//'message' => 'Your custom message here',
				//'allowEmpty' => false,
				//'required' => false,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
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
					'footerpart1' => array(
							'level' => 2,
							'description' => 'Footer text prepending the version number.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testForEmpty',
							'type' => 'string',
					),
					'footerpart2' => array(
							'level' => 2,
							'description' => 'Footer text following the version number.',
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
					'sync' => array(
							'level' => 3,
							'description' => 'This setting is deprecated and can be safely removed.',
							'value' => '',
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
							'description' => 'This setting controls whether notification e-mails will be sent when an event is created via the REST interface. It might be a good idea to disable this setting when first setting up a link to another instance to avoid spamming your users during the initial pull.',
							'value' => '',
							'errorMessage' => '',
							'test' => 'testBool',
							'type' => 'boolean',
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
							'test' => 'testBool',
							'type' => 'boolean',
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
			),
			'GnuPG' => array(
					'branch' => 1,
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
							'description' => 'Password complexity requirement. Leave it empty for the default setting (3 out of 4, with either a digit or a special char) or enter your own regex. Keep in mind that the length is checked in another key. Example (simple 4 out of 4): /(?=.*[0-9])(?=.*[!@#$%^&*_-])(?=.*[A-Z])(?=.*[a-z]).*$/',
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
			'debug' => array(
					'level' => 0,
					'description' => 'The debug level of the instance, always use 0 for production instances.',
					'value' => '',
					'errorMessage' => '',
					'test' => 'testDebug',
					'type' => 'numeric',
					'options' => array(0 => 'Debug off', 1 => 'Debug on', 2 => 'Debug + SQL dump'),
			),
	);

	public function isOwnedByOrg($serverid, $org) {
		return $this->field('id', array('id' => $serverid, 'org' => $org)) === $serverid;
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
		if ("full" == $technique) {
			// get a list of the event_ids on the server
			$eventIds = $eventModel->getEventIdsFromServer($server);
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
			$eventCount = count($eventIds);
		} elseif ("incremental" == $technique) {
			// TODO incremental pull
			return array (3, null);
		
		} elseif (true == $technique) {
			$eventIds[] = intval($technique);
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
						// we have an Event array
						// The event came from a pull, so it should be locked.
						$event['Event']['locked'] = true;
						if (!isset($event['Event']['distribution'])) { // version 1
							$event['Event']['distribution'] = '1';
						}
						// Distribution
						switch($event['Event']['distribution']) {
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
		
						// correct $event if just one Attribute
						if (is_array($event['Event']['Attribute']) && isset($event['Event']['Attribute']['id'])) {
							$tmp = $event['Event']['Attribute'];
							unset($event['Event']['Attribute']);
							$event['Event']['Attribute'][0] = $tmp;
						}
						if (is_array($event['Event']['Attribute'])) {
							$size = is_array($event['Event']['Attribute']) ? count($event['Event']['Attribute']) : 0;
							for ($i = 0; $i < $size; $i++) {
								if (!isset($event['Event']['Attribute'][$i]['distribution'])) { // version 1
									$event['Event']['Attribute'][$i]['distribution'] = 1;
								}
								switch($event['Event']['Attribute'][$i]['distribution']) {
									case 1:
									case 'This community only': // backwards compatibility
										// if community falseonly, downgrade to org only after pull
										$event['Event']['Attribute'][$i]['distribution'] = '0';
										break;
									case 2:
									case 'Connected communities': // backwards compatibility
										// if connected communities downgrade to community only
										$event['Event']['Attribute'][$i]['distribution'] = '1';
										break;
									case 'All communities': // backwards compatibility
										$event['Event']['Attribute'][$i]['distribution'] = '3';
										break;
									case 'Your organisation only': // backwards compatibility
										$event['Event']['Attribute'][$i]['distribution'] = '0';
										break;
								}
							}
							$event['Event']['Attribute'] = array_values($event['Event']['Attribute']);
						} else {
							unset($event['Event']['Attribute']);
						}
						// Distribution, set reporter of the event, being the admin that initiated the pull
						$event['Event']['user_id'] = $user['id'];
						// check if the event already exist (using the uuid)
						$existingEvent = null;
						$existingEvent = $eventModel->find('first', array('conditions' => array('Event.uuid' => $event['Event']['uuid'])));
						if (!$existingEvent) {
							// add data for newly imported events
							$passAlong = $server['Server']['url'];
							$result = $eventModel->_add($event, $fromXml = true, $user, $server['Server']['org'], $passAlong, true, $jobId);
							if ($result) $successes[] = $eventId;
							else {
								$fails[$eventId] = 'Failed (partially?) because of validation errors: '. print_r($eventModel->validationErrors, true);
							}
						} else {
							$result = $eventModel->_edit($event, $existingEvent['Event']['id'], $jobId);
							if ($result === 'success') $successes[] = $eventId;
							else $fails[$eventId] = $result;
						}
					} else {
						// error
						$fails[$eventId] = 'failed downloading the event';
					}
					if ($jobId) {
						$job->id = $jobId;
						$job->saveField('progress', 100 * (($k + 1) / $eventCount));
					}
				}
				if (count($fails) > 0) {
					// there are fails, take the lowest fail
					$lastpulledid = min(array_keys($fails));
				} else {
					// no fails, take the highest success
					$lastpulledid = count($successes) > 0 ? max($successes) : 0;
				}
				// increment lastid based on the highest ID seen
				$this->save($event, array('fieldList' => array('lastpulledid', 'url')));
				// grab all of the shadow attributes that are relevant to us
			}
		}
		$events = $eventModel->find('all', array(
				'fields' => array('id', 'uuid'),
				'recursive' => -1,
		));
		$shadowAttribute = ClassRegistry::init('ShadowAttribute');
		$shadowAttribute->recursive = -1;
		foreach ($events as &$event) {
			$proposals = $eventModel->downloadEventFromServer($event['Event']['uuid'], $server, null, true);
			if (null != $proposals) {
				if (isset($proposals['ShadowAttribute']['id'])) {
					$temp = $proposals['ShadowAttribute'];
					$proposals['ShadowAttribute'] = array(0 => $temp);
				}
				foreach($proposals['ShadowAttribute'] as &$proposal) {
					unset($proposal['id']);
					$oldsa = $shadowAttribute->findOldProposal($proposal);
					$proposal['event_id'] = $event['Event']['id'];
					if (!$oldsa || $oldsa['timestamp'] < $proposal['timestamp']) {
						if ($oldsa) $shadowAttribute->delete($oldsa['id']);
						if (!isset($pulledProposals[$event['Event']['id']])) $pulledProposals[$event['Event']['id']] = 0;
						$pulledProposals[$event['Event']['id']]++;
						if (isset($proposal['old_id'])) {
							$oldAttribute = $eventModel->Attribute->find('first', array('recursive' => -1, 'conditions' => array('uuid' => $proposal['uuid'])));
							if ($oldAttribute) $proposal['old_id'] = $oldAttribute['Attribute']['id'];
							else $proposal['old_id'] = 0;
						}
						$shadowAttribute->create();
						$shadowAttribute->save($proposal);
					}
				}
			}
		}
		$this->Log = ClassRegistry::init('Log');
		$this->Log->create();
		$this->Log->save(array(
			'org' => $user['org'],
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
	
	public function push($id = null, $technique=false, $jobId = false, $HttpSocket, $email = "Scheduled job") {
		if ($jobId) {
			$job = ClassRegistry::init('Job');
			$job->read(null, $jobId);
		}
		$eventModel = ClassRegistry::init('Event');
		$this->read(null, $id);
		$url = $this->data['Server']['url'];
		if ("full" == $technique) {
			$eventid_conditions_key = 'Event.id >';
			$eventid_conditions_value = 0;
		} elseif ("incremental" == $technique) {
			$eventid_conditions_key = 'Event.id >';
			$eventid_conditions_value = $this->data['Server']['lastpushedid'];
		} elseif (true == $technique) {
			$eventIds[] = array('Event' => array ('id' => intval($technique)));
		} else {
			$this->redirect(array('action' => 'index'));
		}
		if (!isset($eventIds)) {
			$findParams = array(
					'conditions' => array(
							$eventid_conditions_key => $eventid_conditions_value,
							'Event.distribution >' => 0,
							'Event.published' => 1,
							'Event.attribute_count >' => 0
					), //array of conditions
					'recursive' => -1, //int
					'fields' => array('Event.id', 'Event.timestamp', 'Event.uuid'), //array of field names
			);
			$eventIds = $eventModel->find('all', $findParams);
		}
		$eventUUIDsFiltered = $this->filterEventIdsForPush($id, $HttpSocket, $eventIds);
		if ($eventUUIDsFiltered === false) $pushFailed = true;
		if (!empty($eventUUIDsFiltered)) {
			
			$eventCount = count($eventUUIDsFiltered);
			//debug($eventIds);
			// now process the $eventIds to pull each of the events sequentially
			if (!empty($eventUUIDsFiltered)) {
				$successes = array();
				$fails = array();
				$lowestfailedid = null;
				foreach ($eventUUIDsFiltered as $k => $eventUuid) {
					$eventModel->recursive=1;
					$eventModel->contain(array('Attribute'));
					$event = $eventModel->findByUuid($eventUuid);
					$event['Event']['locked'] = true;
					$result = $eventModel->uploadEventToServer(
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
		
		$this->syncProposals($HttpSocket, $this->data, null, null, $eventModel);
		
		if (!isset($successes)) $successes = null;
		if (!isset($fails)) $fails = null;
		$this->Log = ClassRegistry::init('Log');
		$this->Log->create();
		$this->Log->save(array(
				'model' => 'Server',
				'model_id' => $id,
				'email' => $email,
				'action' => 'push',
				'title' => 'Push to ' . $url . ' initiated by ' . $email,
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
	
	public function filterEventIdsForPush($id, $HttpSocket, $eventIds) {
		foreach ($eventIds as $k => $event) {
			unset($eventIds[$k]['Event']['id']);
		}
		$server = $this->read(null, $id);
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
	
	public function syncProposals($HttpSocket, $server, $sa_id = null, $event_id = null, $eventModel){
		$saModel = ClassRegistry::init('ShadowAttribute');
		if (null == $HttpSocket) {
			App::uses('SyncTool', 'Tools');
			$syncTool = new SyncTool();
			$HttpSocket = $syncTool->setupHttpSocket($server);
		}
		if ($sa_id == null) {
			if ($event_id == null) {
				// event_id is null when we are doing a push
				$ids = $eventModel->getEventIdsFromServer($server, true, $HttpSocket);
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
			$unchanged = array();
			foreach ($events as $k => &$event) {
				if (!empty($event['ShadowAttribute'])) {
					foreach ($event['ShadowAttribute'] as &$sa) {
						$sa['data'] = $saModel->base64EncodeAttachment($sa);
						unset($sa['id']);
						unset($sa['category_order']);
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
						$result = json_decode($response->body());
						if ($result->success) {
							$success += intval($result->counter);
						} else {
							$fails++;
							if ($error_message == "") $result->message;
							else $error_message += " --- " . $result->message; 
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
			$response = $HttpSocket->get($uri);
			if ($response->code == '200') {
				$uuidList = json_decode($response->body());
			} else {
				return false;
			}
		}
	}
	
	public function serverSettingsRead($unsorted = false) {
		$serverSettings = $this->serverSettings;
		$results = array();
		$currentSettings = Configure::read();
		$finalSettingsUnsorted = array();
		foreach ($serverSettings as $branchKey => &$branchValue) {
			if (isset($branchValue['branch'])) {
				foreach ($branchValue as $leafKey => &$leafValue) {
					if ($leafValue['level'] == 3 && !(isset($currentSettings[$branchKey][$leafKey]))) continue;
					$setting = null;
					if (isset($currentSettings[$branchKey][$leafKey])) $setting = $currentSettings[$branchKey][$leafKey];
					$leafValue = $this->__evaluateLeaf($leafValue, $leafKey, $setting);
					if ($leafKey != 'branch') {
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
	
	private function __evaluateLeaf($leafValue, $leafKey, $setting) {
		if (isset($setting)) {
			$result = $this->{$leafValue['test']}($setting);
			if ($result !== true) {
				$leafValue['error'] = 1;
				if ($result !== false) $leafValue['errorMessage'] = $result;
			}
			if ($setting !== '') $leafValue['value'] = $setting;
		} else {
			if ($leafKey != 'branch') {
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
	
	public function testDebug($value) {
		if ($this->testForEmpty($value) !== true) return $this->testForEmpty($value);
		if ($this->testForNumeric($value) !== true) return 'This setting has to be a number between 0 and 2, with 0 disabling debug mode.';
		if ($value === 0) return true;
		return 'This setting has to be set to 0 on production systems. Ignore this warning if this is not the case.';
	}
	public function testBaseURL($value) {
		if ($this->testForEmpty($value) !== true) return $this->testForEmpty($value);
		$protocol = ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || $_SERVER['SERVER_PORT'] == 443) === true ? 'HTTPS' : 'HTTP';
		if ($value != strtolower($protocol) . '://' . $_SERVER['HTTP_HOST']) return false;
		return true;
	}
	
	public function testBool($value) {
		if ($this->testForEmpty($value) !== true) return $this->testForEmpty($value);
		if ($value !== true && $value !== false) return 'Value is not a boolean, make sure that you convert \'true\' to true for example.';
		return true;
	}
	
	public function testSalt($value) {
		if ($this->testForEmpty($value) !== true) return $this->testForEmpty($value);
		if (strlen($value) != 32) return 'The salt has to be a 32 byte long string.';
		if ($value == "Rooraenietu8Eeyo<Qu2eeNfterd-dd+") return 'This is the default salt shipped with the application and is therefore unsecure.';
		return true;
	}
	
	public function testForTermsFile($value) {
		return $this->__testForFile($value, APP . 'files' . DS . 'terms');
	}
	
	public function testForCustomImage($value) {
		return $this->__testForFile($value, APP . 'webroot' . DS . 'img' . DS . 'custom');
	}
	
	public function testPasswordLength($value) {
		$numeric = $this->testforNumeric($value);
		if ($numeric !== true) return $numeric;
		if ($numeric < 0) return 'Length cannot be negative, set a positive integer or 0 (to choose the default option).';
		return true;
	}
	
	public function testPasswordRegex($value) {
		if (!empty($value) && @preg_match($value, 'test') === false) return 'Invalid regex.';
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
		Configure::dump('config.php', 'default', array('MISP', 'GnuPG', 'Proxy', 'SecureAuth', 'Security', 'debug'));
	}
	
	public function checkVersion($newest) {
		App::uses('Folder', 'Utility');
		$file = new File (ROOT . DS . 'VERSION.json', true);
		$version_array = json_decode($file->read());
		$file->close();
		$current = 'v' . $version_array->major . '.' . $version_array->minor . '.' . $version_array->hotfix;
		$newest_array = $this->__dissectVersion($newest);
		$upToDate = $this->__compareVersions(array($version_array->major, $version_array->minor, $version_array->hotfix), $newest_array, 0); 
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
						'regex' => '.*\.(png|PNG)',
						'regex_error' => 'Filename must be in the following format: *.png',
						'files' => array(),
				),
				'terms' => array(
						'name' => 'Terms of Use file',
						'description' => 'Terms of use file viewable / downloadable by users. Make sure that it is either in text / html format if served inline.',
						'expected' => array('MISP.terms_file' => Configure::read('MISP.terms_file')),
						'valid_format' => 'text/html if served inline, anything that conveys the terms of use if served as download',
						'path' => APP . 'files' . DS . 'terms',
						'regex' => '^(?!empty).*$',
						'regex_error' => 'Filename can be any string consisting of characters between a-z, A-Z, 0-9 or one of the following: "_" or "-". The filename can also have an extension.',
						'files' => array(),
				),
				'img' => array(
						'name' => 'Additional image files',
						'description' => 'Image files uploaded into this directory can be used for various purposes, such as for the login page logos',
						'expected' => array(
								'MISP.footer_logo' => Configure::read('MISP.footer_logo'), 
								'MISP.welcome_logo' => Configure::read('MISP.welcome_logo'),
								'MISP.welcome_logo2' => Configure::read('MISP.welcome_logo2'),
						),
						'valid_format' => 'text/html if served inline, anything that conveys the terms of use if served as download',
						'path' => APP . 'webroot' . DS . 'img' . DS . 'custom',
						'regex' => '.*\.(png|PNG)',
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
		$result = array();
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
}
