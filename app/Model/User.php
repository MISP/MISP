<?php
App::uses('AppModel', 'Model');
App::uses('AuthComponent', 'Controller/Component');

/**
 * User Model
 *
 * @property Role $Role
 * @property Event $Event
 */
class User extends AppModel {

/**
 * Display field
 *
 * @var string
 */
	public $displayField = 'email';
	
	public $orgField = array('Organisation', 'name');	// TODO Audit, LogableBehaviour + org

	
/**
 * Validation rules
 *
 * @var array
 */
	public $validate = array(
		'role_id' => array(
			'numeric' => array(
				'rule' => array('numeric'),
				//'message' => 'Your custom message here',
				//'allowEmpty' => false,
				//'required' => false,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
		),
		'password' => array(
			'minlength' => array(
				'rule' => array('passwordLength'),
				'message' => 'Password length requirement not met.',
				//'allowEmpty' => false,
				'required' => true,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
			'complexity' => array(
				'rule' => array('complexPassword'),
				'message' => 'Password complexity requirement not met.',
				//'allowEmpty' => false,
				//'required' => true,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
			'identical' => array(
				'rule' => array('identicalFieldValues', 'confirm_password'),
				'message' => 'Please re-enter your password twice so that the values match.',
				//'allowEmpty' => false,
				//'required' => true,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
		),

		'org_id' => array(
			'valueNotEmpty' => array(
				'rule' => array('valueNotEmpty'),
			),
			'numeric' => array(
					'rule' => array('numeric'),
					'message' => 'The organisation ID has to be a numeric value.',
			),
		),
		'email' => array(
			'email' => array(
				'rule' => array('email'),
				'message' => 'Please enter a valid email address.',
				//'allowEmpty' => false,
				'required' => true,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
			'unique' => array(
				'rule' => 'isUnique',
				'message' => 'An account with this email address already exists.'
			),
		),
		'autoalert' => array(
			'boolean' => array(
				'rule' => array('boolean'),
				//'message' => 'Your custom message here',
				'allowEmpty' => true,
				'required' => false,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
		),
		'contactalert' => array(
				'boolean' => array(
						'rule' => array('boolean'),
						//'message' => 'Your custom message here',
						'allowEmpty' => true,
						'required' => false,
						//'last' => false, // Stop validation after this rule
						//'on' => 'create', // Limit validation to 'create' or 'update' operations
				),
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
		'invited_by' => array(
			'numeric' => array(
				'rule' => array('numeric'),
				//'message' => 'Your custom message here',
				//'allowEmpty' => false,
				//'required' => false,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
		),
		'change_pw' => array(
			'numeric' => array(
				'rule' => array('numeric'),
				//'message' => 'Your custom message here',
				'allowEmpty' => true,
				'required' => false,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
		),
		'gpgkey' => array(
			'gpgvalidation' => array(
				'rule' => array('validateGpgkey'),
				'message' => 'GPG key not valid, please enter a valid key.',
			),
		),
		'nids_sid' => array(
			'numeric' => array(
				'rule' => array('numeric'),
				'message' => 'A SID should be an integer.',
				'allowEmpty' => false,
				'required' => true,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
		),
		'termsaccepted' => array(
			'boolean' => array(
				'rule' => array('boolean'),
				//'message' => 'Your custom message here',
				//'allowEmpty' => false,
				//'required' => false,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
		),
		'newsread' => array(
			'date' => array(
				'rule' => array('date'),
				//'message' => 'Your custom message here',
				//'allowEmpty' => false,
				//'required' => false,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
		),
	);

	//The Associations below have been created with all possible keys, those that are not needed can be removed

/**
 * belongsTo associations
 *
 * @var array
 */
	public $belongsTo = array(
		'Role' => array(
			'className' => 'Role',
			'foreignKey' => 'role_id',
			'conditions' => '',
			'fields' => '',
			'order' => ''
		),
		'Organisation' => array(
			'className' => 'Organisation',
			'foreignKey' => 'org_id',
			'conditions' => '',
			'fields' => '',
			'order' => ''
		),
		'Server' => array(
			'className' => 'Server',
			'foreignKey' => 'server_id',
			'conditions' => '',
			'fields' => '',
			'order' => ''
		)
	);

/**
 * hasMany associations
 *
 * @var array
 */
	public $hasMany = array(
		'Event' => array(
			'className' => 'Event',
			'foreignKey' => 'user_id',
			'dependent' => false,
			'conditions' => '',
			'fields' => '',
			'order' => '',
			'limit' => '',
			'offset' => '',
			'exclusive' => '',
			'finderQuery' => '',
			'counterQuery' => ''
		),
		'Post'
	);

	public $actsAs = array(
		'SysLogLogable.SysLogLogable' => array(	// TODO Audit, logable
			'userModel' => 'User',
			'userKey' => 'user_id',
			'change' => 'full'
		),
		'Trim',
		'Containable'
	);

	public function beforeSave($options = array()) {
		if (isset($this->data[$this->alias]['password'])) {
			$this->data[$this->alias]['password'] = AuthComponent::password($this->data[$this->alias]['password']);
		}
		return true;
	}

/**
 * Checks if the GPG key is a valid key
 * But also import it in the keychain.
 */
	// TODO: this will NOT fail on keys that can only be used for signing but not encryption!
	// the method in verifyUsers will fail in that case.
	public function validateGpgkey($check) {
		// LATER first remove the old gpgkey from the keychain

		// empty value
		if (empty($check['gpgkey'])) {
			return true;
		}

		// we have a clean, hopefull public, key here

		// key is entered
		require_once 'Crypt/GPG.php';
		try {
			$gpg = new Crypt_GPG(array('homedir' => Configure::read('GnuPG.homedir'), 'binary' => (Configure::read('GnuPG.binary') ? Configure::read('GnuPG.binary') : '/usr/bin/gpg')));
			try {
				$keyImportOutput = $gpg->importKey($check['gpgkey']);
				if (!empty($keyImportOutput['fingerprint'])) {
					return true;
				}
			} catch (Exception $e) {
				//debug($e);
				$this->log($e->getMessage());
				return false;
			}
		} catch (Exception $e) {
			//debug($e);
			$this->log($e->getMessage());
			return true; // TODO was false
		}
	}

	public function passwordLength($check) {
		$length = Configure::read('Security.password_policy_length');
		if (empty($length) || $length < 0) $length = 6;
		$value = array_values($check);
		$value = $value[0];
		if (strlen($value) < $length) return false;
		return true;
	}
	
	public function complexPassword($check) {
		/*
		default password:
		6 characters minimum
		1 or more upper-case letters
		1 or more lower-case letters
		1 or more digits or special characters
		example: "EasyPeasy34"
		If Security.password_policy_complexity is set and valid, use the regex provided.
		*/
		$regex = Configure::read('Security.password_policy_complexity');
		if (empty($regex) || @preg_match($regex, 'test') === false) $regex = '/((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/';
		$value = array_values($check);
		$value = $value[0];
		return preg_match($regex, $value);
	}

	public function identicalFieldValues($field=array(), $compareField=null) {
		foreach ($field as $key => $value) {
			$v1 = $value;
			$v2 = $this->data[$this->name][$compareField];
			if ($v1 !== $v2) {
				return false;
			} else {
				continue;
			}
		}
		return true;
	}

/**
 * Generates an authentication key for each user
 */
	public function generateAuthKey() {
		$length = 40;
		$characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
		$charLen = strlen($characters) - 1;
		$key = '';
		for ($p = 0; $p < $length; $p++) {
			$key .= $characters[rand(0, $charLen)];
		}
		return $key;
	}

	public function generateRandomPassword() {
	    $length = 12;
		$characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-+=!@#$%&*()<>/?';
		$charLen = strlen($characters) - 1;
		$key = '';
		for ($p = 0; $p < $length; $p++) {
			$key .= $characters[rand(0, $charLen)];
		}
		return $key;
	}


	public function checkAndCorrectPgps() {
		$fails = array();
		$users = $this->find('all', array('recursive' => 0));

		foreach ($users as $user) {
			if (strlen($user['User']['gpgkey']) && strpos($user['User']['gpgkey'], "\n")) {
				$fails[] = $user['User']['id'] . ':' . $user['User']['id'];
				//$check['gpgkey'] = trim(preg_replace('/\n', '', $check['gpgkey']));
			}
		}
		return $fails;
	}
	
	public function getOrgs() {
		$orgs = $this->Organisation->find('all', array(
			'recursive' => -1,
			'fields' => array('name'),
		));
		$orgNames = array();
		foreach ($orgs as $org) {
			$orgNames[] = $org['Organisation']['name'];
		}
		return $orgNames;
	}
	
	public function getOrgMemberCount($org) {
		return $this->find('count', array(
				'conditions' => array(
						'org =' => $org,
				)));
	}
	
	public function verifyGPG($id = false) {
		require_once 'Crypt/GPG.php';
		$this->Behaviors->detach('Trim');
		$results = array();
		$conditions = array('not' => array('gpgkey' => ''));
		if ($id !== false) $conditions['User.id'] = $id;
		$users = $this->find('all', array(
			'conditions' => $conditions,
			'recursive' => -1,
		));
		if (empty($users)) return results;
		$currentTimestamp = time();
		$gpg = new Crypt_GPG(array('homedir' => Configure::read('GnuPG.homedir'), 'binary' => (Configure::read('GnuPG.binary') ? Configure::read('GnuPG.binary') : '/usr/bin/gpg')));
		foreach ($users as $k => $user) {
			try {
				$temp = $gpg->importKey($user['User']['gpgkey']);
				$key = $gpg->getKeys($temp['fingerprint']);
				$subKeys = $key[0]->getSubKeys();
				$sortedKeys = array('valid' => 0, 'expired' => 0, 'noEncrypt' => 0);
				foreach ($subKeys as $subKey) {
					$issue = false;
					if ($currentTimestamp > $subKey->getExpirationDate()) {
						$sortedKeys['expired']++;
						continue;
					}
					if (!$subKey->canEncrypt()) {
						$sortedKeys['noEncrypt']++;
						continue;
					}
					$sortedKeys['valid']++;
				}
				if (!$sortedKeys['valid']) {
					$results[$user['User']['id']][2] = 'The user\'s PGP key does not include a valid subkey that could be used for encryption.';
					if ($sortedKeys['expired']) $results[$user['User']['id']][2] .= ' Found ' . $sortedKeys['expired'] . ' subkey(s) that have expired.';
					if ($sortedKeys['noEncrypt']) $results[$user['User']['id']][2] .= ' Found ' . $sortedKeys['noEncrypt'] . ' subkey(s) that are sign only.';
					$results[$user['User']['id']][0] = true;
				}
			} catch (Exception $e){
				$results[$user['User']['id']][2] = $e->getMessage();
				$results[$user['User']['id']][0] = true;
			}
			$results[$user['User']['id']][1] = $user['User']['email'];
		}
		return $results;
	}
	
	public function getPGP($id) {
		$result = $this->find('first', array(
			'recursive' => -1,
			'fields' => array('id', 'gpgkey'),
			'conditions' => array('id' => $id),
		));
		return $result['User']['gpgkey'];
	}
	
	// get the current user and rearrange it to be in the same format as in the auth component
	public function getAuthUser($id) {
		$user = $this->find('first', array('conditions' => array('OR' => array('User.id' => $id, 'User.authkey' => $id)), 'recursive' => -1,'contain' => array('Organisation', 'Role')));
		if (empty($user)) return $user;
		// Rearrange it a bit to match the Auth object created during the login
		$user['User']['Role'] = $user['Role'];
		$user['User']['Organisation'] = $user['Organisation'];
		unset($user['Organisation'], $user['Role']);
		return $user['User'];
	}
	
	// Fetch all users that have access to an event / discussion for e-mailing (or maybe something else in the future.
	// parameters are an array of org IDs that are owners (for an event this would be orgc and org) 
	public function getUsersWithAccess($owners = array(), $distribution, $sharing_group_id = 0, $userConditions = array()) {
		$sgModel = ClassRegistry::init('SharingGroup');
		$conditions = array();
		$validOrgs = array();
		$all = true;

		// add owners to the conditions
		if ($distribution == 0 || $distribution == 4) {
			$all = false;
			$validOrgs = $owners;
		}
		
		// add all orgs to the conditions that can see the SG
		if ($distribution = 4) {
			$sgOrgs = $sgModel->getOrgsWithAccess($sharing_group_id);
			if ($sgOrgs === true) $all = true;
			else $validOrgs = array_merge($validOrgs, $sgOrgs);
		}
		$validOrgs = array_unique($validOrgs);
		if (!$all) $conditions['AND']['OR'][] = array('org_id' => $validOrgs);
		$conditions['AND'][] = $userConditions;
		
		$roles = $this->Role->find('all', array(
			'conditions' => array('perm_site_admin' => 1),
			'fields' => array('id')
		));
		$roleIDs = array();
		foreach ($roles as $role) $roleIDs[] = $role['Role']['id'];
		
		$conditions['AND']['OR'][] = array('role_id' => $roleIDs); 
		$users = $this->find('all', array(
			'conditions' => $conditions,
			'recursive' => -1,
			'fields' => array('id', 'email', 'gpgkey', 'org_id'),
			'contain' => array('Role' => array('fields' => array('perm_site_admin'))),
		));
		foreach ($users as &$user) {
			$temp = $user['User'];
			unset($user['User']);
			$user = array_merge($temp, $user);
		}
		return $users;
	}

	// all e-mail sending is now handled by this method
	// Just pass the user ID in an array that is the target of the e-mail along with the message body and the alternate message body if the message cannot be encrypted
	// the remaining two parameters are the e-mail subject and a secondary user object which will be used as the replyto address if set. If it is set and an encryption key for the replyTo user exists, then his/her public key will also be attached
	public function sendEmail($user, $body, $bodyNoEnc = false, $subject, $replyToUser = false) {
		$failed = false;
		$failureReason = "";
		// check if the e-mail can be encrypted
		$canEncrypt = false;
		if (isset($user['User']['gpgkey']) && !empty($user['User']['gpgkey'])) $canEncrypt = true;
		
		// If bodyonlencrypted is enabled and the user has no encryption key, use the alternate body (if it exists)
		if (Configure::read('GnuPG.bodyonlyencrypted') && !$canEncrypt && $bodyNoEnc) {
			$body = $bodyNoEnc;
		}
		$body = str_replace('\n', PHP_EOL, $body);

		// Sign the body
		require_once 'Crypt/GPG.php';
		try {
			$gpg = new Crypt_GPG(array('homedir' => Configure::read('GnuPG.homedir'), 'binary' => (Configure::read('GnuPG.binary') ? Configure::read('GnuPG.binary') : '/usr/bin/gpg')));	// , 'debug' => true
			$gpg->addSignKey(Configure::read('GnuPG.email'), Configure::read('GnuPG.password'));
			$body = $gpg->sign($body, Crypt_GPG::SIGN_MODE_CLEAR);
		} catch (Exception $e) {
			$failureReason = " the message could not be signed. The following error message was returned by gpg: " . $e->getMessage();
			$this->log($e->getMessage());
			$failed = true;
		}
		
		// If we cannot encrypt the mail and the server settings restricts sending unencrypted messages, return false 
		if (!$failed && !$canEncrypt && Configure::read('GnuPG.onlyencrypted')) {
			$failed = true;
			$failureReason = " encrypted messages are enforced and the message could not be encrypted for this user as no valid encryption key was found.";
		}
		
		// Let's encrypt the message if we can
		if (!$failed && $canEncrypt) {
			$keyImportOutput = $gpg->importKey($user['User']['gpgkey']);
			try {
			$gpg->addEncryptKey($keyImportOutput['fingerprint']); // use the key that was given in the import
				$body = $gpg->encrypt($body, true);
			} catch (Exception $e){
				// despite the user having a PGP key and the signing already succeeding earlier, we get an exception. This must mean that there is an issue with the user's key.
				$failureReason = " the message could not be encrypted because there was an issue with the user's PGP key. The following error message was returned by gpg: " . $e->getMessage();
				$this->log($e->getMessage());
				$failed = true;
			}
		}
		$replyToLog = '';
		if (!$failed) {
			$Email = new CakeEmail();
			
			// If the e-mail is sent on behalf of a user, then we want the target user to be able to respond to the sender
			// For this reason we should also attach the public key of the sender along with the message (if applicable)
			if ($replyToUser != false) {
				$Email->replyTo($replyToUser['User']['email']);
				if (!empty($replyToUser['User']['gpgkey'])) $Email->attachments(array('gpgkey.asc' => array('data' => $replyToUser['User']['gpgkey'])));
				$replyToLog = 'from ' . $replyToUser['User']['email'];
			}
			$Email->from(Configure::read('MISP.email'));
			$Email->to($user['User']['email']);
			$Email->subject($subject);
			$Email->emailFormat('text');
			$result = $Email->send($body);
			$Email->reset();
		}
		$this->Log = ClassRegistry::init('Log');
		$this->Log->create();
		if (!$failed && $result) {
			$this->Log->save(array(
					'org' => 'SYSTEM',
					'model' => 'User',
					'model_id' => $user['User']['id'],
					'email' => $user['User']['email'],
					'action' => 'email',
					'title' => 'Email ' . $replyToLog  . ' to ' . $user['User']['email'] . ' sent, titled "' . $subject . '".',
					'change' => null,
			));
			return true;
		} else {
			if (isset($result) && !$result) $failureReason = " there was an error sending the e-mail.";
			$this->Log->save(array(
					'org' => 'SYSTEM',
					'model' => 'User',
					'model_id' => $user['User']['id'],
					'email' => $user['User']['email'],
					'action' => 'email',
					'title' => 'Email ' . $replyToLog  . ' to ' . $user['User']['email'] . ', titled "' . $subject . '" failed. Reason: ' . $failureReason,
					'change' => null,
			));
		}
		return false;
	}
	
	public function adminMessageResolve($message) {
		$resolveVars = array('$contact' => 'MISP.contact', '$org' => 'MISP.org', '$misp' => 'MISP.baseurl');
		foreach ($resolveVars as $k => $v) {
			$v = Configure::read($v);
			$message = str_replace($k, $v, $message);
		}
		return $message;
	}
	
	public function fetchPGPKey($email) {
		App::uses('SyncTool', 'Tools');
		$syncTool = new SyncTool();
		$HttpSocket = $syncTool->setupHttpSocket();
		$response = $HttpSocket->get('https://pgp.mit.edu/pks/lookup?search=' . $email . '&op=index&fingerprint=on');
		if ($response->code != 200) return $response->code;
		$string = str_replace(array("\r", "\n"), "", $response->body);
		$result = preg_match_all('/<pre>pub(.*?)<\/pre>/', $string, $matches);
		$results = $this->__extractPGPInfo($matches[1]);
		return $results;
	}
	
	private function __extractPGPInfo($lines) {
		$extractionRules = array(
			'key_id' => array('regex' => '/\">(.*?)<\/a>/', 'all' => false, 'alternate' => false),
			'date' => array('regex' => '/([0-9]{4}\-[0-9]{2}\-[0-9]{2})/', 'all' => false, 'alternate' => false),
			'fingerprint' => array('regex' => '/Fingerprint=(.*)$/m', 'all' => false, 'alternate' => false),
			'uri' => array('regex' => '/<a href=\"(.*?)\">/', 'all' => false, 'alternate' => false),
			'address' => array('regex' => '/<a href="\/pks\/lookup\?op=vindex[^>]*>([^\<]*)<\/a>(.*)Fingerprint/s', 'all' => true, 'alternate' => true),
		);
		$final = array();
		foreach ($lines as $line) {
			if (strpos($line, 'KEY REVOKED')) continue;
			$temp = array();
			foreach ($extractionRules as $ruleName => $rule) {
				if ($rule['all']) preg_match_all($rule['regex'], $line, ${$ruleName});
				else preg_match($rule['regex'], $line, ${$ruleName});
				if ($rule['alternate'] && isset(${$ruleName}[2]) && trim(${$ruleName}[2][0]) != '') $temp[$ruleName] = ${$ruleName}[2];
				else $temp[$ruleName] = ${$ruleName}[1];
				if ($rule['all']) $temp[$ruleName] = $temp[$ruleName][0];
				$temp[$ruleName] = html_entity_decode($temp[$ruleName]);
			}
			$temp['address'] = preg_replace('/\s{2,}/', PHP_EOL, trim($temp['address']));
			$final[] = $temp;
		}
		return $final;
	}
}
