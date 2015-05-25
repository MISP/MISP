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

	public $orgField = 'org';	// TODO Audit, LogableBehaviour + org

	
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
		'org' => array(
			'notempty' => array(
				'rule' => array('notempty'),
				'message' => 'Please specify the organisation where you are working.',
				//'allowEmpty' => false,
				//'required' => false,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
		),
		'org_id' => array(
			'notempty' => array(
				'rule' => array('notempty'),
				'message' => 'Please specify the organisation ID where you are working.',
				//'allowEmpty' => false,
				//'required' => false,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
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
			'notempty' => array(
				'rule' => array('notempty'),
				//'message' => 'Your custom message here',
				//'allowEmpty' => false,
				//'required' => false,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
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
			'notempty' => array(
				'rule' => array('validateGpgkey'),
				'message' => 'GPG key not valid, please enter a valid key.',
				//'allowEmpty' => false,
				//'required' => false,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
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
		'Post' => array(
		)
	);

	public $actsAs = array(
		'SysLogLogable.SysLogLogable' => array(	// TODO Audit, logable
			'userModel' => 'User',
			'userKey' => 'user_id',
			'change' => 'full'
		),
		'Trim',
		'Containable'
		//'RemoveNewline' => array('fields' => array('gpgkey')),
	);

	public function beforeSave($options = array()) {
		if (isset($this->data[$this->alias]['password'])) {
			$this->data[$this->alias]['password'] = AuthComponent::password($this->data[$this->alias]['password']);
		}
		return true;

		// only accept add and edit in own org
		//if ($this->data[$this->alias]['org'] != "TEST") {
		//	return false;
		//}
		//return true;
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
			$gpg = new Crypt_GPG(array('homedir' => Configure::read('GnuPG.homedir')));
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
		$this->recursive = -1;
		$orgs = $this->find('all', array(
				'fields' => array('DISTINCT (User.org) AS org'),
		));
		$orgNames = array();
		foreach ($orgs as $org) {
			$orgNames[] = $org['User']['org'];
		}
		return $orgNames;
	}
	
	public function getOrgMemberCount($org) {
		return $this->find('count', array(
				'conditions' => array(
						'org =' => $org,
				)));
	}
	
	public function verifyGPG() {
		require_once 'Crypt/GPG.php';
		$this->Behaviors->detach('Trim');
		$results = array();
		$users = $this->find('all', array(
			'conditions' => array('not' => array('gpgkey' => '')),
			//'fields' => array('id', 'email', 'gpgkey'),
			'recursive' => -1,
		));
		foreach ($users as $k => $user) {
			$gpg = new Crypt_GPG(array('homedir' => Configure::read('GnuPG.homedir')));
			$key = $gpg->importKey($user['User']['gpgkey']);
			$gpg->addEncryptKey($key['fingerprint']); // use the key that was given in the import
			try {
				$enc = $gpg->encrypt('test', true);
			} catch (Exception $e){
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
	
	// all e-mail sending is now handled by this method
	// Just pass the user ID in an array that is the target of the e-mail along with the message body and the alternate message body if the message cannot be encrypted
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

		// Sign the body
		require_once 'Crypt/GPG.php';
		try {
			$gpg = new Crypt_GPG(array('homedir' => Configure::read('GnuPG.homedir')));	// , 'debug' => true
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
			debug($result['headers']);
			debug($result['message']);
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
					'title' => 'Email ' . $replyToLog  . ' to ' . $user['User']['email'] . ', titled "' . $subject . ' failed. Reason: ' . $failureReason,
					'change' => null,
			));
		}
		return false;
	}
}
