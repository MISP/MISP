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
				'rule' => array('minlength', 6),
				'message' => 'A password of a minimum length of 6 is required.',
				//'allowEmpty' => false,
				'required' => true,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
			'complexity' => array(
				'rule' => array('complexPassword'),
				'message' => 'The password must contain at least one upper-case, one lower-case, one (digits or special character).',
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

	public function complexPassword($check) {
		/*
		6 characters minimum
		1 or more upper-case letters
		1 or more lower-case letters
		1 or more digits or special characters
		example: "EasyPeasy34"
		*/
		$value = array_values($check);
		$value = $value[0];
		return preg_match('/((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/', $value);
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
		$gpg = new Crypt_GPG(array('homedir' => Configure::read('GnuPG.homedir')));
		$users = $this->find('all', array(
			'conditions' => array('not' => array('gpgkey' => '')),
			//'fields' => array('id', 'email', 'gpgkey'),
			'recursive' => -1,
		));
		foreach ($users as $k => $user) {
			$key = $gpg->importKey($user['User']['gpgkey']);
			$gpg->addEncryptKey($key['fingerprint']); // use the key that was given in the import
			try {
				$enc = $gpg->encrypt('test', true);
				$verified = $gpg->verify($enc);
			} catch (Exception $e){
				$results[$user['User']['id']][0] = true;
			}
			$results[$user['User']['id']][1] = $user['User']['email'];
		}
		return $results;
	}
}
