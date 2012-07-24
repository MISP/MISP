<?php
App::uses('AppModel', 'Model');
App::uses('AuthComponent', 'Controller/Component');

/**
 * User Model
 *
 * @property Group $Group
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
 * Model Name
 *
 * @var string
 */
	var $name = 'User';			// TODO general
/**
 * Validation rules
 *
 * @var array
 */
	public $validate = array(
		'group_id' => array(
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
				'message' => 'Please specify the organisation ID where you are working.',	// TODO ACL, org_id in Users
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
		'authkey' => array(
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
		'Group' => array(
			'className' => 'Group',
			'foreignKey' => 'group_id',
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
		)
	);

	// TODO ACL: 1: be requester to CakePHP ACL system
	public $actsAs = array('Acl' => array('type' => 'requester', 'enabled' => false));	// TODO ACL, + 'enabled' => false
    
	// TODO ACL: 2: hook User into CakePHP ACL system (so link to aros)
	public function parentNode() {
        if (!$this->id && empty($this->data)) {
            return null;
        }
        if (isset($this->data['User']['group_id'])) {
            $groupId = $this->data['User']['group_id'];
        } else {
            $groupId = $this->field('group_id');
        }
        if (!$groupId) {
            return null;
        } else {
            return array('Group' => array('id' => $groupId));
        }
    }

    // TODO ACL: 3: rights on Groups: http://stackoverflow.com/questions/6154285/aros-table-in-cakephp-is-still-including-users-even-after-bindnode
	function bindNode($user) {
    	// return array('model' => 'Group', 'foreign_key' => $user['User']['group_id']);
		return array('Group' => array('id' => $user['User']['group_id']));
	}
	
	public function beforeSave() {
	    if (isset($this->data[$this->alias]['password'])) {
	        $this->data[$this->alias]['password'] = AuthComponent::password($this->data[$this->alias]['password']);
	    }
	    return true;
	}


	/**
	* Checks if the GPG key is a valid key
	* But also import it in the keychain.
	*/
	function validateGpgkey($check) {
	    // LATER first remove the old gpgkey from the keychain

	    // empty value
	    if (empty($check['gpgkey']))
	    return true;

	    // key is entered
	    require_once 'Crypt/GPG.php';
	    $gpg = new Crypt_GPG(array('homedir' => Configure::read('GnuPG.homedir')));
	    try {
	        $key_import_output = $gpg->importKey($check['gpgkey']);
	        if (!empty($key_import_output['fingerprint'])) {
	            return true;
	        }
	    } catch (Exception $e) {
	        debug($e);
	        return false;
	    }
	}


	function complexPassword($check) {
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

	function identicalFieldValues( $field=array(), $compare_field=null )
	{
	    foreach( $field as $key => $value ){
	        $v1 = $value;
	        $v2 = $this->data[$this->name][ $compare_field ];
	        if($v1 !== $v2) {
	            return FALSE;
	        } else {
	            continue;
	        }
	    }
	    return TRUE;
	}

	/**
	 * Generates an authentication key for each user
	 */
	function generateAuthKey() {
	    //$key = sha1(mt_rand(30, 30).time());
	    $length = 40;
	    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
	    $char_len = strlen($characters)-1;
	    $key = '';
	    for ($p = 0; $p < $length; $p++) {
	        $key .= $characters[rand(0, $char_len)];
	    }

	    return $key;
	}



}
