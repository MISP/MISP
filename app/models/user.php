<?php
class User extends AppModel {
	var $name = 'User';
	var $validate = array(
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
			'notempty' => array(
				'rule' => array('notempty'),
				'message' => 'A password is required', // LATER password strength requirements
				//'allowEmpty' => false,
				'required' => true,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
//			'complex' => array(
//                'rule' => array('complexPassword'),
//                'message' => 'Password must be 8 characters minimum and contain at least one number and one uppercase character'
//            ),

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
				//'allowEmpty' => false,
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
		'gpgkey' => array(
            'rule' => array('validateGpgkey'),
            'message' => 'GPG key not valid, please enter a valid key'
         ),
         'nids_sid' => array (
         	'numeric' => array(
				'rule' => array('numeric'),
				'message' => 'A SID should be an integer.',
	            'allowEmpty' => false,
				'required' => true,
			),
		),
	);
	//The Associations below have been created with all possible keys, those that are not needed can be removed

	var $belongsTo = array(
		'Group' => array(
			'className' => 'Group',
			'foreignKey' => 'group_id',
			'conditions' => '',
			'fields' => '',
			'order' => ''
		)
	);

	var $hasMany = array(
		'Event' => array(
			'className' => 'Event',
			'foreignKey' => 'user_id',
			'dependent' => false,     // do not delete Events when user is deleted
			'conditions' => '',
			'fields' => '',
			'order' => '',
			'limit' => '',
			'offset' => '',
			'exclusive' => '',
			'finderQuery' => '',
			'counterQuery' => ''
		),
		'User' => array(
            'className' => 'User',
			'foreignKey' => 'invited_by',
			'dependent' => false,     // do not delete Users when user is deleted
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
	
	
	var $actsAs = array('Acl' => array('type' => 'requester'));
	
	public function beforeValidate() {
	    
	    // Fix issue with an empty password being automagically hashed
	    App::import('Core', 'Security'); // not sure whether this is necessary
	    if ($this->data['User']['password'] == Security::hash('', null, true)) {
	        $this->data['User']['password'] = '';
	    }
	    return true;
	}
	
	function parentNode() {
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
    
    function bindNode($user) {
        return array('model' => 'Group', 'foreign_key' => $user['User']['group_id']);
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
        $gpg = new Crypt_GPG();
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
        debug($check);
        /*
        8 characters minimum
        1 or more upper-case letters
        1 or more lower-case letters
        1 or more digits or special characters
        example: "EasyPeasy34"
        */
        
        $value = array_values($check);
        $value = $value[0];
        return preg_match('/(?=^.{8,}$)((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/', $value);
    
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
