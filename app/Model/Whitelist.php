<?php
App::uses('AppModel', 'Model');
/**
 * Whitelist Model
 *
 */
class Whitelist extends AppModel {

/**
 * Use table
 *
 * @var mixed False or table name
 */
	public $useTable = 'whitelist';

/**
 * Display field
 *
 * @var string
 */
	public $displayField = 'name';

	public $actsAs = array('Trim');

/**
 * Validation rules
 *
 * @var array
 */
	public $validate = array(
		'name' => array(
			'notempty' => array(
			'rule' => array('notempty'),
			'message' => 'Please fill in this field',
			//'allowEmpty' => false,
			//'required' => false,
			//'last' => false, // Stop validation after this rule
			//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
			'userdefined' => array(
				'rule' => array('validateValue'),
				'message' => 'Name not in the right format. Please double check the name.',
				//'allowEmpty' => false,
				//'required' => true,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
			'unique' => array(
					'rule' => 'isUnique', //array('valueIsUnique'),
					'message' => 'A similar name already exists.',
					//'allowEmpty' => false,
					//'required' => true,
					//'last' => false, // Stop validation after this rule
					//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
		),
	);

	public function validateValue ($fields) {
		$value = $fields['name'];

		// check data validation
		// host domainname maybe..
		if(preg_match("#^[A-Z0-9.-]+\.[A-Z]{2,4}$#i", $value))
		return true;

		// IP maybe..
		$parts = explode("/", $value);
		// [0] = the ip
		// [1] = the network address
		if (count($parts) <= 2 ) {
			// ipv4 and ipv6 matching
			if (filter_var($parts[0],FILTER_VALIDATE_IP)) {
				// ip is validated, now check if we have a valid network mask
				if (empty($parts[1]))
				return true;
				else if(is_numeric($parts[1]) && $parts[1] < 129)
				return true;
			}
		}
		return false;
	}

	public function valueIsUnique ($fields) {
		$value = $fields['name'];

		$whitelist = $this->find('all', array('recursive' => 0,'fields' => 'name'));
		foreach ($whitelist as $whitelistItem) {
			if ($value == $whitelistItem['Whitelist']['name']) {
				return false;
			}
		}

		return true;
	}

/**
 * get the Whitelist as an array
 *
 * @return array whitelistCheck names
 */
	public function populateWhitelist() {
		$whitelistCheck = array();

		$whitelist = $this->find('all', array('recursive' => 0,'fields' => 'name'));

		// loop through whitelist table,
		foreach ($whitelist as $whitelistItem) {
			$ipl = array();
			$ipl[] = $whitelistItem['Whitelist']['name'];
			$whitelistCheck = array_merge($whitelistCheck,$ipl);
			if (count($ipl) > 0 && $whitelistItem != $ipl[0]) {
				$dummyArray = array();
				$dummyArray[] = $whitelistItem['Whitelist']['name'];
				$whitelistCheck = array_merge($whitelistCheck,$dummyArray);
			}
		}
		return $whitelistCheck;
	}
}
