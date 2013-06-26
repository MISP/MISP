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

	public $actsAs = array(
			'Trim',
			'SysLogLogable.SysLogLogable' => array(	// TODO Audit, logable
					'roleModel' => 'Role',
					'roleKey' => 'role_id',
					'change' => 'full'
			),
	);

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

	// regexp validation
	public function validateValue ($fields) {
		if (preg_match($fields['name'], 'test') === false) return false;
		return true;
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

	public function getBlockedValues() {
		$Whitelists = $this->find('all', array('fields' => array('name')));
		$toReturn = array();
		foreach ($Whitelists as $item) {
			$toReturn[] = $item['Whitelist']['name'];
		}
		return $toReturn;
	}

	public function removeWhitelistedFromArray($data, $isAttributeArray) {
		// Let's get all of the values that will be blocked by the whitelist
		$whitelists = $this->getBlockedValues();
		// if we don't have any whitelist items in the db, don't loop through each attribute
		if (!empty($whitelists)) {
			// if $isAttributeArray, we know that we have just an array of attributes
			if ($isAttributeArray) {
				// loop through each attribute and unset the ones that are whitelisted
				foreach ($data as $k => $attribute) {
					// loop through each whitelist item and run a preg match against the attribute value. If it matches, unset the attribute
					foreach ($whitelists as $wlitem) {
						if (preg_match($wlitem, $attribute['Attribute']['value'])) {
							unset($data[$k]);
						}
					}
				}
			} else {
			// if !$isAttributeArray, we know that we have an array of events that we need to parse through
				foreach ($data as $ke => $event) {
					// loop through each attribute and unset the ones that are whitelisted
					foreach ($event['Attribute'] as $k => $attribute) {
						// loop through each whitelist item and run a preg match against the attribute value. If it matches, unset the attribute
						foreach ($whitelists as $wlitem) {
							if (preg_match($wlitem, $attribute['value'])) {
								unset($data[$ke]['Attribute'][$k]);
							}
						}
					}
				}
			}
		}
		return $data;
	}
}
