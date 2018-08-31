<?php

App::uses('AppModel', 'Model');

class Whitelist extends AppModel
{
    public $useTable = 'whitelist';

    public $displayField = 'name';

    public $actsAs = array(
            'Trim',
            'SysLogLogable.SysLogLogable' => array(	// TODO Audit, logable
                    'roleModel' => 'Role',
                    'roleKey' => 'role_id',
                    'change' => 'full'
            ),
    );

	public $whitelistedItems = false;

    public $validate = array(
        'name' => array(
            'valueNotEmpty' => array(
                'rule' => array('valueNotEmpty'),
            ),
            'userdefined' => array(
                'rule' => array('validateValue'),
                'message' => 'Name not in the right format. Whitelist entries have to be enclosed by a valid php delimiter (which can be most non-alphanumeric / non-whitespace character). Format: "/8.8.8.8/" Please double check the name.',				//'allowEmpty' => false,
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
    public function validateValue($fields)
    {
        if (preg_match($fields['name'], 'test') === false) {
            return false;
        }
        return true;
    }

    public function valueIsUnique($fields)
    {
        $value = $fields['name'];

        $whitelist = $this->find('all', array('recursive' => 0,'fields' => 'name'));
        foreach ($whitelist as $whitelistItem) {
            if ($value == $whitelistItem['Whitelist']['name']) {
                return false;
            }
        }

        return true;
    }

    public function getBlockedValues()
    {
		if ($this->whitelistedItems !== false) {
	        $Whitelists = $this->find('all', array('fields' => array('name')));
	        $this->whitelistedItems = array();
	        foreach ($Whitelists as $item) {
	            $this->whitelistedItems[] = $item['Whitelist']['name'];
	        }
		}
        return $this->whitelistedItems;
    }

    public function removeWhitelistedFromArray($data, $isAttributeArray)
    {
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
                $data = array_values($data);
            } else {
                // if !$isAttributeArray, we know that we have an array of events that we need to parse through
                foreach ($data as $ke => $event) {
                    if (isset($event['Attribute'])) {
                        // loop through each attribute and unset the ones that are whitelisted
                        foreach ($event['Attribute'] as $k => $attribute) {
                            // loop through each whitelist item and run a preg match against the attribute value. If it matches, unset the attribute
                            foreach ($whitelists as $wlitem) {
                                if (preg_match($wlitem, $attribute['value'])) {
                                    unset($data[$ke]['Attribute'][$k]);
                                }
                            }
                        }
                        $data[$ke]['Attribute'] = array_values($data[$ke]['Attribute']);
                    }
                }
            }
        }
        return $data;
    }

    // A simplified whitelist removal, for when we just want to throw values against the list instead of attributes / events
    public function removeWhitelistedValuesFromArray($data)
    {
        $whitelists = $this->getBlockedValues();
        // if we don't have any whitelist items in the db, don't loop through each attribute
        if (!empty($whitelists)) {
            foreach ($data as $k => $value) {
                foreach ($whitelists as $wlitem) {
                    if (preg_match($wlitem, $value)) {
                        unset($data[$k]);
                    }
                }
            }
            $data = array_values($data);
        }
        return $data;
    }
}
