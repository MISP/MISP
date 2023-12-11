<?php

App::uses('AppModel', 'Model');

class Allowedlist extends AppModel
{
    public $useTable = 'allowedlist';

    public $displayField = 'name';

    public $actsAs = array(
        'AuditLog',
            'Trim',
            'SysLogLogable.SysLogLogable' => array( // TODO Audit, logable
                    'roleModel' => 'Role',
                    'roleKey' => 'role_id',
                    'change' => 'full'
            ),
    );

    public $allowedlistedItems = false;

    public $validate = array(
        'name' => array(
            'valueNotEmpty' => array(
                'rule' => array('valueNotEmpty'),
            ),
            'userdefined' => array(
                'rule' => array('validateValue'),
                'message' => 'Name not in the right format. Allowedlist entries have to be enclosed by a valid php delimiter (which can be most non-alphanumeric / non-whitespace character). Format: "/8.8.8.8/" Please double check the name.',             //'allowEmpty' => false,
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

        $allowedlist = $this->find('all', array('recursive' => 0,'fields' => 'name'));
        foreach ($allowedlist as $allowedlistItem) {
            if ($value == $allowedlistItem['Allowedlist']['name']) {
                return false;
            }
        }

        return true;
    }

    public function getBlockedValues()
    {
        if ($this->allowedlistedItems === false) {
            $Allowedlists = $this->find('all', array('fields' => array('name')));
            $this->allowedlistedItems = array();
            foreach ($Allowedlists as $item) {
                $this->allowedlistedItems[] = $item['Allowedlist']['name'];
            }
        }
        return $this->allowedlistedItems;
    }

    public function removeAllowedlistedFromArray($data, $isAttributeArray)
    {
        // Let's get all of the values that will be blocked by the allowedlist
        $allowedlists = $this->getBlockedValues();
        // if we don't have any allowedlist items in the db, don't loop through each attribute
        if (!empty($allowedlists)) {
            // if $isAttributeArray, we know that we have just an array of attributes
            if ($isAttributeArray) {
                // loop through each attribute and unset the ones that are allowedlisted
                foreach ($data as $k => $attribute) {
                    // loop through each allowedlist item and run a preg match against the attribute value. If it matches, unset the attribute
                    foreach ($allowedlists as $wlitem) {
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
                        // loop through each attribute and unset the ones that are allowedlisted
                        foreach ($event['Attribute'] as $k => $attribute) {
                            // loop through each allowedlist item and run a preg match against the attribute value. If it matches, unset the attribute
                            foreach ($allowedlists as $wlitem) {
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

    // A simplified allowedlist removal, for when we just want to throw values against the list instead of attributes / events
    public function removeAllowedlistedValuesFromArray($data)
    {
        $allowedlists = $this->getBlockedValues();
        // if we don't have any allowedlist items in the db, don't loop through each attribute
        if (!empty($allowedlists)) {
            foreach ($data as $k => $value) {
                foreach ($allowedlists as $wlitem) {
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
