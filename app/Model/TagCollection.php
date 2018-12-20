<?php

App::uses('AppModel', 'Model');

class TagCollection extends AppModel
{
    public $useTable = 'tag_collections';

    public $displayField = 'name';

    public $actsAs = array(
            'Trim',
            'SysLogLogable.SysLogLogable' => array(
                    'roleModel' => 'Role',
                    'roleKey' => 'role_id',
                    'change' => 'full'
            ),
            'Containable'
    );

    public $hasMany = array(
        'TagCollectionElement' => array(
            'dependent' => true
        )
    );

    public $whitelistedItems = false;

    public $validate = array(
        'name' => array(
            'valueNotEmpty' => array(
                'rule' => array('valueNotEmpty'),
            ),
            'unique' => array(
                    'rule' => 'isUnique',
                    'message' => 'A similar name already exists.',
            ),
        )
    );

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        // generate UUID if it doesn't exist
        if (empty($this->data['TagCollection']['uuid'])) {
            $this->data['TagCollection']['uuid'] = CakeText::uuid();
        }
        return true;
    }
}
