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
}
