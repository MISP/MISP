<?php

App::uses('AppModel', 'Model');

class TagCollectionElement extends AppModel
{
    public $useTable = 'tag_collection_elements';

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
        
    );
}
