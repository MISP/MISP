<?php

App::uses('AppModel', 'Model');

class TagCollectionElement extends AppModel
{
    public $useTable = 'tag_collection_elements';

    public $actsAs = array(
            'Trim',
            'SysLogLogable.SysLogLogable' => array(
                    'roleModel' => 'Role',
                    'roleKey' => 'role_id',
                    'change' => 'full'
            ),
            'Containable'
    );

    public $belongsTo = array(
        'TagCollection' => array(
            'className' => 'TagCollection',
        ),
        'Tag' => array(
            'className' => 'Tag',
        )
    );

    public $validate = array(

    );
}
