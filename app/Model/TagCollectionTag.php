<?php

App::uses('AppModel', 'Model');

class TagCollectionTag extends AppModel
{
    public $useTable = 'tag_collection_tags';

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
