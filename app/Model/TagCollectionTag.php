<?php

App::uses('AppModel', 'Model');

/**
 * @property Tag $Tag
 */
class TagCollectionTag extends AppModel
{
    public $useTable = 'tag_collection_tags';

    public $actsAs = array(
        'AuditLog',
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
}
