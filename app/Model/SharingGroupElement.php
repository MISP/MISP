<?php
App::uses('AppModel', 'Model');
class SharingGroupElement extends AppModel
{
    public $actsAs = array('Containable');

    public $belongsTo = array(
            'SharingGroup' => array(
                    'className' => 'SharingGroup',
                    'foreignKey' => 'sharing_group_id'
            ),
            'Organisation' => array(
                    'className' => 'Organisation',
                    'foreignKey' => 'org_id',
                    //'conditions' => array('SharingGroupElement.organisation_uuid' => 'Organisation.uuid')
            )
    );

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
    }
}
