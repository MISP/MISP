<?php
App::uses('AppModel', 'Model');

class Collection extends AppModel
{

    public $recursive = -1;

    public $actsAs = array(
            'Containable'
    );

    public $belongsTo = [
        'Orgc' => array(
            'className' => 'Organisation',
            'foreignKey' => 'orgc_id',
            'fields' => [
                'Orgc.id',
                'Orgc.uuid',
                'Orgc.name'
            ]
        ),
        'Org' => array(
            'className' => 'Organisation',
            'foreignKey' => 'org_id',
            'fields' => [
                'Org.id',
                'Org.uuid',
                'Org.name'
            ]
        ),
        'User' => array(
            'className' => 'User',
            'foreignKey' => 'user_id',
            'fields' => [
                'User.id',
                'User.email'
            ]
        )
    ];

    public $hasMany = [
        'CollectionElement' => [
            'dependent' => true
        ]
    ];
 
    public $valid_targets = [
        'Attribute',
        'Event',
        'GalaxyCluster',
        'Galaxy',
        'Object',
        'Note',
        'Opinion',
        'Relationship',
        'Organisation',
        'SharingGroup'
    ];

    public $current_user = null;


    public function beforeValidate($options = array())
    {
        if (empty($this->data['Collection'])) {
            $this->data = ['Collection' => $this->data];
        }
        if (empty($this->id) && empty($this->data['Collection']['uuid'])) {
            $this->data['Collection']['uuid'] = CakeText::uuid();
        }
        if (empty($this->id)) {
            $this->data['Collection']['user_id'] = $this->current_user['id'];
            if (empty($this->data['Collection']['orgc_id']) || empty($this->current_user['Role']['perm_sync'])) {
                $this->data['Collection']['orgc_id'] = $this->current_user['Organisation']['id'];
            }
            $this->data['Collection']['org_id'] = $this->current_user['Organisation']['id'];
            $this->data['Collection']['user_id'] = $this->current_user['id'];
        }
        return true;
    }

    public function mayModify($user_id, $collection_id)
    {
        $user = $this->User->getAuthUser($user_id);
        $collection = $this->find('first', [
            'recursive' => -1,
            'conditions' => ['Collection.id' => $collection_id]
        ]);
        if ($user['Role']['perm_site_admin']) {
            return true;
        }
        if (empty($user['Role']['perm_modify'])) {
            return false;
        }
        if (!empty($user['Role']['perm_modify_org'])) {
            if ($user['org_id'] == $collection['Collection']['Orgc_id']) {
                return true;
            }
            if ($user['Role']['perm_sync'] && $user['org_id'] == $collection['Collection']['Org_id']) {
                return true;
            }            
        }
        if (!empty($user['Role']['perm_modify']) && $user['id'] === $collection['Collection']['user_id']) {
        }
    }

    public function mayView($user_id, $collection_id)
    {
        $user = $this->User->getAuthUser($user_id);
        $collection = $this->find('first', [
            'recursive' => -1,
            'conditions' => ['Collection.id' => $collection_id]
        ]);
        if ($user['Role']['perm_site_admin']) {
            return true;
        }
        if ($collection['Collection']['org_id'] == $user('org_id')) {
            return true;
        }
        if (in_array($collection['Collection']['distribution'], [1,2,3])) {
            return true;
        }
        if ($collection['Collection']['distribution'] === 4) {
            $SharingGroup = ClassRegistry::init('SharingGroup');
            $sgs = $this->SharingGroup->fetchAllAuthorised($user, 'uuid');
            if (isset($sgs[$collection['Collection']['sharing_group_id']])) {
                return true;
            } else {
                return false;
            }
        }
        return false;
    }

    public function rearrangeCollection(array $collection) {
        foreach ($collection as $key => $elements) {
            if ($key !== 'Collection') {
                $collection['Collection'][$key] = $elements;
                unset($collection[$key]);
            }
        }
        return $collection;
    }
}
