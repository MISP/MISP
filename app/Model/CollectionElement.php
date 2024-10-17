<?php
App::uses('AppModel', 'Model');

class CollectionElement extends AppModel
{

    public $recursive = -1;

    public $actsAs = array(
            'Containable'
    );

    public $belongsTo = array(
        'Collection' => array(
            'className' => 'Collection',
            'foreignKey' => 'collection_id'
        )
    );

    // Make sure you also update the validation for element_type to include anything you add here.
    public $valid_types = [
        'Event',
        'GalaxyCluster'
    ];

    public $validate = [
        'collection_id' => [
            'numeric' => [
                'rule' => ['numeric']
            ]
        ],
        'uuid' => [
            'uuid' => [
                'rule' => 'uuid',
                'message' => 'Please provide a valid RFC 4122 UUID'
            ]
        ],
        'element_uuid' => [
            'element_uuid' => [
                'rule' => 'uuid',
                'message' => 'Please provide a valid RFC 4122 UUID'
            ]
        ],
        'element_type' => [
            'element_type' => [
                'rule' => ['inList', ['Event', 'GalaxyCluster']],
                'message' => 'Invalid object type.'
            ]
        ]
    ];


    public function beforeValidate($options = array())
    {
        // Massage to a common format
        if (empty($this->data['CollectionElement'])) {
            $this->data = ['CollectionElement' => $this->data];
        }

        // if we're creating a new element, assign a uuid (unless provided)
        if (empty($this->id) && empty($this->data['CollectionElement']['uuid'])) {
            $this->data['CollectionElement']['uuid'] = CakeText::uuid();
        }
        if (
            empty($this->id) &&
            empty($this->data['CollectionElement']['element_type']) &&
            !empty($this->data['CollectionElement']['element_uuid'])
        ) {
            $this->data['CollectionElement']['element_type'] = $this->deduceType($this->data['CollectionElement']['element_uuid']);
        }
        return true;
    }

    public function mayModify(int $user_id, int $collection_id)
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

    public function mayView(int $user_id, int $collection_id)
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

    public function deduceType(string $uuid)
    {
        foreach ($this->valid_types as $valid_type) {
            $this->{$valid_type} = ClassRegistry::init($valid_type);
            $result = $this->$valid_type->find('first', [
                'conditions' => [$valid_type.'.uuid' => $uuid],
                'recursive' => -1
            ]);
            if (!empty($result)) {
                return $valid_type;
            }
        }
        throw new NotFoundException(__('Invalid UUID'));
    }

    /*
     *  Pass a Collection as received from another instance to this function to capture the elements
     *  The received object is authoritative, so all elements that no longer exist in the upstream will be culled.
     */
    public function captureElements($data) {
        $temp = $this->find('all', [
            'recursive' => -1,
            'conditions' => ['CollectionElement.collection_id' => $data['Collection']['id']]
        ]);
        $oldElements = [];
        foreach ($temp as $oldElement) {
            $oldElements[$oldElement['CollectionElement']['uuid']] = $oldElement['CollectionElement'];
        }
        if (isset($data['Collection']['CollectionElement'])) {
            $elementsToSave = [];
            foreach ($data['Collection']['CollectionElement'] as $k => $element) {
                if (empty($element['uuid'])) {
                    $element['uuid'] = CakeText::uuid();
                }
                if (isset($oldElements[$element['uuid']])) {
                    if (isset($element['description'])) {
                        $oldElements[$element['uuid']]['description'] = $element['description'];
                    }
                    $elementsToSave[$k] = $oldElements[$element['uuid']];
                    unset($oldElements[$element['uuid']]);
                } else {
                    $elementsToSave[$k] = [
                        'CollectionElement' => [
                            'uuid' => $element['uuid'],
                            'element_uuid' => $element['element_uuid'],
                            'element_type' => $element['element_type'],
                            'description' => $element['description'],
                            'collection_id' => $data['Collection']['id']
                        ]
                    ];
                    
                }
            }
            foreach ($elementsToSave as $k => $element) {
                if (empty($element['CollectionElement']['id'])) {
                    $this->create();
                }
                try{
                    $this->save($element);
                } catch (PDOException $e) {
                    // duplicate value?
                }
            }
            foreach ($oldElements as $toDelete) {
                $this->delete($toDelete['id']);
            }
            $temp = $this->find('all', [
                'conditions' => ['CollectionElement.collection_id' => $data['Collection']['id']],
                'recursive' => -1
            ]);
            $data['Collection']['CollectionElement'] = [];
            foreach ($temp as $element) {
                $data['Collection']['CollectionElement'][] = $element['CollectionElement'];
            }
        }

        return $data;
    }
}
