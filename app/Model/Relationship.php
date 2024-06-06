<?php
App::uses('AppModel', 'Model');
App::uses('AnalystData', 'Model');
class Relationship extends AnalystData
{

    public $recursive = -1;

    public $actsAs = array(
        'AuditLog',
        'Containable',
        'AnalystData',
    );

    public $current_type = 'Relationship';
    public $current_type_id = 2;

    protected $EDITABLE_FIELDS = [
        'relationship_type',
    ];

    public $validate = [];

    /** @var object|null */
    protected $Event;
    /** @var object|null */
    protected $Attribute;
    /** @var object|null */
    protected $Object;
    /** @var object|null */
    protected $Note;
    /** @var object|null */
    protected $Opinion;
    /** @var object|null */
    protected $Relationship;
    /** @var object|null */
    protected $User;
    /** @var array|null */
    private $__currentUser;

    public function beforeValidate($options = array())
    {
        parent::beforeValidate($options);
        // Prevent self-referencing relationships
        if ($this->data[$this->current_type]['object_uuid'] == $this->data[$this->current_type]['related_object_uuid']) {
            return false;
        }
        return true;

    }

    public function afterFind($results, $primary = false)
    {
        $results = parent::afterFind($results, $primary);
        if (empty($this->__currentUser)) {
            $user_id = Configure::read('CurrentUserId');
            $this->User = ClassRegistry::init('User');
            if ($user_id) {
                $this->__currentUser = $this->User->getAuthUser($user_id);
            }
        }
        foreach ($results as $i => $v) {
            if (!empty($v[$this->alias]['related_object_type']) && !empty($v[$this->alias]['related_object_uuid']) && empty($results[$i][$this->alias]['related_object'])) {
                $results[$i][$this->alias]['related_object'] = $this->getRelatedElement($this->__currentUser, $v[$this->alias]['related_object_type'], $v[$this->alias]['related_object_uuid']);
            }
        }
        return $results;
    }

    public function getRelatedElement(array $user, $type, $uuid): array
    {
        $data = [];
        if ($type == 'Event') {
            $this->Event = ClassRegistry::init('Event');
            $params = [
            ];
            $backup = $this->Event->includeAnalystData;
            $this->Event->includeAnalystData = false;
            $data = $this->Event->fetchSimpleEvent($user, $uuid, $params);
            $this->Event->includeAnalystData = $backup;
        } else if ($type == 'Attribute') {
            $this->Attribute = ClassRegistry::init('Attribute');
            $params = [
                'conditions' => [
                    ['Attribute.uuid' => $uuid],
                ],
                'contain' => ['Event' => 'Orgc', 'Object',]
            ];
            $backup = $this->Attribute->includeAnalystData;
            $this->Attribute->includeAnalystData = false;
            $data = $this->Attribute->fetchAttributeSimple($user, $params);
            $this->Attribute->includeAnalystData = $backup;
            $data = $this->rearrangeData($data, 'Attribute');
        } else if ($type == 'Object') {
            $this->Object = ClassRegistry::init('MispObject');
            $params = [
                'conditions' => [
                    ['Object.uuid' => $uuid],
                ],
                'contain' => ['Event' => 'Orgc',]
            ];
            $backup = $this->Object->includeAnalystData;
            $this->Object->includeAnalystData = false;
            $data = $this->Object->fetchObjectSimple($user, $params);
            $this->Object->includeAnalystData = $backup;
            if (!empty($data)) {
                $data = $data[0];
            }
            $data = $this->rearrangeData($data, 'Object');
        } else if ($type == 'Note') {
            $this->Note = ClassRegistry::init('Note');
            $params = [

            ];
            $backup = $this->Note->includeAnalystData;
            $this->Note->includeAnalystData = false;
            $data = $this->Note->fetchNote();
            $this->Note->includeAnalystData = $backup;
        } else if ($type == 'Opinion') {
            $this->Opinion = ClassRegistry::init('Opinion');
            $params = [

            ];
            $backup = $this->Opinion->includeAnalystData;
            $this->Opinion->includeAnalystData = false;
            $data = $this->Opinion->fetchOpinion();
            $this->Opinion->includeAnalystData = $backup;
        } else if ($type == 'Relationship') {
            $this->Relationship = ClassRegistry::init('Relationship');
            $params = [

            ];
            $backup = $this->Relationship->includeAnalystData;
            $this->Relationship->includeAnalystData = false;
            $data = $this->Relationship->fetchRelationship();
            $this->Relationship->includeAnalystData = $backup;
        }
        return $data;
    }

    private function rearrangeData(array $data, $objectType): array
    {
        $models = ['Event', 'Attribute', 'Object', 'Organisation', ];
        if (!empty($data) && !empty($data[$objectType])) {
            foreach ($models as $model) {
                if ($model == $objectType) {
                    continue;
                }
                if (isset($data[$model])) {
                    $data[$objectType][$model] = $data[$model];
                    unset($data[$model]);
                }
            }
            $data[$objectType]['Organisation'] = $data[$objectType]['Event']['Orgc'];
            $data[$objectType]['orgc_uuid'] = $data[$objectType]['Event']['Orgc']['uuid'];
            unset($data[$objectType]['Event']['Orgc']);
        }
        return $data;
    }

    public function getInboundRelationships(array $user, $object_type, $object_uuid): array
    {
        $conditions = [
            'related_object_type' => $object_type,
            'related_object_uuid' => $object_uuid,
        ];
        $type = 'Relationship';
        if (empty($user['Role']['perm_site_admin'])) {
            if ($this->__valid_sharing_groups === null) {
                $this->__valid_sharing_groups = $this->SharingGroup->authorizedIds($user, true);
            }
            $conditions['AND'][] = [
                'OR' => [
                    $type . '.orgc_uuid' => $user['Organisation']['uuid'],
                    $type . '.org_uuid' => $user['Organisation']['uuid'],
                    $type . '.distribution IN' => [1, 2, 3],
                    'AND' => [
                        $type . '.distribution' => 4,
                        $type . '.sharing_group_id IN' => $this->__valid_sharing_groups
                    ]
                ]
            ];
        }
        $inboundRelations = $this->find('all', [
            'recursive' => -1,
            'conditions' => $conditions,
            'contain' => ['Org', 'Orgc', 'SharingGroup'],
        ]);

        foreach ($inboundRelations as $i => $relationship) {
            $relationship = $relationship['Relationship'];
            $inboundRelations[$i]['Relationship']['related_object'] = $this->getRelatedElement($this->__currentUser, $relationship['object_type'], $relationship['object_uuid']);
        }

        return $inboundRelations;
    }
}
