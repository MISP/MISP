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

    public const EDITABLE_FIELDS = [
        'relationship_type',
    ];

    public const SEARCHABLE_FIELDS = [
        'relationship_type',
    ];

    const ADDRESS_ENDS = [
        'object',
        'related_object',
    ];

    public $childValidate = [
        'related_object_uuid' => [
            'address' => [
                'rule' => 'validAddress',
            ],
            'notSelf' => [
                'rule' => 'notSelfReference',
                'message' => 'A relationship cannot point at itself.',
            ],
        ],
        'related_object_sha256' => [
            'address' => [
                'rule' => 'validAddress',
            ],
        ],
        'related_object_type' => [
            'validTarget' => [
                'rule' => ['inList', AnalystData::valid_targets],
                'message' => 'Invalid target type.',
                'allowEmpty' => false,
                'required' => true,
            ]
        ],
    ];

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
        if (!empty($this->data[$this->current_type]['related_object_uuid'])) {
            $this->data[$this->current_type]['related_object_uuid'] = trim($this->data[$this->current_type]['related_object_uuid']);
        }
        return true;
    }

    /**
     * @param array $check
     * @return bool
     */
    public function notSelfReference($check)
    {
        return !self::isSelfReference($this->data[$this->current_type]);
    }

    /**
     * @param array $relationship
     * @return bool True when both ends name the same uuid or the same SHA-256.
     */
    public static function isSelfReference(array $relationship)
    {
        foreach (['_uuid', '_sha256'] as $suffix) {
            $from = trim((string)($relationship['object' . $suffix] ?? ''));
            $to = trim((string)($relationship['related_object' . $suffix] ?? ''));
            if ($from !== '' && strcasecmp($from, $to) === 0) {
                return true;
            }
        }
        return false;
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
            $type = $v[$this->alias]['related_object_type'] ?? null;
            $address = $v[$this->alias][self::addressColumn($type, 'related_object')] ?? null;
            if (!empty($type) && !empty($address) && empty($results[$i][$this->alias]['related_object'])) {
                $results[$i][$this->alias]['related_object'] = $this->getRelatedElement($this->__currentUser, $type, $address);
            }
        }
        return $results;
    }

    /**
     * @param array $user
     * @param string $type
     * @param string $address A uuid, or a SHA-256 for the SHA256_TARGETS.
     * @return array Empty when the target is missing or not visible to $user.
     */
    public function getRelatedElement(array $user, $type, $address): array
    {
        $data = [];
        if ($type == 'AttributeValue') {
            $ids = $this->visibleValuesBySha256($user, [$address]);
            $values = empty($ids) ? [] : ClassRegistry::init('MispAttribute')->loadAttributeValue()->fetchValues($ids);
            // No id: value ids never leave the instance, and this rides in REST payloads
            if (!empty($values)) {
                $data = ['AttributeValue' => ['value' => current($values), 'sha256' => key($ids)]];
            }
        } else if ($type == 'Event') {
            $this->Event = ClassRegistry::init('Event');
            $params = [
            ];
            $backup = $this->Event->includeAnalystData;
            $this->Event->includeAnalystData = false;
            $data = $this->Event->fetchSimpleEvent($user, $address, $params);
            $data = $data ?? [];
            $this->Event->includeAnalystData = $backup;
        } else if ($type == 'Attribute') {
            $this->Attribute = ClassRegistry::init('MispAttribute');
            $params = [
                'conditions' => [
                    ['Attribute.uuid' => $address],
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
                    ['Object.uuid' => $address],
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

    /**
     * @param array $user
     * @param string $object_type
     * @param string $address A uuid, or a SHA-256 for the SHA256_TARGETS.
     * @return array
     */
    public function getInboundRelationships(array $user, $object_type, $address): array
    {
        if (in_array($object_type, self::SHA256_TARGETS, true)) {
            $address = strtolower((string)$address);
        }
        $conditions = [
            'related_object_type' => $object_type,
            self::addressColumn($object_type, 'related_object') => $address,
        ];
        $acl = $this->analystDataConditions($user);
        if (!empty($acl)) {
            $conditions['AND'][] = $acl;
        }
        $inboundRelations = $this->find('all', [
            'recursive' => -1,
            'conditions' => $conditions,
            'contain' => ['Org', 'Orgc', 'SharingGroup'],
        ]);

        foreach ($inboundRelations as $i => $relationship) {
            $relationship = $relationship['Relationship'];
            $from = $relationship[self::addressColumn($relationship['object_type'], 'object')] ?? null;
            $inboundRelations[$i]['Relationship']['related_object'] = $this->getRelatedElement($user, $relationship['object_type'], $from);
        }

        return $inboundRelations;
    }

    public function countRelationships(): array
    {
        $this->virtualFields['type_count'] = 'COUNT(Relationship.id)';
        $counts = $this->find('list', [
            'recursive' => -1,
            'fields' => ['Relationship.relationship_type', 'type_count'],
            'group' => ['Relationship.relationship_type'],
        ]);
        unset($this->virtualFields['reference_count']);
        return $counts;
    }
}
