<?php
App::uses('AppModel', 'Model');
App::uses('AnalystData', 'Model');

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

    public $valid_types = [
        'Event',
        'GalaxyCluster',
        'Attribute',
        'Object',
        'AttributeValue',
    ];

    /**
     * Model behind each pointer type, for those whose class name differs.
     */
    private $typeModels = [
        'Attribute' => 'MispAttribute',
        'Object' => 'MispObject',
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
            'address' => [
                'rule' => 'validAddress',
            ]
        ],
        'element_sha256' => [
            'address' => [
                'rule' => 'validAddress',
            ]
        ],
        'element_type' => [
            'element_type' => [
                'rule' => ['validElementType'],
                'message' => 'Invalid object type.'
            ]
        ]
    ];

    public function validElementType($check)
    {
        return in_array(reset($check), $this->valid_types, true);
    }

    /**
     * When true, element saves/deletes do NOT bump the parent Collection's
     * `modified`. Set during sync capture, where the parent's `modified` is
     * set authoritatively from the remote by Collection::captureCollection().
     * @var bool
     */
    public $skipCollectionModifiedBump = false;

    /** @var int|null parent collection_id stashed in beforeDelete for afterDelete */
    private $deletedElementCollectionId = null;


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
        $this->data['CollectionElement'] = AnalystData::normaliseAddress($this->data['CollectionElement'], 'element', empty($this->id));
        if (
            empty($this->id) &&
            empty($this->data['CollectionElement']['element_type']) &&
            !empty($this->data['CollectionElement']['element_uuid'])
        ) {
            $this->data['CollectionElement']['element_type'] = $this->deduceType($this->data['CollectionElement']['element_uuid']);
        }
        return true;
    }

    /**
     * The element addresses of one type that $user may read.
     *
     * @param array $user
     * @param string $type
     * @param array $uuids uuids, or SHA-256s for AnalystData::SHA256_TARGETS
     * @return array SHA-256s in lower case
     */
    public function readableUuids(array $user, $type, array $uuids)
    {
        $uuids = array_values(array_unique($uuids));
        if (empty($uuids)) {
            return [];
        }
        switch ($type) {
            case 'AttributeValue':
                return array_keys(ClassRegistry::init('AnalystData')->visibleValuesBySha256($user, $uuids));
            case 'Event':
                $rows = ClassRegistry::init('Event')->fetchSimpleEvents($user, [
                    'conditions' => ['Event.uuid' => $uuids]
                ]);
                return Hash::extract($rows, '{n}.Event.uuid');
            case 'GalaxyCluster':
                $rows = ClassRegistry::init('GalaxyCluster')->fetchGalaxyClusters($user, [
                    'conditions' => ['GalaxyCluster.uuid' => $uuids],
                    'fields' => ['GalaxyCluster.uuid'],
                    'contain' => []
                ]);
                return Hash::extract($rows, '{n}.GalaxyCluster.uuid');
            case 'Attribute':
                $rows = ClassRegistry::init('MispAttribute')->fetchAttributesSimple($user, [
                    'conditions' => ['Attribute.uuid' => $uuids, 'Attribute.deleted' => 0],
                    'fields' => ['Attribute.uuid']
                ]);
                return Hash::extract($rows, '{n}.Attribute.uuid');
            case 'Object':
                $rows = ClassRegistry::init('MispObject')->fetchObjectSimple($user, [
                    'conditions' => ['Object.uuid' => $uuids, 'Object.deleted' => 0],
                    'fields' => ['Object.uuid']
                ]);
                return Hash::extract($rows, '{n}.Object.uuid');
        }
        return [];
    }

    /**
     * Attach to each element the record it points at, as $user sees it.
     * Elements whose record the user cannot read are returned bare.
     *
     * @param array $user
     * @param array $elements CollectionElement rows, unwrapped
     * @return array
     */
    public function attachTargets(array $user, array $elements)
    {
        $uuidsByType = [];
        foreach ($elements as $element) {
            $type = $element['element_type'] ?? '';
            $address = $element[AnalystData::addressColumn($type, 'element')] ?? '';
            if (!empty($address)) {
                $uuidsByType[$type][] = $address;
            }
        }
        $targets = [];
        foreach ($uuidsByType as $type => $uuids) {
            $targets[$type] = $this->fetchTargets($user, $type, array_values(array_unique($uuids)));
        }
        foreach ($elements as $k => $element) {
            $type = $element['element_type'] ?? '';
            $uuid = $element[AnalystData::addressColumn($type, 'element')] ?? '';
            if (isset($targets[$type][$uuid])) {
                $elements[$k][$type] = $targets[$type][$uuid];
            }
        }
        return $elements;
    }

    /**
     * @param array $user
     * @param string $type
     * @param array $uuids uuids, or SHA-256s for AnalystData::SHA256_TARGETS
     * @return array uuid => what the view shows of the record
     */
    private function fetchTargets(array $user, $type, array $uuids)
    {
        $byUuid = [];
        switch ($type) {
            case 'AttributeValue':
                $ids = ClassRegistry::init('AnalystData')->visibleValuesBySha256($user, $uuids);
                $texts = empty($ids) ? [] : ClassRegistry::init('MispAttribute')->loadAttributeValue()->fetchValues(array_values($ids));
                foreach ($ids as $hex => $id) {
                    if (isset($texts[$id])) {
                        $byUuid[$hex] = ['sha256' => $hex, 'value' => $texts[$id]];
                    }
                }
                break;
            case 'Event':
                $rows = ClassRegistry::init('Event')->fetchSimpleEvents($user, [
                    'conditions' => ['Event.uuid' => $uuids]
                ]);
                foreach ($rows as $row) {
                    $byUuid[$row['Event']['uuid']] = [
                        'id' => $row['Event']['id'],
                        'info' => $row['Event']['info'],
                    ];
                }
                break;
            case 'GalaxyCluster':
                $GalaxyCluster = ClassRegistry::init('GalaxyCluster');
                $rows = $GalaxyCluster->fetchGalaxyClusters($user, [
                    'conditions' => ['GalaxyCluster.uuid' => $uuids]
                ]);
                foreach ($rows as $row) {
                    $arranged = $GalaxyCluster->arrangeData($row);
                    $byUuid[$row['GalaxyCluster']['uuid']] = [$arranged['GalaxyCluster']];
                }
                break;
            case 'Attribute':
                $rows = ClassRegistry::init('MispAttribute')->fetchAttributesSimple($user, [
                    'conditions' => ['Attribute.uuid' => $uuids, 'Attribute.deleted' => 0],
                    'fields' => [
                        'Attribute.id', 'Attribute.uuid', 'Attribute.type',
                        'Attribute.category', 'Attribute.value', 'Attribute.event_id',
                        'Attribute.object_id', 'Event.id', 'Event.info',
                    ]
                ]);
                foreach ($rows as $row) {
                    $byUuid[$row['Attribute']['uuid']] = $row['Attribute'] + [
                        'Event' => $row['Event'],
                    ];
                }
                break;
            case 'Object':
                $rows = ClassRegistry::init('MispObject')->fetchObjectSimple($user, [
                    'conditions' => ['Object.uuid' => $uuids, 'Object.deleted' => 0],
                    'fields' => [
                        'Object.id', 'Object.uuid', 'Object.name',
                        'Object.meta-category', 'Object.event_id',
                    ],
                    'contain' => ['Event' => ['fields' => ['id', 'info']]]
                ]);
                foreach ($rows as $row) {
                    $byUuid[$row['Object']['uuid']] = $row['Object'] + [
                        'Event' => $row['Event'],
                    ];
                }
                break;
        }
        return $byUuid;
    }

    public function afterSave($created, $options = array())
    {
        parent::afterSave($created, $options);
        if ($this->skipCollectionModifiedBump) {
            return;
        }
        $collectionId = $this->data['CollectionElement']['collection_id'] ?? null;
        if (empty($collectionId) && !empty($this->id)) {
            $collectionId = $this->field('collection_id', ['CollectionElement.id' => $this->id]);
        }
        $this->touchCollection($collectionId);
    }

    public function beforeDelete($cascade = true)
    {
        // The row is gone by afterDelete, so stash the parent collection_id now.
        $this->deletedElementCollectionId = $this->field('collection_id', ['CollectionElement.id' => $this->id]);
        return true;
    }

    public function afterDelete()
    {
        parent::afterDelete();
        $collectionId = $this->deletedElementCollectionId;
        $this->deletedElementCollectionId = null;
        if ($this->skipCollectionModifiedBump) {
            return;
        }
        $this->touchCollection($collectionId);
    }

    /**
     * Bump the parent Collection's `modified` so element-only edits are visible
     * to {uuid: modified} sync dedup (D5). updateAll avoids callbacks/validation
     * and harmlessly affects zero rows if the parent no longer exists (e.g. a
     * cascading Collection delete). Skipped during sync capture (see the flag).
     */
    private function touchCollection($collectionId)
    {
        if (empty($collectionId)) {
            return;
        }
        $this->Collection->updateAll(
            ['Collection.modified' => "'" . date('Y-m-d H:i:s') . "'"],
            ['Collection.id' => $collectionId]
        );
    }

    /**
     * @param array $check
     * @return bool|string
     */
    public function validAddress($check)
    {
        return AnalystData::addressError($this->data['CollectionElement'], key($check)) ?? true;
    }

    public function deduceType(string $uuid)
    {
        foreach (array_diff($this->valid_types, AnalystData::SHA256_TARGETS) as $valid_type) {
            $model = ClassRegistry::init($this->typeModels[$valid_type] ?? $valid_type);
            $result = $model->find('first', [
                'conditions' => [$model->alias . '.uuid' => $uuid],
                'fields' => [$model->alias . '.id'],
                'recursive' => -1
            ]);
            if (!empty($result)) {
                return $valid_type;
            }
        }
        throw new NotFoundException(__('Invalid UUID'));
    }

    /**
     * Refuse any target $user cannot read. The read side resolves elements back
     * into objects, so every write path that stores one must check it first. A
     * missing target and an invisible one get the same answer. Any value is
     * accepted: the read side shows its text only to whoever can see it.
     *
     * @param array $user
     * @param string|null $elementType When empty, deduced per address as
     *      beforeValidate() does on save, so leaving it out skips nothing
     * @param array $addresses uuids, or SHA-256s for AnalystData::SHA256_TARGETS
     * @throws NotFoundException
     */
    public function assertTargetsUsable(array $user, $elementType, array $addresses)
    {
        foreach ($addresses as $address) {
            $type = empty($elementType) ? $this->deduceType($address) : $elementType;
            if ($type === 'Event') {
                $event = ClassRegistry::init('Event')->fetchSimpleEvent($user, $address, [
                    'fields' => ['Event.id']
                ]);
                if (empty($event)) {
                    throw new NotFoundException(__('Invalid event or not authorized.'));
                }
            } elseif ($type === 'GalaxyCluster') {
                $clusterCount = ClassRegistry::init('GalaxyCluster')->fetchGalaxyClusters($user, [
                    'conditions' => ['GalaxyCluster.uuid' => $address],
                    'count' => true
                ]);
                if (empty($clusterCount)) {
                    throw new NotFoundException(__('Invalid galaxy cluster or not authorized.'));
                }
            } elseif ($type === 'AttributeValue') {
                continue;
            } elseif ($type === 'Attribute' || $type === 'Object') {
                if (empty($this->readableUuids($user, $type, [$address]))) {
                    throw new NotFoundException(__('Invalid element or not authorized.'));
                }
            } else {
                throw new NotFoundException(__('Invalid element type.'));
            }
        }
    }

    /**
     * SQLSTATE class 23, integrity constraint violation: MySQL reports a
     * duplicate key as 23000, PostgreSQL as 23505.
     *
     * @param PDOException $e
     * @return bool
     */
    public static function isDuplicate(PDOException $e)
    {
        return isset($e->errorInfo[0]) && strpos((string)$e->errorInfo[0], '23') === 0;
    }

    /*
     *  Pass a Collection as received from another instance to this function to capture the elements
     *  The received object is authoritative, so all elements that no longer exist in the upstream will be culled.
     */
    public function captureElements($data) {
        // Sync capture: the parent Collection's `modified` is set authoritatively
        // from the remote by Collection::captureCollection(), so element saves/
        // deletes here must NOT bump it to the local now (D5 / D6 dedup).
        $this->skipCollectionModifiedBump = true;
        try {
        $temp = $this->find('all', [
            'recursive' => -1,
            'conditions' => ['CollectionElement.collection_id' => $data['Collection']['id']]
        ]);
        // Rows match as the unique keys compare them: by row uuid, else by element
        // within the collection, both case-insensitive (ascii_general_ci).
        $oldElements = [];
        $oldByTarget = [];
        foreach ($temp as $oldElement) {
            $row = $oldElement['CollectionElement'];
            $oldElements[strtolower($row['uuid'])] = $row;
            $oldByTarget[$this->targetKey($row)] = strtolower($row['uuid']);
        }
        if (isset($data['Collection']['CollectionElement'])) {
            $elementsToSave = [];
            $captured = [];
            foreach ($data['Collection']['CollectionElement'] as $k => $element) {
                if (!is_array($element)) {
                    continue;
                }
                if (empty($element['uuid'])) {
                    $element['uuid'] = CakeText::uuid();
                }
                $key = $this->targetKey($element);
                $rowUuid = is_string($element['uuid']) ? strtolower($element['uuid']) : '';
                if (!isset($oldElements[$rowUuid]) && $key !== '' && isset($oldByTarget[$key])) {
                    $rowUuid = $oldByTarget[$key];
                }
                if (isset($oldElements[$rowUuid])) {
                    $captured[$this->targetKey($oldElements[$rowUuid])] = true;
                    if (isset($element['description'])) {
                        $oldElements[$rowUuid]['description'] = $element['description'];
                    }
                    $elementsToSave[$k] = $oldElements[$rowUuid];
                    unset($oldElements[$rowUuid]);
                } elseif ($key !== '' && isset($captured[$key])) {
                    continue;
                } else {
                    if ($key !== '') {
                        $captured[$key] = true;
                    }
                    $elementsToSave[$k] = [
                        'CollectionElement' => [
                            'uuid' => $element['uuid'],
                            'element_uuid' => $element['element_uuid'] ?? null,
                            'element_sha256' => $element['element_sha256'] ?? null,
                            'element_type' => $element['element_type'] ?? null,
                            'description' => $element['description'] ?? null,
                            'collection_id' => $data['Collection']['id']
                        ]
                    ];
                    
                }
            }
            foreach ($elementsToSave as $k => $element) {
                if (empty($element['CollectionElement']['id'])) {
                    $this->create();
                }
                try {
                    if (!$this->save($element)) {
                        $this->log(
                            sprintf(
                                'Could not save CollectionElement %s for collection %s: %s',
                                $element['CollectionElement']['uuid'] ?? '',
                                $data['Collection']['id'],
                                json_encode($this->validationErrors)
                            ),
                            LOG_WARNING
                        );
                    }
                } catch (PDOException $e) {
                    $this->log(
                        sprintf(
                            'Could not save CollectionElement %s for collection %s: %s',
                            $element['CollectionElement']['uuid'] ?? '',
                            $data['Collection']['id'],
                            $e->getMessage()
                        ),
                        LOG_WARNING
                    );
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
        } finally {
            $this->skipCollectionModifiedBump = false;
        }
        return $data;
    }

    /**
     * @param array $element
     * @return string What a unique key on the target holds, with its column,
     *      lowercased; '' when the element names no target.
     */
    private function targetKey(array $element)
    {
        foreach (['element_sha256', 'element_uuid'] as $column) {
            $address = $element[$column] ?? null;
            if (is_string($address) && trim($address) !== '') {
                return $column . ':' . strtolower(trim($address));
            }
        }
        return '';
    }
}
