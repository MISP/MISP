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

    public $valid_types = [
        'Event',
        'GalaxyCluster',
        'Attribute',
        'Object',
        'Value'
    ];

    /**
     * A Value element points at its value dictionary row (value_id), and its
     * element_uuid is derived from the literal (Value::uuidFor), so the
     * (element_uuid, collection_id) unique key keeps a value in a collection
     * once. Reads and sync carry the literal as `value`, never the id.
     */
    const VALUE_MAX_BYTES = 1024;

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
            'element_uuid' => [
                'rule' => 'uuid',
                'message' => 'Please provide a valid RFC 4122 UUID'
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
        if (
            empty($this->id) &&
            empty($this->data['CollectionElement']['element_type']) &&
            !empty($this->data['CollectionElement']['element_uuid'])
        ) {
            $this->data['CollectionElement']['element_type'] = $this->deduceType($this->data['CollectionElement']['element_uuid']);
        }
        $element = &$this->data['CollectionElement'];
        if (($element['element_type'] ?? null) === 'Value') {
            $value = isset($element['value']) && is_scalar($element['value'])
                ? trim((string)$element['value'])
                : '';
            if ($value === '') {
                $this->invalidate('value', __('A value element needs a value.'));
            } elseif (strlen($value) > self::VALUE_MAX_BYTES) {
                $this->invalidate('value', __('A value element holds at most %s bytes.', self::VALUE_MAX_BYTES));
            } else {
                App::uses('Value', 'Model');
                $element['value'] = $value;
                $element['element_uuid'] = Value::uuidFor($value);
            }
        } elseif (isset($element['element_type'])) {
            $element['value'] = null;
        }
        return true;
    }

    public function beforeSave($options = array())
    {
        $element = &$this->data['CollectionElement'];
        if (array_key_exists('value', $element)) {
            $element['value_id'] = ($element['element_type'] ?? null) === 'Value' && $element['value'] !== null
                ? ClassRegistry::init('AttributeValue')->intern((string)$element['value'])
                : null;
            unset($element['value']);
        }
        return true;
    }

    public function afterFind($results, $primary = false)
    {
        if (!is_array($results)) {
            return $results;
        }
        $ids = [];
        $this->valueIdsIn($results, $ids);
        $texts = empty($ids) ? [] : ClassRegistry::init('AttributeValue')->fetchValues(array_keys($ids));
        $this->fillValues($results, $texts);
        return $results;
    }

    /**
     * @param array $node A find result, or any part of one
     * @param array $ids value_id => true, added to
     * @return void
     */
    private function valueIdsIn(array $node, array &$ids)
    {
        if (!empty($node['value_id'])) {
            $ids[(int)$node['value_id']] = true;
        }
        foreach ($node as $child) {
            if (is_array($child)) {
                $this->valueIdsIn($child, $ids);
            }
        }
    }

    /**
     * The literal in place of the id, wherever an element row sits in a
     * result: primary rows and the ones a Collection find contains alike.
     *
     * @param array $node
     * @param array $texts value_id => value
     * @return void
     */
    private function fillValues(array &$node, array $texts)
    {
        if (array_key_exists('value_id', $node)) {
            $node['value'] = empty($node['value_id']) ? null : ($texts[(int)$node['value_id']] ?? null);
            unset($node['value_id']);
        }
        foreach ($node as &$child) {
            if (is_array($child)) {
                $this->fillValues($child, $texts);
            }
        }
        unset($child);
    }

    /**
     * The element UUIDs of one type that $user may read. A Value element is
     * authored content of the collection, so every one is readable to whoever
     * sees the collection.
     *
     * @param array $user
     * @param string $type
     * @param array $uuids
     * @return array
     */
    public function readableUuids(array $user, $type, array $uuids)
    {
        $uuids = array_values(array_unique($uuids));
        if (empty($uuids) || $type === 'Value') {
            return $uuids;
        }
        switch ($type) {
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
            if (!empty($element['element_uuid'])) {
                $uuidsByType[$element['element_type'] ?? ''][] = $element['element_uuid'];
            }
        }
        $targets = [];
        foreach ($uuidsByType as $type => $uuids) {
            $targets[$type] = $this->fetchTargets($user, $type, array_values(array_unique($uuids)));
        }
        foreach ($elements as $k => $element) {
            $type = $element['element_type'] ?? '';
            $uuid = $element['element_uuid'] ?? '';
            if (isset($targets[$type][$uuid])) {
                $elements[$k][$type] = $targets[$type][$uuid];
            }
        }
        return $elements;
    }

    /**
     * @param array $user
     * @param string $type
     * @param array $uuids
     * @return array uuid => what the view shows of the record
     */
    private function fetchTargets(array $user, $type, array $uuids)
    {
        $byUuid = [];
        switch ($type) {
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

    public function deduceType(string $uuid)
    {
        foreach ($this->valid_types as $valid_type) {
            if ($valid_type === 'Value') {
                continue;
            }
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
        $oldByElement = [];
        foreach ($temp as $oldElement) {
            $row = $oldElement['CollectionElement'];
            $oldElements[strtolower($row['uuid'])] = $row;
            $oldByElement[$this->elementKey($row)] = strtolower($row['uuid']);
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
                $key = $this->elementKey($element);
                $rowUuid = is_string($element['uuid']) ? strtolower($element['uuid']) : '';
                if (!isset($oldElements[$rowUuid]) && $key !== null && isset($oldByElement[$key])) {
                    $rowUuid = $oldByElement[$key];
                }
                if (isset($oldElements[$rowUuid])) {
                    $captured[$this->elementKey($oldElements[$rowUuid])] = true;
                    if (isset($element['description'])) {
                        $oldElements[$rowUuid]['description'] = $element['description'];
                    }
                    $elementsToSave[$k] = $oldElements[$rowUuid];
                    unset($oldElements[$rowUuid]);
                } elseif ($key !== null && isset($captured[$key])) {
                    continue;
                } else {
                    if ($key !== null) {
                        $captured[$key] = true;
                    }
                    $elementsToSave[$k] = [
                        'CollectionElement' => [
                            'uuid' => $element['uuid'],
                            'element_uuid' => $element['element_uuid'] ?? null,
                            'element_type' => $element['element_type'] ?? null,
                            'value' => $element['value'] ?? null,
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
     * @return string|null The element's half of the (element_uuid, collection_id) key
     */
    private function elementKey(array $element)
    {
        $uuid = $element['element_uuid'] ?? null;
        $value = ($element['element_type'] ?? null) === 'Value' && isset($element['value']) && is_scalar($element['value'])
            ? trim((string)$element['value'])
            : '';
        if ($value !== '') {
            // beforeValidate() derives a Value element's uuid from its text and ignores a payload one
            App::uses('Value', 'Model');
            $uuid = Value::uuidFor($value);
        }
        return is_string($uuid) && $uuid !== '' ? strtolower($uuid) : null;
    }
}
