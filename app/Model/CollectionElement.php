<?php
App::uses('AppModel', 'Model');
App::uses('AnalystData', 'Model');
App::uses('AnalystGraphDocumentTool', 'Tools');
App::uses('DistributionLevel', 'Tools');

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
        'StandaloneObject',
    ];

    /**
     * The element types a MISP older than 3.0 can hold.
     */
    const PRE30_TYPES = [
        'Event',
        'GalaxyCluster',
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

    /** @var array|null the row stashed in beforeDelete for afterDelete */
    private $deletedElement = null;

    /** @var array collection_id => whether it holds removal rows, read once per request */
    private $mayHaveRemovals = [];

    /** The user a new element records as having added it. */
    public $current_user = null;

    /** While capturing from another instance: who added an element stays there. */
    private $remoteCapture = false;

    /** Items one addItems() or removeItems() call takes. */
    const ITEM_LIMIT = 2000;
    const WHY_LENGTH = 255;

    /** What an item of the workspace names, by its type. */
    const ITEM_TYPES = [
        'Event' => 'Event',
        'Attribute' => 'Attribute',
        'Object' => 'Object',
        'GalaxyCluster' => 'GalaxyCluster',
        'Value' => 'AttributeValue',
        'StandaloneObject' => 'StandaloneObject',
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
        // Who and when are this instance's to record, never the request's
        if (empty($this->id)) {
            $this->data['CollectionElement']['user_id'] = $this->remoteCapture ? null : ($this->current_user['id'] ?? null);
            if (!$this->remoteCapture) {
                $this->data['CollectionElement']['created'] = date('Y-m-d H:i:s');
            }
            $this->data['CollectionElement']['published'] = $this->remoteCapture;
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
            case 'StandaloneObject':
                // Readable through any collection the user can see that holds it
                $conditions = ['CollectionElement.element_type' => 'StandaloneObject', 'CollectionElement.element_uuid' => $uuids];
                $acl = $this->Collection->buildConditions($user);
                if (!empty($acl)) {
                    $conditions['AND'][] = $acl;
                }
                $rows = $this->find('all', [
                    'recursive' => -1,
                    'fields' => ['DISTINCT CollectionElement.element_uuid'],
                    'joins' => [[
                        'table' => $this->Collection->table,
                        'alias' => 'Collection',
                        'type' => 'INNER',
                        'conditions' => ['Collection.id = CollectionElement.collection_id'],
                    ]],
                    'conditions' => $conditions,
                ]);
                return array_values(array_unique(array_map('strtolower', Hash::extract($rows, '{n}.CollectionElement.element_uuid'))));
        }
        return [];
    }

    /**
     * Attach to each element the record it points at, as $user sees it.
     * Elements whose record the user cannot read are returned bare. A value
     * member shows the text it keeps, `held` saying whether an attribute the
     * user can see carries it; one without text shows it only then.
     *
     * @param array $user
     * @param array $elements CollectionElement rows, unwrapped
     * @return array
     */
    public function attachTargets(array $user, array $elements)
    {
        $uuidsByType = [];
        $texts = [];
        foreach ($elements as $element) {
            $type = $element['element_type'] ?? '';
            $address = $element[AnalystData::addressColumn($type, 'element')] ?? '';
            if (!empty($address)) {
                $uuidsByType[$type][] = $address;
                if ($type === 'AttributeValue' && is_string($element['element_value'] ?? null)) {
                    $texts[strtolower($address)] = $element['element_value'];
                }
            }
        }
        $targets = [];
        foreach ($uuidsByType as $type => $uuids) {
            $targets[$type] = $this->fetchTargets($user, $type, array_values(array_unique($uuids)), $texts);
        }
        foreach ($elements as $k => $element) {
            $type = $element['element_type'] ?? '';
            $uuid = (string)($element[AnalystData::addressColumn($type, 'element')] ?? '');
            $target = $targets[$type][$uuid] ?? $targets[$type][strtolower($uuid)] ?? null;
            if ($target !== null) {
                $elements[$k][$type] = $target;
            }
            if (array_key_exists('origin', $element)) {
                $elements[$k]['origin'] = self::decodedOrigin($element['origin']);
            }
        }
        return $elements;
    }

    /**
     * @param array $user
     * @param string $type
     * @param array $uuids uuids, or SHA-256s for AnalystData::SHA256_TARGETS
     * @param array $texts A value member's own text, by its SHA-256
     * @return array uuid => what the view shows of the record
     */
    private function fetchTargets(array $user, $type, array $uuids, array $texts = [])
    {
        $byUuid = [];
        switch ($type) {
            case 'AttributeValue':
                $ids = ClassRegistry::init('AnalystData')->visibleValuesBySha256($user, $uuids);
                $unread = array_values(array_diff_key($ids, $texts));
                $read = empty($unread) ? [] : ClassRegistry::init('MispAttribute')->loadAttributeValue()->fetchValues($unread);
                foreach ($uuids as $hex) {
                    $hex = strtolower($hex);
                    $text = $texts[$hex] ?? (isset($ids[$hex]) ? ($read[$ids[$hex]] ?? null) : null);
                    if ($text !== null) {
                        $byUuid[$hex] = ['sha256' => $hex, 'value' => $text, 'held' => isset($ids[$hex])];
                    }
                }
                break;
            case 'StandaloneObject':
                $readable = $this->readableUuids($user, 'StandaloneObject', array_merge($uuids, array_map('strtoupper', $uuids)));
                $byUuid = ClassRegistry::init('StandaloneObject')->records($readable);
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
                        'Object.template_uuid', 'Object.template_version',
                    ],
                    'contain' => ['Event' => ['fields' => ['id', 'info']]]
                ]);
                $ids = [];
                foreach ($rows as $row) {
                    $byUuid[$row['Object']['uuid']] = $row['Object'] + [
                        'Event' => $row['Event'],
                        'Attribute' => [],
                    ];
                    $ids[(int)$row['Object']['id']] = $row['Object']['uuid'];
                }
                // What names the object: its attributes the user can read
                if (!empty($ids)) {
                    $attributes = ClassRegistry::init('MispAttribute')->fetchAttributesSimple($user, [
                        'conditions' => ['Attribute.object_id' => array_keys($ids), 'Attribute.deleted' => 0],
                        'fields' => ['Attribute.id', 'Attribute.object_id', 'Attribute.object_relation', 'Attribute.type', 'Attribute.value'],
                        'order' => ['Attribute.id' => 'ASC'],
                    ]);
                    foreach ($attributes as $row) {
                        $uuid = $ids[(int)$row['Attribute']['object_id']] ?? null;
                        if ($uuid !== null) {
                            $byUuid[$uuid]['Attribute'][] = [
                                'object_relation' => $row['Attribute']['object_relation'],
                                'type' => $row['Attribute']['type'],
                                'value' => $row['Attribute']['value'],
                            ];
                        }
                    }
                }
                break;
        }
        return $byUuid;
    }

    public function afterSave($created, $options = array())
    {
        parent::afterSave($created, $options);
        if ($created && !$this->remoteCapture) {
            $this->takeBackRemoval($this->data['CollectionElement'], $this->id);
        }
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
        // The row is gone by afterDelete, so stash it now.
        $row = $this->find('first', [
            'recursive' => -1,
            'conditions' => ['CollectionElement.id' => $this->id],
        ]);
        $this->deletedElement = $row['CollectionElement'] ?? null;
        $this->deletedElementCollectionId = $this->deletedElement['collection_id'] ?? null;
        return true;
    }

    public function afterDelete()
    {
        parent::afterDelete();
        $collectionId = $this->deletedElementCollectionId;
        $element = $this->deletedElement;
        $this->deletedElementCollectionId = null;
        $this->deletedElement = null;
        if (!empty($element['published']) && !$this->remoteCapture) {
            $this->recordRemoval($element);
        }
        if (($element['element_type'] ?? null) === 'StandaloneObject' && is_string($element['element_uuid'] ?? null)) {
            ClassRegistry::init('StandaloneObject')->deleteIfUnheld($element['element_uuid']);
        }
        if ($this->skipCollectionModifiedBump) {
            return;
        }
        $this->touchCollection($collectionId);
    }

    /**
     * Bump the parent Collection's `modified` so element-only edits are visible
     * to {uuid: modified} sync dedup (D5), and leave it with changes partners
     * do not have yet. updateAll avoids callbacks/validation and harmlessly
     * affects zero rows if the parent no longer exists (e.g. a cascading
     * Collection delete). Skipped during sync capture (see the flag).
     */
    private function touchCollection($collectionId)
    {
        if (empty($collectionId)) {
            return;
        }
        $this->Collection->updateAll(
            ['Collection.modified' => "'" . date('Y-m-d H:i:s') . "'", 'Collection.published' => false],
            ['Collection.id' => $collectionId]
        );
    }

    /**
     * Partners hold a published member until the next publish says it is gone.
     *
     * @param array $element The deleted row
     */
    private function recordRemoval(array $element)
    {
        $Removal = ClassRegistry::init('CollectionElementRemoval');
        $Removal->create();
        try {
            $Removal->save(['CollectionElementRemoval' => [
                'collection_id' => $element['collection_id'],
                'element_type' => $element['element_type'],
                'element_uuid' => is_string($element['element_uuid']) ? strtolower($element['element_uuid']) : null,
                'element_sha256' => $element['element_sha256'],
                'user_id' => $this->current_user['id'] ?? null,
                'created' => date('Y-m-d H:i:s'),
            ]]);
        } catch (PDOException $e) {
            if (!self::isDuplicate($e)) {
                throw $e;
            }
        }
        $this->mayHaveRemovals[(int)$element['collection_id']] = true;
    }

    /**
     * A member added back before the next publish is one partners still
     * hold: its removal is dropped and it joins as published.
     *
     * @param array $element The saved row
     * @param int $id
     */
    private function takeBackRemoval(array $element, $id)
    {
        $collectionId = (int)($element['collection_id'] ?? 0);
        $Removal = ClassRegistry::init('CollectionElementRemoval');
        if (!isset($this->mayHaveRemovals[$collectionId])) {
            $this->mayHaveRemovals[$collectionId] = $Removal->hasAny(['CollectionElementRemoval.collection_id' => $collectionId]);
        }
        if (!$this->mayHaveRemovals[$collectionId]) {
            return;
        }
        $key = $this->targetKey($element);
        if ($key === '') {
            return;
        }
        list($column, $address) = explode(':', $key, 2);
        $removal = $Removal->find('first', [
            'recursive' => -1,
            'fields' => ['CollectionElementRemoval.id'],
            'conditions' => [
                'CollectionElementRemoval.collection_id' => $collectionId,
                'CollectionElementRemoval.' . $column => $address,
            ],
        ]);
        if (empty($removal)) {
            return;
        }
        $Removal->delete($removal['CollectionElementRemoval']['id']);
        $this->updateAll(['CollectionElement.published' => true], ['CollectionElement.id' => $id]);
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
     *  A MISP older than 3.0 holds only event and galaxy cluster elements: from one ($fromPre30), the others are neither taken nor culled.
     *  From another instance ($remote), a new element keeps the time it was added there and names nobody.
     *  A value's text is kept only when it is the text its SHA-256 names; a standalone object comes with its record.
     */
    public function captureElements($data, $fromPre30 = false, $remote = false) {
        // Sync capture: the parent Collection's `modified` is set authoritatively
        // from the remote by Collection::captureCollection(), so element saves/
        // deletes here must NOT bump it to the local now (D5 / D6 dedup).
        $this->skipCollectionModifiedBump = true;
        $this->remoteCapture = (bool)$remote;
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
                if ($fromPre30 && !self::heldBefore30($element)) {
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
                    if (!isset($oldElements[$rowUuid]['element_value'])) {
                        $oldElements[$rowUuid]['element_value'] = self::capturedText([
                            'element_sha256' => $oldElements[$rowUuid]['element_sha256'] ?? null,
                            'element_value' => $element['element_value'] ?? null,
                        ]);
                    }
                    $elementsToSave[$k] = $oldElements[$rowUuid];
                    unset($oldElements[$rowUuid]);
                } elseif ($key !== '' && isset($captured[$key])) {
                    continue;
                } else {
                    if (($element['element_type'] ?? null) === 'StandaloneObject' && !$this->captureRecord($element, $data['Collection']['id'])) {
                        continue;
                    }
                    if ($key !== '') {
                        $captured[$key] = true;
                    }
                    $origin = self::decodedOrigin($element['origin'] ?? null);
                    $elementsToSave[$k] = [
                        'CollectionElement' => [
                            'uuid' => $element['uuid'],
                            'element_uuid' => $element['element_uuid'] ?? null,
                            'element_sha256' => $element['element_sha256'] ?? null,
                            'element_value' => self::capturedText($element),
                            'element_type' => $element['element_type'] ?? null,
                            'description' => $element['description'] ?? null,
                            'origin' => $origin === null ? null : json_encode($origin, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
                            'collection_id' => $data['Collection']['id']
                        ]
                    ];
                    if ($remote) {
                        $elementsToSave[$k]['CollectionElement']['created'] = self::capturedTime($element['created'] ?? null);
                    }

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
                if ($fromPre30 && !self::heldBefore30($toDelete)) {
                    continue;
                }
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
            $this->remoteCapture = false;
        }
        return $data;
    }

    /**
     * @param mixed $value When another instance says the element was added
     * @return string|null
     */
    private static function capturedTime($value)
    {
        return is_string($value) && preg_match('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $value) ? $value : null;
    }

    /**
     * Add records to a collection the caller checked $user may edit, named
     * as the workspace names them: {type, uuid} for an event, an attribute,
     * an object or a galaxy cluster; {type: 'Value', value} for a value,
     * which the member keeps as text, whether or not MISP holds it;
     * {type: 'StandaloneObject', module, content} for an object a module
     * answered, {type: 'StandaloneObject', template, attributes, comment?}
     * for one made from a template, or {type: 'StandaloneObject', uuid} for
     * one a collection the user sees holds. A value or an answer may say
     * where it came from: `origin` {module, type, value, ran_at}.
     *
     * Each is reported by its key in a graph document (`Type:address`):
     * added, present when the collection holds it already, or refused.
     * `narrower` lists the values added that every attribute the user can
     * see holding them shares more narrowly than the collection.
     *
     * @param array $user
     * @param int $collectionId
     * @param array $items
     * @param string $description
     * @return array {added: [key], present: [key], refused: [{index, key, error}], narrower: [key]}
     */
    public function addItems(array $user, $collectionId, array $items, $description = '')
    {
        list($wanted, $report) = $this->itemTargets($items);
        $report += ['added' => [], 'present' => [], 'narrower' => []];
        $wanted = $this->valueTexts($user, $wanted, $report['refused']);
        $wanted = $this->readableTargets($user, $wanted, $report['refused'], ['AttributeValue']);
        $wanted = $this->builtRecords($wanted, $report['refused']);
        $held = $this->heldKeys($collectionId, $wanted);
        $StandaloneObject = null;
        foreach ($wanted as $target) {
            if (isset($target['record'])) {
                $StandaloneObject = ClassRegistry::init('StandaloneObject');
                break;
            }
        }
        $addedValues = [];
        $this->current_user = $user;
        $this->skipCollectionModifiedBump = true;
        try {
            foreach ($wanted as $key => $target) {
                if (isset($held[$key])) {
                    $report['present'][] = $key;
                    continue;
                }
                if (isset($target['record']) && !$StandaloneObject->ensure($target['record'])) {
                    $report['refused'][] = ['index' => $target['index'], 'key' => $key, 'error' => implode(' ', Hash::flatten($StandaloneObject->validationErrors))];
                    continue;
                }
                $this->create();
                try {
                    $saved = $this->save(['CollectionElement' => [
                        'collection_id' => $collectionId,
                        'element_type' => $target['element_type'],
                        $target['column'] => $target['address'],
                        'element_value' => $target['text'] ?? null,
                        'description' => (string)$description,
                        'origin' => isset($target['origin']) ? json_encode($target['origin'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) : null,
                    ]]);
                } catch (PDOException $e) {
                    if (!self::isDuplicate($e)) {
                        throw $e;
                    }
                    $report['present'][] = $key;
                    continue;
                }
                if ($saved) {
                    $report['added'][] = $key;
                    if ($target['element_type'] === 'AttributeValue') {
                        $addedValues[$target['address']] = $key;
                    }
                } else {
                    $report['refused'][] = ['index' => $target['index'], 'key' => $key, 'error' => implode(' ', Hash::flatten($this->validationErrors))];
                    if (isset($target['record'])) {
                        $StandaloneObject->deleteIfUnheld($target['address']);
                    }
                }
            }
        } finally {
            $this->skipCollectionModifiedBump = false;
        }
        if (!empty($report['added'])) {
            $this->touchCollection($collectionId);
        }
        if (!empty($addedValues)) {
            $distribution = $this->Collection->field('distribution', ['Collection.id' => $collectionId]);
            foreach ($this->narrowerValues($user, (int)$distribution, array_keys($addedValues)) as $hex) {
                $report['narrower'][] = $addedValues[$hex];
            }
        }
        return $report;
    }

    /**
     * Of these values, those an attribute the user can see holds, and every
     * such attribute shares more narrowly than a collection of this
     * distribution: by its event, its object or itself.
     *
     * @param array $user
     * @param int $distribution The collection's
     * @param array $hexes SHA-256s
     * @return array The narrower SHA-256s, lowercase
     */
    public function narrowerValues(array $user, $distribution, array $hexes)
    {
        $narrower = DistributionLevel::narrowerThan($distribution);
        if (empty($narrower) || empty($hexes)) {
            return [];
        }
        $held = ClassRegistry::init('AnalystData')->visibleValuesBySha256($user, $hexes);
        if (empty($held)) {
            return [];
        }
        $reach = array_values(array_diff([0, 1, 2, 3, 4], $narrower));
        $wide = array_flip(ClassRegistry::init('MispAttribute')->visibleValueIds($user, array_values($held), count($held), $reach));
        $out = [];
        foreach ($held as $hex => $id) {
            if (!isset($wide[$id])) {
                $out[] = $hex;
            }
        }
        return $out;
    }

    /**
     * Give each new member of a copy where its original came from.
     *
     * @param int $fromCollectionId
     * @param int $toCollectionId
     * @param array $keys The copy's members, by key
     * @return void
     */
    public function copyOrigins($fromCollectionId, $toCollectionId, array $keys)
    {
        list($wanted) = $this->itemTargets($keys);
        if (empty($wanted)) {
            return;
        }
        $from = $this->heldKeys($fromCollectionId, $wanted);
        $to = $this->heldKeys($toCollectionId, $wanted);
        $origins = empty($from) ? [] : $this->find('list', [
            'recursive' => -1,
            'fields' => ['CollectionElement.id', 'CollectionElement.origin'],
            'conditions' => ['CollectionElement.id' => array_values($from), 'CollectionElement.origin !=' => null],
        ]);
        foreach ($from as $key => $id) {
            if (!isset($origins[$id], $to[$key])) {
                continue;
            }
            $this->create();
            $this->save(
                ['CollectionElement' => ['id' => $to[$key], 'origin' => $origins[$id]]],
                ['validate' => false, 'callbacks' => false, 'fieldList' => ['origin']]
            );
        }
    }

    /**
     * Elements as sync carries them: their origin decoded, a standalone
     * object with its record.
     *
     * @param array $elements CollectionElement rows, unwrapped
     * @return array
     */
    public function withRecords(array $elements)
    {
        $uuids = [];
        foreach ($elements as $element) {
            if (is_array($element) && ($element['element_type'] ?? null) === 'StandaloneObject' && is_string($element['element_uuid'] ?? null)) {
                $uuids[] = $element['element_uuid'];
            }
        }
        $records = empty($uuids) ? [] : ClassRegistry::init('StandaloneObject')->records($uuids);
        foreach ($elements as $i => $element) {
            if (!is_array($element)) {
                continue;
            }
            if (array_key_exists('origin', $element)) {
                $elements[$i]['origin'] = self::decodedOrigin($element['origin']);
            }
            $record = isset($element['element_uuid']) ? ($records[strtolower((string)$element['element_uuid'])] ?? null) : null;
            if (($element['element_type'] ?? null) === 'StandaloneObject' && $record !== null) {
                $elements[$i]['StandaloneObject'] = $record;
            }
        }
        return $elements;
    }

    /**
     * Values named by their SHA-256 alone take their text from an attribute
     * the user can see; without one there is no text to keep.
     *
     * @param array $user
     * @param array $wanted itemTargets()'s
     * @param array $refused
     * @return array
     */
    private function valueTexts(array $user, array $wanted, array &$refused)
    {
        $hexes = [];
        foreach ($wanted as $key => $target) {
            if ($target['element_type'] === 'AttributeValue' && !isset($target['text'])) {
                $hexes[$key] = $target['address'];
            }
        }
        if (empty($hexes)) {
            return $wanted;
        }
        $ids = ClassRegistry::init('AnalystData')->visibleValuesBySha256($user, array_values($hexes));
        $texts = empty($ids) ? [] : ClassRegistry::init('MispAttribute')->loadAttributeValue()->fetchValues(array_values($ids));
        foreach ($hexes as $key => $hex) {
            $text = isset($ids[$hex]) ? ($texts[$ids[$hex]] ?? null) : null;
            if ($text === null) {
                $refused[] = ['index' => $wanted[$key]['index'], 'key' => $key, 'error' => __('Send the value itself: no attribute you can see holds this SHA-256.')];
                unset($wanted[$key]);
                continue;
            }
            $wanted[$key]['text'] = $text;
        }
        return $wanted;
    }

    /**
     * Standalone objects named by what they hold become records, not saved
     * yet; one that does not fit its template is refused.
     *
     * @param array $wanted itemTargets()'s
     * @param array $refused
     * @return array
     */
    private function builtRecords(array $wanted, array &$refused)
    {
        $StandaloneObject = null;
        foreach ($wanted as $key => $target) {
            if (!isset($target['build'])) {
                continue;
            }
            $StandaloneObject = $StandaloneObject ?: ClassRegistry::init('StandaloneObject');
            $build = $target['build'];
            $errors = [];
            $record = isset($build['content'])
                ? $StandaloneObject->fromAnswer($build['module'], $build['content'], $errors)
                : $StandaloneObject->fromTemplate($build['template'], $build['attributes'], $build['comment'], $errors);
            if ($record === null) {
                $refused[] = ['index' => $target['index'], 'key' => $key, 'error' => implode(' ', $errors)];
                unset($wanted[$key]);
                continue;
            }
            if (!isset($build['content'])) {
                // Made by hand: its key is the uuid drawn for it
                $record['uuid'] = $target['address'];
            }
            $wanted[$key] = $target + ['record' => $record];
        }
        return $wanted;
    }

    /**
     * @param array $element As another instance sends it
     * @param int $collectionId
     * @return bool Whether its record is here now
     */
    private function captureRecord(array $element, $collectionId)
    {
        $errors = [];
        $StandaloneObject = ClassRegistry::init('StandaloneObject');
        $record = $StandaloneObject->fromRemote($element['StandaloneObject'] ?? null, $errors);
        if ($record !== null && $record['uuid'] !== strtolower((string)($element['element_uuid'] ?? ''))) {
            $errors[] = __('The element names another record.');
            $record = null;
        }
        if ($record === null || !$StandaloneObject->ensure($record)) {
            $this->log(sprintf(
                'Could not capture standalone object %s for collection %s: %s',
                is_scalar($element['element_uuid'] ?? null) ? $element['element_uuid'] : '',
                $collectionId,
                implode(' ', $errors ?: Hash::flatten($StandaloneObject->validationErrors))
            ), LOG_WARNING);
            return false;
        }
        return true;
    }

    /**
     * Take records out of a collection the caller checked $user may edit,
     * named as addItems() takes them or by the keys it reports.
     *
     * @param int $collectionId
     * @param array $items
     * @return array {removed: [key], absent: [key], refused: [{index, key, error}]}
     */
    public function removeItems($collectionId, array $items)
    {
        list($wanted, $report) = $this->itemTargets($items);
        $report += ['removed' => [], 'absent' => []];
        $held = $this->heldKeys($collectionId, $wanted);
        $this->skipCollectionModifiedBump = true;
        try {
            foreach ($wanted as $key => $target) {
                if (isset($held[$key]) && $this->delete($held[$key])) {
                    $report['removed'][] = $key;
                } else {
                    $report['absent'][] = $key;
                }
            }
        } finally {
            $this->skipCollectionModifiedBump = false;
        }
        if (!empty($report['removed'])) {
            $this->touchCollection($collectionId);
        }
        return $report;
    }

    /**
     * Say why a collection the caller checked $user may edit holds a record.
     *
     * @param int $collectionId
     * @param mixed $item Named as addItems() takes it
     * @param string $description
     * @return string|null The record's key, or null when the collection does
     *      not hold it
     */
    public function describeItem($collectionId, $item, $description)
    {
        list($wanted) = $this->itemTargets([$item]);
        $held = $this->heldKeys($collectionId, $wanted);
        if (empty($held)) {
            return null;
        }
        $key = array_keys($held)[0];
        $this->create();
        $this->id = $held[$key];
        $this->save(['CollectionElement' => ['id' => $held[$key], 'description' => $description]], true, ['description']);
        return $key;
    }

    /**
     * Which of these records a collection holds, named as addItems() takes
     * them. A record the user cannot read is answered absent, so a guessed
     * uuid says nothing about the collection. Its values and standalone
     * objects are shown to whoever sees it, so they are answered as held.
     *
     * @param array $user
     * @param int $collectionId
     * @param array $items
     * @return array {present: [key], absent: [key]}
     */
    public function heldItems(array $user, $collectionId, array $items)
    {
        list($wanted) = $this->itemTargets($items);
        $unreadable = [];
        $readable = $this->readableTargets($user, $wanted, $unreadable, ['AttributeValue', 'StandaloneObject']);
        $held = $this->heldKeys($collectionId, $readable);
        $report = ['present' => [], 'absent' => []];
        foreach (array_keys($wanted) as $key) {
            $report[isset($held[$key]) ? 'present' : 'absent'][] = $key;
        }
        return $report;
    }

    /**
     * The targets the user can read: one lookup per type. The others are
     * appended to $refused. What the request itself brings, a value's text
     * or an object's content, is the adder's to share and is not looked up.
     *
     * @param array $user
     * @param array $wanted itemTargets()'s
     * @param array $refused
     * @param array $unchecked Element types let through as they are
     * @return array $wanted without what the user cannot read
     */
    private function readableTargets(array $user, array $wanted, array &$refused, array $unchecked = [])
    {
        $byType = [];
        foreach ($wanted as $key => $target) {
            if (in_array($target['element_type'], $unchecked, true) || isset($target['text']) || isset($target['build'])) {
                continue;
            }
            $byType[$target['element_type']][$key] = $target['address'];
        }
        foreach ($byType as $type => $addresses) {
            // Records are stored as each creator spelled their uuid
            $lookup = $type === 'AttributeValue' ? array_values($addresses) : array_merge(array_values($addresses), array_map('strtoupper', $addresses));
            $readable = array_flip(array_map('strtolower', $this->readableUuids($user, $type, $lookup)));
            foreach ($addresses as $key => $address) {
                if (!isset($readable[$address])) {
                    $refused[] = [
                        'index' => $wanted[$key]['index'],
                        'key' => $key,
                        'error' => __('Not found or not authorised.'),
                    ];
                    unset($wanted[$key]);
                }
            }
        }
        return $wanted;
    }

    /**
     * @param array $items
     * @return array [key => {element_type, column, address, index, text?, origin?, build?}, {refused: [...]}]
     */
    private function itemTargets(array $items)
    {
        $wanted = [];
        $refused = [];
        foreach (array_values($items) as $i => $item) {
            $target = self::itemTarget($item);
            if ($target === null) {
                $refused[] = ['index' => $i, 'key' => null, 'error' => __('Not a record a collection can hold.')];
            } elseif (isset($target['error'])) {
                $refused[] = ['index' => $i, 'key' => $target['key'], 'error' => $target['error']];
            } elseif (!isset($wanted[$target['key']])) {
                $wanted[$target['key']] = $target + ['index' => $i];
            }
        }
        return [$wanted, ['refused' => $refused]];
    }

    /**
     * @param mixed $item {type, uuid}, {type: 'Value', value | sha256},
     *      {type: 'StandaloneObject', module, content | template, attributes},
     *      each with an optional `origin`, or a `Type:address` key
     * @return array|null {key, element_type, column, address, text?, origin?,
     *      build?, error?}; null when it names nothing a collection holds
     */
    public static function itemTarget($item)
    {
        if (is_string($item) && strpos($item, ':') !== false) {
            list($type, $address) = explode(':', $item, 2);
            $item = $type === 'Value' ? ['type' => $type, 'sha256' => $address] : ['type' => $type, 'uuid' => $address];
        }
        if (!is_array($item) || !is_string($item['type'] ?? null) || !isset(self::ITEM_TYPES[$item['type']])) {
            return null;
        }
        $type = $item['type'];
        $extra = [];
        $error = null;
        if ($type === 'Value') {
            if (isset($item['value']) && is_scalar($item['value']) && trim((string)$item['value']) !== '') {
                $text = trim((string)$item['value']);
                $address = hash('sha256', $text);
                $extra['text'] = $text;
                if (strlen($text) > AnalystGraphDocumentTool::MAX_ANSWER_STRING_BYTES) {
                    $error = __('A value holds at most %s bytes.', AnalystGraphDocumentTool::MAX_ANSWER_STRING_BYTES);
                }
            } elseif (is_string($item['sha256'] ?? null) && preg_match('/^[0-9a-f]{64}$/i', $item['sha256'])) {
                $address = strtolower($item['sha256']);
            } else {
                return null;
            }
            $column = 'element_sha256';
        } elseif ($type === 'StandaloneObject' && array_key_exists('content', $item)) {
            $errors = [];
            $content = AnalystGraphDocumentTool::normaliseObjectContent($item['content'], $errors);
            $module = $item['module'] ?? null;
            if (!is_string($module) || !preg_match(AnalystGraphDocumentTool::MODULE_PATTERN, $module)) {
                return null;
            }
            if ($content === null) {
                return ['key' => null, 'error' => implode(' ', $errors)];
            }
            $address = AnalystGraphDocumentTool::answerUuid($content, $module);
            $extra['build'] = ['module' => $module, 'content' => $content];
            $column = 'element_uuid';
        } elseif ($type === 'StandaloneObject' && array_key_exists('template', $item)) {
            $address = strtolower(CakeText::uuid());
            $extra['build'] = [
                'template' => $item['template'],
                'attributes' => $item['attributes'] ?? null,
                'comment' => $item['comment'] ?? '',
            ];
            $column = 'element_uuid';
        } else {
            $address = $item['uuid'] ?? null;
            if (!is_string($address) || !preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $address)) {
                return null;
            }
            $address = strtolower($address);
            $column = 'element_uuid';
        }
        if (isset($item['origin']) && in_array($type, ['Value', 'StandaloneObject'], true)) {
            $originError = null;
            $extra['origin'] = AnalystGraphDocumentTool::normaliseMemberOrigin($item['origin'], $originError);
            if ($extra['origin'] === null) {
                $error = $error ?? __('origin: %s', $originError);
            }
        }
        $target = [
            'key' => $type . ':' . $address,
            'element_type' => self::ITEM_TYPES[$type],
            'column' => $column,
            'address' => $address,
        ] + $extra;
        if ($error !== null) {
            $target['error'] = $error;
        }
        return $target;
    }

    /**
     * Of these targets, those the collection holds: one lookup per address
     * column, each on its unique index.
     *
     * @param int $collectionId
     * @param array $wanted itemTargets()'s
     * @return array key => element id
     */
    private function heldKeys($collectionId, array $wanted)
    {
        $byColumn = [];
        foreach ($wanted as $key => $target) {
            $byColumn[$target['column']][$target['address']] = $key;
        }
        $held = [];
        foreach ($byColumn as $column => $keys) {
            $rows = $this->find('list', [
                'recursive' => -1,
                'fields' => ['CollectionElement.id', 'CollectionElement.' . $column],
                'conditions' => [
                    'CollectionElement.collection_id' => $collectionId,
                    'CollectionElement.' . $column => array_map('strval', array_keys($keys)),
                ],
            ]);
            foreach ($rows as $id => $address) {
                $key = $keys[strtolower((string)$address)] ?? null;
                if ($key !== null) {
                    $held[$key] = $id;
                }
            }
        }
        return $held;
    }

    /**
     * @param array $element
     * @return bool Whether a MISP older than 3.0 can hold the element
     */
    public static function heldBefore30(array $element)
    {
        return in_array($element['element_type'] ?? null, self::PRE30_TYPES, true);
    }

    /**
     * @param array $element As sent: element_sha256 and element_value
     * @return string|null The text, when it is the one the SHA-256 names
     */
    private static function capturedText(array $element)
    {
        $text = $element['element_value'] ?? null;
        $hex = $element['element_sha256'] ?? null;
        if (!is_string($text) || !is_string($hex) || strlen($text) > AnalystGraphDocumentTool::MAX_ANSWER_STRING_BYTES) {
            return null;
        }
        $text = trim($text);
        return $text !== '' && hash('sha256', $text) === strtolower($hex) ? $text : null;
    }

    /**
     * @param mixed $origin As stored (JSON) or sent
     * @return array|null {module, type, value, ran_at}
     */
    public static function decodedOrigin($origin)
    {
        if (is_string($origin)) {
            $origin = json_decode($origin, true);
        }
        if (!is_array($origin)) {
            return null;
        }
        $error = null;
        return AnalystGraphDocumentTool::normaliseMemberOrigin($origin, $error);
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
