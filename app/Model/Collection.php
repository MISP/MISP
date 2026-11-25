<?php
App::uses('AppModel', 'Model');
App::uses('CollectionElement', 'Model');
App::uses('DistributionLevel', 'Tools');
App::uses('ServerSyncTool', 'Tools');
App::uses('SyncTool', 'Tools');
App::uses('ComplexQueryTool', 'Tools');
App::uses('TmpFileTool', 'Tools');
App::uses('JsonTool', 'Tools');

class Collection extends AppModel
{

    public $recursive = -1;

    public $actsAs = array(
            'Containable',
            'AnalystDataParent',
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
        ),
        'SharingGroup' => [
            'className' => 'SharingGroup',
            'foreignKey' => 'sharing_group_id',
            'fields' => [
                'SharingGroup.id',
                'SharingGroup.uuid',
                'SharingGroup.name'
            ]
        ]
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

    const VALID_TYPES = [
        'campaign',
        'intrusion_set',
        'named_threat',
        'research',
        'other'
    ];

    /** How far the investigation went, as on events. */
    const ANALYSIS_LEVELS = [0, 1, 2];

    /** Entries a publish review lists per kind of change. */
    const REVIEW_LIMIT = 50;

    /**
     * The fields of the restSearch `query` tree (ComplexQueryTool). Elements are
     * matched by their address only: their targets' ACL is not part of the visible set.
     */
    const QUERY_FIELDS = [
        'id' => ['kind' => 'int', 'column' => 'Collection.id', 'level' => ['collection']],
        'uuid' => ['kind' => 'string', 'column' => 'Collection.uuid', 'ops' => ComplexQueryTool::EXACT_STRING_OPS, 'level' => ['collection']],
        'name' => ['kind' => 'string', 'column' => 'Collection.name', 'level' => ['collection']],
        'type' => ['kind' => 'string', 'column' => 'Collection.type', 'level' => ['collection']],
        'description' => ['kind' => 'string', 'column' => 'Collection.description', 'nullable' => 'Collection.description', 'level' => ['collection']],
        'distribution' => ['kind' => 'int', 'column' => 'Collection.distribution', 'level' => ['collection']],
        'org_id' => ['kind' => 'int', 'column' => 'Collection.org_id', 'level' => ['collection']],
        'orgc_id' => ['kind' => 'int', 'column' => 'Collection.orgc_id', 'level' => ['collection']],
        'org' => [
            'kind' => 'string', 'column' => ['Orgc.name', 'Orgc.uuid'], 'lower' => true, 'via' => ['Orgc', 'Collection.orgc_id'],
            'ops' => ComplexQueryTool::EXACT_STRING_OPS, 'level' => ['collection'],
        ],
        'user_id' => ['kind' => 'int', 'column' => 'Collection.user_id', 'level' => ['collection']],
        'created' => ['kind' => 'datetime', 'column' => 'Collection.created', 'local' => true, 'level' => ['collection']],
        'modified' => ['kind' => 'datetime', 'column' => 'Collection.modified', 'local' => true, 'level' => ['collection']],
        'locked' => ['kind' => 'bool', 'column' => 'Collection.locked', 'level' => ['collection']],
        'published' => ['kind' => 'bool', 'column' => 'Collection.published', 'level' => ['collection']],
        'last_published' => [
            'kind' => 'datetime', 'column' => 'Collection.last_published', 'local' => true,
            'nullable' => 'Collection.last_published', 'level' => ['collection'],
        ],
        'analysis' => ['kind' => 'int', 'column' => 'Collection.analysis', 'level' => ['collection']],
        'element_type' => [
            'kind' => 'string', 'column' => 'CollectionElement.element_type', 'via' => ['CollectionElement', 'Collection.id', 'collection_id'],
            'ops' => ComplexQueryTool::EXACT_STRING_OPS, 'level' => ['collection_element'],
        ],
        'element_uuid' => [
            'kind' => 'string', 'column' => 'CollectionElement.element_uuid', 'lower' => 'value',
            'via' => ['CollectionElement', 'Collection.id', 'collection_id'],
            'ops' => ComplexQueryTool::EXACT_STRING_OPS, 'level' => ['collection_element'],
        ],
        'element_sha256' => [
            'kind' => 'string', 'column' => 'CollectionElement.element_sha256', 'lower' => 'value',
            'via' => ['CollectionElement', 'Collection.id', 'collection_id'],
            'ops' => ComplexQueryTool::EXACT_STRING_OPS, 'level' => ['collection_element'],
        ],
        'element_description' => [
            'kind' => 'string', 'column' => 'CollectionElement.description', 'via' => ['CollectionElement', 'Collection.id', 'collection_id'],
            'level' => ['collection_element'],
        ],
    ];

    const REST_SEARCH_ORDER_FIELDS = [
        'Collection' => ['id', 'name', 'type', 'created', 'modified', 'distribution'],
    ];

    // each row carries all of its elements
    const REST_SEARCH_CHUNK = 100;

    public $validFormats = [
        'json' => ['json', 'JsonExport', 'json'],
        'count' => ['txt', 'CountExport', 'txt'],
    ];

    public $current_user = null;

    /** Set while a publish, or a capture from another instance, writes the published state. */
    private $writingPublishState = false;

    /** @var array|null withheldCollections(), read once for a request from another instance */
    private $servedWithheld = null;

    public $validate = [
        'uuid' => [
            'rule' => 'uuid',
            'message' => 'Please provide a valid RFC 4122 UUID',
        ],
        'name' => [
            'notBlank' => [
                'rule' => 'notBlank',
                'required' => 'create',
                'message' => 'A collection needs a name.',
            ],
            'maxLength' => [
                'rule' => ['maxLength', 191],
                'message' => 'A collection name holds at most 191 characters.',
            ],
        ],
        'type' => [
            'rule' => ['inList', self::VALID_TYPES],
            'required' => 'create',
            'message' => 'Invalid collection type.',
        ],
        'distribution' => [
            'rule' => ['inList', [0, 1, 2, 3, 4]],
            'required' => 'create',
            'message' => 'Invalid distribution level.',
        ],
        'analysis' => [
            'rule' => ['inList', self::ANALYSIS_LEVELS],
            'allowEmpty' => true,
            'message' => 'Invalid analysis level.',
        ],
    ];

    /**
     * @return array Each of VALID_TYPES => its label
     */
    public static function typeLabels()
    {
        $labels = [
            'campaign' => __('Campaign'),
            'intrusion_set' => __('Intrusion set'),
            'named_threat' => __('Named threat'),
            'research' => __('Research'),
            'other' => __('Other'),
        ];
        $out = [];
        foreach (self::VALID_TYPES as $type) {
            $out[$type] = $labels[$type] ?? ucfirst(str_replace('_', ' ', $type));
        }
        return $out;
    }

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
            // A locally created collection is never locked; only the sync-capture path
            // (running as a perm_sync user) may set locked=1 to mark a synced-in original.
            // Force it to 0 for everyone else so a web user cannot self-set locked via
            // mass assignment (mirrors the perm_sync exemption on orgc_id above).
            if (empty($this->current_user['Role']['perm_sync'])) {
                $this->data['Collection']['locked'] = 0;
            }
        }
        // A partial update that leaves the distribution alone keeps the group
        if (isset($this->data['Collection']['distribution']) || empty($this->id)) {
            if (($this->data['Collection']['distribution'] ?? null) != 4) {
                $this->data['Collection']['sharing_group_id'] = null;
            }
        }
        return true;
    }

    /**
     * A local save leaves the collection with changes partners do not have
     * yet; only a publish or a capture from another instance says otherwise.
     */
    public function beforeSave($options = array())
    {
        if (!$this->writingPublishState) {
            $this->data['Collection']['published'] = false;
            unset($this->data['Collection']['last_published']);
        }
        return true;
    }

    public function afterDelete()
    {
        ClassRegistry::init('CollectionElementRemoval')->deleteAll(
            ['CollectionElementRemoval.collection_id' => $this->id],
            false
        );
    }

    /**
     * @param array $collection Unwrapped; reads distribution and published
     * @return bool Whether partners are kept from it: shared beyond its
     *              organisation and not published since its last change
     */
    public static function isWithheld(array $collection)
    {
        return (int)($collection['distribution'] ?? 0) !== 0 && empty($collection['published']);
    }

    /**
     * @return array Conditions leaving withheld collections out
     */
    public static function releasedConditions()
    {
        return ['OR' => [['Collection.distribution' => 0], ['Collection.published' => true]]];
    }

    /**
     * @return array Conditions leaving withheld collections in alone
     */
    public static function withheldConditions()
    {
        return ['Collection.distribution !=' => 0, 'Collection.published' => false];
    }

    /**
     * Another 3.0 instance is served an unpublished collection as an
     * unpublished event, and pulls published ones only. A MISP older than
     * 3.0 has no publish step to tell them apart.
     *
     * @return array Conditions on what the requester is served
     */
    public static function servedConditions()
    {
        return SyncTool::requesterBelow30() ? self::releasedConditions() : [];
    }

    /**
     * As for events: the edit right and perm_publish.
     *
     * @param array $user
     * @param array $collection Unwrapped; reads org_id, orgc_id and user_id
     * @return bool
     */
    public function canPublish(array $user, array $collection)
    {
        if (!empty($user['Role']['perm_site_admin'])) {
            return true;
        }
        return !empty($user['Role']['perm_publish']) && $this->canModify($user, $collection);
    }

    /**
     * Release a collection: it, its members and what its organisation drew
     * on it reach partners together on the next push or pull.
     *
     * @param int $id
     * @param int|null $analysis One of ANALYSIS_LEVELS, or null to keep it
     * @return bool
     */
    public function publish($id, $analysis = null)
    {
        $now = date('Y-m-d H:i:s');
        $record = ['id' => (int)$id, 'published' => true, 'last_published' => $now, 'modified' => $now];
        if ($analysis !== null) {
            $record['analysis'] = (int)$analysis;
        }
        $this->writingPublishState = true;
        try {
            $this->id = (int)$id;
            $saved = $this->save(['Collection' => $record], ['fieldList' => array_keys($record)]);
        } finally {
            $this->writingPublishState = false;
        }
        if (!$saved) {
            return false;
        }
        $this->markReleased((int)$id);
        return true;
    }

    /**
     * Withdraw it from partners until it is published again: they keep the
     * version they last received, and its members stay as they were released.
     *
     * @param int $id
     * @return bool
     */
    public function unpublish($id)
    {
        // Nothing in it changed: modified stays, so partners need not refetch it
        $modified = $this->field('modified', ['Collection.id' => (int)$id]);
        $record = ['id' => (int)$id, 'published' => false, 'modified' => $modified];
        $this->writingPublishState = true;
        try {
            $this->id = (int)$id;
            return (bool)$this->save(['Collection' => $record], ['fieldList' => ['published', 'modified']]);
        } finally {
            $this->writingPublishState = false;
        }
    }

    /**
     * Say how far the investigation went. A change partners do not have:
     * a shared collection waits for its next publish.
     *
     * @param int $id
     * @param int $analysis One of ANALYSIS_LEVELS
     * @return bool
     */
    public function setAnalysis($id, $analysis)
    {
        $this->id = (int)$id;
        $record = ['id' => (int)$id, 'analysis' => (int)$analysis, 'modified' => date('Y-m-d H:i:s')];
        return (bool)$this->save(['Collection' => $record], ['fieldList' => ['analysis', 'modified', 'published']]);
    }

    /**
     * Send a published collection to the servers collections are pushed to,
     * with what its organisation drew on it, as an event's publish does.
     *
     * @param array $user Who published it
     * @param int $id
     * @return mixed The job's process id, or the number of servers reached
     */
    public function publishRouter(array $user, $id)
    {
        if (Configure::read('MISP.background_jobs')) {
            /** @var Job $Job */
            $Job = ClassRegistry::init('Job');
            $jobId = $Job->createJob($user, Job::WORKER_PRIO, 'publish_collection', 'Collection ID: ' . (int)$id, 'Publishing.');
            return $this->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::PRIO_QUEUE,
                BackgroundJobsTool::CMD_EVENT,
                ['publish_collection', (int)$id, $jobId, $user['id']],
                true,
                $jobId
            );
        }
        return $this->uploadToServers($user, $id);
    }

    /**
     * @param array $user
     * @param int $id
     * @return int How many servers took the collection
     */
    public function uploadToServers(array $user, $id)
    {
        $found = $this->find('first', [
            'recursive' => -1,
            'contain' => ['Orgc'],
            'conditions' => ['Collection.id' => (int)$id],
        ]);
        if (empty($found) || empty($found['Collection']['published'])) {
            return 0;
        }
        $Server = ClassRegistry::init('Server');
        $servers = $Server->find('all', [
            'conditions' => ['Server.push' => true, 'Server.push_collections' => true],
            'order' => ['Server.priority ASC', 'Server.id ASC'],
        ]);
        if (empty($servers)) {
            return 0;
        }
        $released = $this->releasedAnalystData($found);
        $AnalystData = ClassRegistry::init('AnalystData');
        $reached = 0;
        foreach ($servers as $server) {
            try {
                $serverSync = new ServerSyncTool($server, $this->setupSyncRequest($server));
                if (!$serverSync->isSupported(ServerSyncTool::PERM_SYNC)) {
                    continue;
                }
                if ($this->push($user, $serverSync, (int)$id) > 0) {
                    $reached++;
                }
                if (!empty($released)) {
                    $AnalystData->push($user, $serverSync, $released);
                }
            } catch (Exception $e) {
                $this->logException("Could not push collection #$id to server #{$server['Server']['id']}.", $e);
            }
        }
        return $reached;
    }

    /**
     * The graphs its organisation drew on it and the relationships between
     * its members: what withheldScopesFor() kept back until the publish.
     *
     * @param array $found The collection, with its Orgc
     * @return array [type => conditions] for AnalystData::push(), empty for none
     */
    private function releasedAnalystData(array $found)
    {
        $orgcUuid = $found['Orgc']['uuid'] ?? null;
        if (empty($orgcUuid)) {
            return [];
        }
        $collection = $found['Collection'];
        $graphIds = ClassRegistry::init('Graph')->find('column', [
            'fields' => ['Graph.id'],
            'conditions' => [
                'Graph.object_type' => 'Collection',
                'Graph.object_uuid' => self::spellings($collection['uuid']),
                'Graph.orgc_uuid' => $orgcUuid,
                'Graph.locked' => false,
            ],
            'callbacks' => false,
        ]);
        $members = $this->memberAddresses([(int)$collection['id']])[(int)$collection['id']] ?? [];
        $members[strtolower($collection['uuid'])] = true;
        $relationshipIds = array_column($this->relationshipsBetween($orgcUuid, $members), 'id');
        $released = [];
        if (!empty($graphIds)) {
            $released['Graph'] = ['Graph.id' => array_values($graphIds)];
        }
        if (!empty($relationshipIds)) {
            $released['Relationship'] = ['Relationship.id' => $relationshipIds];
        }
        return $released;
    }

    /**
     * Partners hold every member now, and none of those taken out.
     *
     * @param int $id
     * @param array|null $types These member types only
     */
    private function markReleased($id, ?array $types = null)
    {
        $elements = ['CollectionElement.collection_id' => $id, 'CollectionElement.published' => false];
        $removals = ['CollectionElementRemoval.collection_id' => $id];
        if ($types !== null) {
            $elements['CollectionElement.element_type'] = $types;
            $removals['CollectionElementRemoval.element_type'] = $types;
        }
        $this->CollectionElement->updateAll(['CollectionElement.published' => true], $elements);
        ClassRegistry::init('CollectionElementRemoval')->deleteAll($removals, false);
    }

    /**
     * Members added and removed since each collection was last published.
     *
     * @param array $ids
     * @return array id => {added, removed}
     */
    public function pendingChanges(array $ids)
    {
        $ids = array_values(array_unique(array_map('intval', $ids)));
        $changes = array_fill_keys($ids, ['added' => 0, 'removed' => 0]);
        if (empty($ids)) {
            return $changes;
        }
        $added = $this->CollectionElement->find('all', [
            'recursive' => -1,
            'fields' => ['CollectionElement.collection_id', 'COUNT(*) AS n'],
            'conditions' => ['CollectionElement.collection_id' => $ids, 'CollectionElement.published' => false],
            'group' => ['CollectionElement.collection_id'],
        ]);
        foreach ($added as $row) {
            $changes[(int)$row['CollectionElement']['collection_id']]['added'] = (int)$row[0]['n'];
        }
        $Removal = ClassRegistry::init('CollectionElementRemoval');
        $removed = $Removal->find('all', [
            'recursive' => -1,
            'fields' => ['CollectionElementRemoval.collection_id', 'COUNT(*) AS n'],
            'conditions' => ['CollectionElementRemoval.collection_id' => $ids],
            'group' => ['CollectionElementRemoval.collection_id'],
        ]);
        foreach ($removed as $row) {
            $changes[(int)$row['CollectionElementRemoval']['collection_id']]['removed'] = (int)$row[0]['n'];
        }
        return $changes;
    }

    /**
     * What a publish releases: members added and removed, graphs saved on it
     * and relationships drawn between its members since it was last
     * published, by its organisation. Each list holds at most REVIEW_LIMIT
     * entries; its count says how many there are.
     *
     * Members and the ends of relationships are {type, address, label, meta},
     * labelled as the user sees them (label null when they cannot), members
     * also with `at` (added or removed) and `user_id`.
     *
     * @param array $user
     * @param array $collection Unwrapped, with Orgc
     * @return array {added, removed, graphs, relationships}, each {count, items}
     */
    public function publishReview(array $user, array $collection)
    {
        $id = (int)$collection['id'];
        $since = $collection['last_published'] ?? null;
        $review = [];

        $added = $this->CollectionElement->find('all', [
            'recursive' => -1,
            'conditions' => ['CollectionElement.collection_id' => $id, 'CollectionElement.published' => false],
            'order' => ['CollectionElement.id' => 'DESC'],
            'limit' => self::REVIEW_LIMIT,
        ]);
        $review['added'] = [
            'count' => $this->pendingChanges([$id])[$id]['added'],
            'items' => array_map(function ($row) {
                return self::reviewEnd($row['CollectionElement'], 'element') + [
                    'at' => $row['CollectionElement']['created'],
                    'user_id' => $row['CollectionElement']['user_id'],
                    'text' => $row['CollectionElement']['element_value'] ?? null,
                ];
            }, $added),
        ];
        list($review['narrower'], $review['narrower_origins']) = $this->narrowerReview($user, $collection);

        $Removal = ClassRegistry::init('CollectionElementRemoval');
        $removedConditions = ['CollectionElementRemoval.collection_id' => $id];
        $removed = $Removal->find('all', [
            'recursive' => -1,
            'conditions' => $removedConditions,
            'order' => ['CollectionElementRemoval.id' => 'DESC'],
            'limit' => self::REVIEW_LIMIT,
        ]);
        $review['removed'] = [
            'count' => $Removal->find('count', ['recursive' => -1, 'conditions' => $removedConditions]),
            'items' => array_map(function ($row) {
                return self::reviewEnd($row['CollectionElementRemoval'], 'element') + [
                    'at' => $row['CollectionElementRemoval']['created'],
                    'user_id' => $row['CollectionElementRemoval']['user_id'],
                ];
            }, $removed),
        ];

        $orgcUuid = $collection['Orgc']['uuid'] ?? null;
        $review['graphs'] = ['count' => 0, 'items' => []];
        $review['relationships'] = ['count' => 0, 'items' => []];
        if (empty($orgcUuid)) {
            return $this->labelReview($user, $collection, $review);
        }
        $changedSince = $since === null ? [] : ['modified >' => $since];

        $Graph = ClassRegistry::init('Graph');
        $graphConditions = [
            'Graph.object_type' => 'Collection',
            'Graph.object_uuid' => self::spellings($collection['uuid']),
            'Graph.orgc_uuid' => $orgcUuid,
            'Graph.locked' => false,
            'Graph.distribution !=' => 0,
        ];
        foreach ($changedSince as $field => $value) {
            $graphConditions['Graph.' . $field] = $value;
        }
        $review['graphs'] = [
            'count' => $Graph->find('count', ['recursive' => -1, 'conditions' => $graphConditions, 'callbacks' => false]),
            'items' => $Graph->summaries($user, $graphConditions, ['counts' => false, 'targets' => false, 'limit' => self::REVIEW_LIMIT]),
        ];

        $members = $this->memberAddresses([$id])[$id] ?? [];
        $members[strtolower($collection['uuid'])] = true;
        $drawn = $this->relationshipsBetween($orgcUuid, $members, $changedSince + ['distribution !=' => 0]);
        $review['relationships'] = [
            'count' => count($drawn),
            'items' => array_map(function ($relationship) {
                return [
                    'uuid' => $relationship['uuid'],
                    'relationship_type' => $relationship['relationship_type'],
                    'modified' => $relationship['modified'],
                    'from' => self::reviewEnd($relationship, 'object'),
                    'to' => self::reviewEnd($relationship, 'related_object'),
                ];
            }, array_slice($drawn, 0, self::REVIEW_LIMIT)),
        ];
        return $this->labelReview($user, $collection, $review);
    }

    /**
     * Of the members added since the last publish, the values every
     * attribute the user can see holding them shares more narrowly than the
     * collection, and the members whose origin asked about such a value.
     *
     * @param array $user
     * @param array $collection Unwrapped
     * @return array [values {count, items: [{type, address, label, meta}]},
     *      origins {count, items: [{type, address, text, asked}]}]
     */
    private function narrowerReview(array $user, array $collection)
    {
        $texts = [];
        $asked = [];
        $lastId = 0;
        do {
            $rows = $this->CollectionElement->find('all', [
                'recursive' => -1,
                'fields' => [
                    'CollectionElement.id', 'CollectionElement.element_type', 'CollectionElement.element_uuid',
                    'CollectionElement.element_sha256', 'CollectionElement.element_value', 'CollectionElement.origin',
                ],
                'conditions' => [
                    'CollectionElement.collection_id' => (int)$collection['id'],
                    'CollectionElement.published' => false,
                    'CollectionElement.id >' => $lastId,
                ],
                'order' => ['CollectionElement.id' => 'ASC'],
                'limit' => 1000,
            ]);
            foreach ($rows as $row) {
                $element = $row['CollectionElement'];
                $lastId = (int)$element['id'];
                if ($element['element_type'] === 'AttributeValue') {
                    $texts[strtolower($element['element_sha256'])] = $element['element_value'];
                }
                $origin = CollectionElement::decodedOrigin($element['origin'] ?? null);
                if ($origin !== null) {
                    $asked[] = self::reviewEnd($element, 'element') + [
                        'text' => $element['element_value'] ?? null,
                        'asked' => $origin['value'],
                    ];
                }
            }
        } while (count($rows) === 1000);
        $hexes = array_map('strval', array_keys($texts));
        foreach ($asked as $member) {
            $hexes[] = CollectionElement::valueSha256($member['asked']);
        }
        $narrower = $this->CollectionElement->narrowerValues($user, (int)$collection['distribution'], array_values(array_unique($hexes)));
        $values = array_values(array_filter($narrower, function ($hex) use ($texts) {
            return isset($texts[$hex]);
        }));
        $flipped = array_flip($narrower);
        $origins = array_values(array_filter($asked, function ($member) use ($flipped) {
            return isset($flipped[CollectionElement::valueSha256($member['asked'])]);
        }));
        return [
            [
                'count' => count($values),
                'items' => array_map(function ($hex) use ($texts) {
                    return ['type' => 'AttributeValue', 'address' => $hex, 'label' => $texts[$hex], 'meta' => []];
                }, array_slice($values, 0, self::REVIEW_LIMIT)),
            ],
            ['count' => count($origins), 'items' => array_slice($origins, 0, self::REVIEW_LIMIT)],
        ];
    }

    /**
     * @param array $row An element, a removal or a relationship, unwrapped
     * @param string $end 'element', 'object' or 'related_object'
     * @return array {type, address}
     */
    private static function reviewEnd(array $row, $end)
    {
        $type = $row[$end . '_type'] ?? null;
        $address = $row[AnalystData::addressColumn($type, $end)] ?? null;
        return ['type' => $type, 'address' => is_string($address) ? strtolower($address) : null];
    }

    /**
     * Label the members and relationship ends of a review, in one pass.
     *
     * @param array $user
     * @param array $collection
     * @param array $review
     * @return array
     */
    private function labelReview(array $user, array $collection, array $review)
    {
        $targets = [];
        $collect = function (array $end) use (&$targets) {
            if ($end['address'] !== null && $end['type'] !== 'Collection') {
                $targets[$end['type'] . ':' . $end['address']] = ['type' => $end['type'], 'address' => $end['address']];
            }
        };
        $memberKinds = array_values(array_filter(['added', 'removed', 'narrower_origins'], function ($kind) use ($review) {
            return isset($review[$kind]);
        }));
        foreach ($memberKinds as $kind) {
            array_map($collect, $review[$kind]['items']);
        }
        foreach ($review['relationships']['items'] as $relationship) {
            $collect($relationship['from']);
            $collect($relationship['to']);
        }
        $standalone = [];
        foreach ($targets as $key => $target) {
            if ($target['type'] === 'StandaloneObject') {
                $standalone[] = $target['address'];
                unset($targets[$key]);
            }
        }
        $described = empty($targets) ? [] : ClassRegistry::init('AnalystData')->describeTargets($user, array_values($targets));
        $byAddress = [];
        foreach ($described as $address => $description) {
            $byAddress[strtolower((string)$address)] = $description;
        }
        $records = empty($standalone) ? [] : ClassRegistry::init('StandaloneObject')->records($standalone);
        foreach ($records as $uuid => $record) {
            $byAddress[$uuid] = ['label' => $record['name'], 'meta' => ['attributes' => count($record['attributes'])]];
        }
        $label = function (array $end) use ($byAddress, $collection) {
            if ($end['type'] === 'Collection' && $end['address'] === strtolower($collection['uuid'])) {
                return $end + ['label' => $collection['name'], 'meta' => []];
            }
            $found = $byAddress[$end['address']] ?? null;
            $text = $end['text'] ?? null;
            unset($end['text']);
            return $end + ['label' => $found['label'] ?? $text, 'meta' => $found['meta'] ?? []];
        };
        foreach ($memberKinds as $kind) {
            foreach ($review[$kind]['items'] as $i => $item) {
                $review[$kind]['items'][$i] = $label($item);
            }
        }
        foreach ($review['relationships']['items'] as $i => $relationship) {
            $review['relationships']['items'][$i]['from'] = $label($relationship['from']);
            $review['relationships']['items'][$i]['to'] = $label($relationship['to']);
        }
        return $review;
    }

    /**
     * What may go along with the collection shared as $to: the graphs its
     * organisation keeps on it and the relationships it drew between its
     * members, those the user may change that reach fewer than $to. One that
     * already reached fewer than the collection is not ticked.
     *
     * @param array $user
     * @param array $collection Unwrapped, as stored before the change
     * @param array $to [distribution, sharing_group_id]
     * @return array {graphs, relationships}, each {count, items}
     */
    public function shareAlong(array $user, array $collection, array $to)
    {
        $rows = $this->shareAlongRows($user, $collection, $to);
        $from = [$collection['distribution'], $collection['sharing_group_id']];
        $groups = ClassRegistry::init('SharingGroup')->fetchAllAuthorised($user, 'name', 1);
        $item = function (array $row) use ($from, $groups) {
            $group = (int)$row['distribution'] === 4 ? (int)$row['sharing_group_id'] : null;
            return [
                'uuid' => $row['uuid'],
                'distribution' => (int)$row['distribution'],
                'sharing_group' => $group === null ? null : ['id' => $group, 'name' => $groups[$group] ?? null],
                'ticked' => !DistributionLevel::reachesFewer([$row['distribution'], $row['sharing_group_id']], $from),
            ];
        };
        $graphs = array_map(function ($row) use ($item) {
            return $item($row) + ['name' => $row['name'], 'node_count' => (int)$row['node_count']];
        }, $rows['graphs']);
        $relationships = array_map(function ($row) use ($item) {
            return $item($row) + [
                'relationship_type' => $row['relationship_type'],
                'from' => self::reviewEnd($row, 'object'),
                'to' => self::reviewEnd($row, 'related_object'),
            ];
        }, $rows['relationships']);
        $labelled = $this->labelReview($user, $collection, [
            'added' => ['items' => []],
            'removed' => ['items' => []],
            'relationships' => ['items' => $relationships],
        ]);
        return [
            'graphs' => ['count' => count($graphs), 'items' => $graphs],
            'relationships' => ['count' => count($relationships), 'items' => $labelled['relationships']['items']],
        ];
    }

    /**
     * Shares as $to what shareAlong() lists and $picked names.
     *
     * @param array $user
     * @param array $collection Unwrapped, as stored before the change
     * @param array $to [distribution, sharing_group_id]
     * @param array $picked {graphs: [uuid], relationships: [uuid]}
     * @return array {graphs: int, relationships: int, failed: [{type, uuid, errors}]}
     */
    public function applyShareAlong(array $user, array $collection, array $to, array $picked)
    {
        $done = ['graphs' => 0, 'relationships' => 0, 'failed' => []];
        $rows = $this->shareAlongRows($user, $collection, $to);
        $sharing = [
            'distribution' => (string)(int)$to[0],
            'sharing_group_id' => (int)$to[0] === 4 ? (int)$to[1] : null,
        ];
        foreach (['graphs' => 'Graph', 'relationships' => 'Relationship'] as $kind => $modelName) {
            $wanted = [];
            foreach ((array)($picked[$kind] ?? []) as $uuid) {
                if (is_string($uuid)) {
                    $wanted[strtolower($uuid)] = true;
                }
            }
            if (empty($wanted)) {
                continue;
            }
            $Model = ClassRegistry::init($modelName);
            $Model->current_user = $user;
            foreach ($rows[$kind] as $row) {
                if (!isset($wanted[strtolower($row['uuid'])])) {
                    continue;
                }
                $Model->create(false);
                $saved = $Model->save(
                    [$modelName => ['id' => (int)$row['id'], 'modified' => date('Y-m-d H:i:s')] + $sharing],
                    ['fieldList' => ['distribution', 'sharing_group_id', 'modified']]
                );
                if ($saved) {
                    $done[$kind]++;
                } else {
                    $done['failed'][] = ['type' => $modelName, 'uuid' => $row['uuid'], 'errors' => $Model->validationErrors];
                }
            }
        }
        return $done;
    }

    /**
     * @param array $user
     * @param array $collection Unwrapped
     * @param array $to [distribution, sharing_group_id]
     * @return array {graphs: [row], relationships: [row]}, unwrapped
     */
    private function shareAlongRows(array $user, array $collection, array $to)
    {
        $rows = ['graphs' => [], 'relationships' => []];
        $orgcUuid = $collection['Orgc']['uuid'] ?? $this->Orgc->field('uuid', ['Orgc.id' => $collection['orgc_id']]);
        $mayChange = !empty($user['Role']['perm_site_admin'])
            || (!empty($user['Role']['perm_add']) && !empty($user['Role']['perm_analyst_data']));
        if (empty($orgcUuid) || !$mayChange) {
            return $rows;
        }
        $fewer = function (array $row) use ($to) {
            return DistributionLevel::reachesFewer([$row['distribution'], $row['sharing_group_id']], $to);
        };
        $Graph = ClassRegistry::init('Graph');
        $graphs = $Graph->find('all', [
            'recursive' => -1,
            'callbacks' => false,
            'fields' => ['id', 'uuid', 'name', 'node_count', 'distribution', 'sharing_group_id', 'orgc_uuid'],
            'conditions' => [
                'Graph.object_type' => 'Collection',
                'Graph.object_uuid' => self::spellings($collection['uuid']),
                'Graph.orgc_uuid' => $orgcUuid,
                'Graph.locked' => false,
            ],
            'order' => ['Graph.modified' => 'DESC'],
        ]);
        foreach ($graphs as $graph) {
            if ($fewer($graph['Graph']) && $Graph->canEditAnalystData($user, $graph, 'Graph')) {
                $rows['graphs'][] = $graph['Graph'];
            }
        }
        $Relationship = ClassRegistry::init('Relationship');
        $members = $this->memberAddresses([(int)$collection['id']])[(int)$collection['id']] ?? [];
        $members[strtolower($collection['uuid'])] = true;
        foreach ($this->relationshipsBetween($orgcUuid, $members) as $relationship) {
            if ($fewer($relationship) && $Relationship->canEditAnalystData($user, ['Relationship' => $relationship], 'Relationship')) {
                $rows['relationships'][] = $relationship;
            }
        }
        return $rows;
    }

    /**
     * Relationships an organisation drew here whose both ends are in
     * $addresses. Read by their first end, one indexed lookup per chunk of
     * addresses and address column.
     *
     * @param string $orgcUuid
     * @param array $addresses address => true, lowercased
     * @param array $changedSince Extra conditions on the relationship, unqualified
     * @return array Relationship rows, unwrapped, newest first
     */
    private function relationshipsBetween($orgcUuid, array $addresses, array $changedSince = [])
    {
        $Relationship = ClassRegistry::init('Relationship');
        $byColumn = ['object_uuid' => [], 'object_sha256' => []];
        foreach (array_keys($addresses) as $address) {
            $address = (string)$address;
            $byColumn[strlen($address) === 64 ? 'object_sha256' : 'object_uuid'][] = $address;
        }
        $found = [];
        foreach ($byColumn as $column => $values) {
            foreach (array_chunk($values, 1000) as $chunk) {
                $conditions = [
                    'Relationship.' . $column => $column === 'object_uuid' ? self::spellingsOf($chunk) : $chunk,
                    'Relationship.orgc_uuid' => $orgcUuid,
                    'Relationship.locked' => false,
                ];
                foreach ($changedSince as $field => $value) {
                    $conditions['Relationship.' . $field] = $value;
                }
                $rows = $Relationship->find('all', [
                    'recursive' => -1,
                    'conditions' => $conditions,
                    'callbacks' => false,
                ]);
                foreach ($rows as $row) {
                    $relationship = $row['Relationship'];
                    $to = self::endAddress($relationship, 'related_object');
                    if ($to !== null && isset($addresses[$to])) {
                        $found[$relationship['id']] = $relationship;
                    }
                }
            }
        }
        usort($found, function ($a, $b) {
            return strcmp((string)$b['modified'], (string)$a['modified']);
        });
        return array_values($found);
    }

    /**
     * Each collection's member addresses, lowercased.
     *
     * @param array $ids
     * @return array id => [address => true]
     */
    private function memberAddresses(array $ids)
    {
        $members = [];
        foreach (array_chunk(array_map('intval', $ids), 500) as $chunk) {
            $rows = $this->CollectionElement->find('all', [
                'recursive' => -1,
                'fields' => [
                    'CollectionElement.collection_id',
                    'CollectionElement.element_uuid',
                    'CollectionElement.element_sha256',
                ],
                'conditions' => ['CollectionElement.collection_id' => $chunk],
            ]);
            foreach ($rows as $row) {
                $element = $row['CollectionElement'];
                $address = $element['element_sha256'] ?: $element['element_uuid'];
                if (is_string($address) && $address !== '') {
                    $members[(int)$element['collection_id']][strtolower($address)] = true;
                }
            }
        }
        return $members;
    }

    /**
     * The shared collections not published since their last change.
     *
     * @return array [{id, uuid, orgc_uuid}], lowercased
     */
    public function withheldCollections()
    {
        $rows = $this->find('all', [
            'recursive' => -1,
            'contain' => ['Orgc'],
            'fields' => ['Collection.id', 'Collection.uuid', 'Orgc.uuid'],
            'conditions' => self::withheldConditions(),
        ]);
        $collections = [];
        foreach ($rows as $row) {
            $collections[] = [
                'id' => (int)$row['Collection']['id'],
                'uuid' => strtolower($row['Collection']['uuid']),
                'orgc_uuid' => strtolower((string)($row['Orgc']['uuid'] ?? '')),
            ];
        }
        return $collections;
    }

    /**
     * What withheld collections keep back of these relationships: per
     * collection, its organisation and which of the addresses they name it
     * holds, its own included. Only the ends of these rows are looked up,
     * one indexed lookup per address column and chunk, so the cost follows
     * the rows, not the size of the collections.
     *
     * @param array $relationships Unwrapped
     * @param array|null $collections withheldCollections()'s, when read already
     * @return array [{uuid, orgc_uuid, members: [address => true]}]
     */
    public function withheldScopesFor(array $relationships, $collections = null)
    {
        $collections = $collections ?? $this->withheldCollections();
        if (empty($collections)) {
            return [];
        }
        $orgs = [];
        foreach ($collections as $collection) {
            $orgs[$collection['orgc_uuid']] = true;
        }
        $wanted = ['element_uuid' => [], 'element_sha256' => []];
        foreach ($relationships as $row) {
            $orgc = strtolower((string)($row['orgc_uuid'] ?? ''));
            if ($orgc === '' || !isset($orgs[$orgc])) {
                continue;
            }
            foreach (['object', 'related_object'] as $end) {
                $hex = $row[$end . '_sha256'] ?? null;
                $uuid = $row[$end . '_uuid'] ?? null;
                if (is_string($hex) && trim($hex) !== '') {
                    $wanted['element_sha256'][strtolower(trim($hex))] = true;
                } elseif (is_string($uuid) && trim($uuid) !== '') {
                    $wanted['element_uuid'][strtolower(trim($uuid))] = true;
                }
            }
        }
        $ids = array_column($collections, 'id');
        $members = [];
        foreach ($wanted as $column => $addresses) {
            // Separate statements: an OR across the two columns loses both indexes
            foreach (array_chunk(array_map('strval', array_keys($addresses)), 500) as $chunk) {
                $rows = $this->CollectionElement->find('all', [
                    'recursive' => -1,
                    'fields' => ['CollectionElement.collection_id', 'CollectionElement.' . $column],
                    'conditions' => ['CollectionElement.' . $column => $chunk, 'CollectionElement.collection_id' => $ids],
                ]);
                foreach ($rows as $row) {
                    $members[(int)$row['CollectionElement']['collection_id']][strtolower($row['CollectionElement'][$column])] = true;
                }
            }
        }
        $scopes = [];
        foreach ($collections as $collection) {
            $scopes[] = [
                'uuid' => $collection['uuid'],
                'orgc_uuid' => $collection['orgc_uuid'],
                'members' => ($members[$collection['id']] ?? []) + [$collection['uuid'] => true],
            ];
        }
        return $scopes;
    }

    /**
     * @param array $rows Relationship rows, wrapped or not
     * @return array The same, unwrapped
     */
    private static function relationshipRows(array $rows)
    {
        return array_map(function ($row) {
            return $row['Relationship'] ?? $row;
        }, array_values($rows));
    }

    /**
     * A graph on a withheld collection, or a relationship between its
     * members, waits for the collection's publish when the collection's
     * organisation made it. Notes and opinions never wait.
     *
     * @param array $scopes withheldScopesFor()'s
     * @param string $type
     * @param array $row Unwrapped analyst data
     * @return bool
     */
    public static function holdsBack(array $scopes, $type, array $row)
    {
        if ($type !== 'Graph' && $type !== 'Relationship') {
            return false;
        }
        $orgc = strtolower((string)($row['orgc_uuid'] ?? ''));
        foreach ($scopes as $scope) {
            if ($orgc === '' || $scope['orgc_uuid'] !== $orgc) {
                continue;
            }
            if ($type === 'Graph') {
                if (($row['object_type'] ?? null) === 'Collection' && strtolower((string)($row['object_uuid'] ?? '')) === $scope['uuid']) {
                    return true;
                }
                continue;
            }
            $from = self::endAddress($row, 'object');
            $to = self::endAddress($row, 'related_object');
            if ($from !== null && $to !== null && isset($scope['members'][$from], $scope['members'][$to])) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param array $byType [type => [[type => row], ...]], as analyst-data sync collects it
     * @return array The same, without what withheld collections keep from partners
     */
    public function withoutHeldBack(array $byType)
    {
        if (empty($byType['Graph']) && empty($byType['Relationship'])) {
            return $byType;
        }
        $scopes = $this->withheldScopesFor(self::relationshipRows($byType['Relationship'] ?? []));
        if (empty($scopes)) {
            return $byType;
        }
        foreach (['Graph', 'Relationship'] as $type) {
            if (empty($byType[$type])) {
                continue;
            }
            $byType[$type] = array_values(array_filter($byType[$type], function ($entry) use ($scopes, $type) {
                return !self::holdsBack($scopes, $type, $entry[$type] ?? $entry);
            }));
        }
        return $byType;
    }

    /**
     * Relationships as another instance receives them inside the records
     * they are attached to.
     *
     * @param array $rows Relationship rows, wrapped or not
     * @return array The same, without those withheld collections hold back
     */
    public function servedRelationships(array $rows)
    {
        if (empty($rows) || !SyncTool::requesterIsMisp()) {
            return $rows;
        }
        if ($this->servedWithheld === null) {
            $this->servedWithheld = $this->withheldCollections();
        }
        if (empty($this->servedWithheld)) {
            return $rows;
        }
        $scopes = $this->withheldScopesFor(self::relationshipRows($rows), $this->servedWithheld);
        return array_values(array_filter($rows, function ($row) use ($scopes) {
            return !self::holdsBack($scopes, 'Relationship', $row['Relationship'] ?? $row);
        }));
    }

    /**
     * A graph or a relationship an organisation drew here changed what
     * partners will receive with these collections of that organisation.
     *
     * @param string $orgcUuid
     * @param array $conditions Which collections
     */
    public function unpublishFor($orgcUuid, array $conditions)
    {
        if (!is_string($orgcUuid) || $orgcUuid === '') {
            return;
        }
        $org = $this->Orgc->find('first', [
            'recursive' => -1,
            'fields' => ['Orgc.id'],
            'conditions' => ['Orgc.uuid' => $orgcUuid],
        ]);
        if (empty($org)) {
            return;
        }
        $this->updateAll(
            ['Collection.published' => false, 'Collection.modified' => "'" . date('Y-m-d H:i:s') . "'"],
            ['AND' => [$conditions, ['Collection.orgc_id' => $org['Orgc']['id'], 'Collection.published' => true]]]
        );
    }

    /**
     * @param array $row A graph or a relationship, unwrapped
     * @return bool Whether it stays on this instance, so partners lack nothing
     */
    private static function staysHere(array $row)
    {
        return isset($row['distribution']) && (string)$row['distribution'] === '0';
    }

    /**
     * A graph saved here on a collection of its organisation changed it.
     *
     * @param array $graph Unwrapped; reads object_type, object_uuid, orgc_uuid, locked and distribution
     */
    public function graphSaved(array $graph)
    {
        if (($graph['object_type'] ?? null) !== 'Collection' || !empty($graph['locked']) || !is_string($graph['object_uuid'] ?? null)) {
            return;
        }
        if (self::staysHere($graph)) {
            return;
        }
        $this->unpublishFor($graph['orgc_uuid'] ?? null, ['Collection.uuid' => self::spellings($graph['object_uuid'])]);
    }

    /**
     * A relationship saved here: the collections of its organisation that
     * hold both of its ends (one end may be the collection) have changed.
     *
     * @param array $relationship Unwrapped
     */
    public function relationshipSaved(array $relationship)
    {
        if (!empty($relationship['locked']) || self::staysHere($relationship)) {
            return;
        }
        $sets = [];
        foreach (['object', 'related_object'] as $end) {
            $type = $relationship[$end . '_type'] ?? null;
            $address = self::endAddress($relationship, $end);
            if ($address === null) {
                return;
            }
            if ($type === 'Collection') {
                $ids = $this->find('list', [
                    'recursive' => -1,
                    'fields' => ['Collection.id', 'Collection.id'],
                    'conditions' => ['Collection.uuid' => self::spellings($address)],
                ]);
            } else {
                $column = AnalystData::addressColumn($type, 'element');
                $ids = $this->CollectionElement->find('list', [
                    'recursive' => -1,
                    'fields' => ['CollectionElement.id', 'CollectionElement.collection_id'],
                    'conditions' => ['CollectionElement.' . $column => $address],
                ]);
            }
            $sets[] = array_flip(array_map('intval', array_values($ids)));
        }
        $both = array_keys(array_intersect_key($sets[0], $sets[1]));
        if (!empty($both)) {
            $this->unpublishFor($relationship['orgc_uuid'] ?? null, ['Collection.id' => $both]);
        }
    }

    /**
     * @param array $row Analyst data, unwrapped
     * @param string $end 'object' or 'related_object'
     * @return string|null The end's uuid or SHA-256, lowercased
     */
    private static function endAddress(array $row, $end)
    {
        foreach (['_sha256', '_uuid'] as $suffix) {
            $address = $row[$end . $suffix] ?? null;
            if (is_string($address) && trim($address) !== '') {
                return strtolower(trim($address));
            }
        }
        return null;
    }

    /**
     * @param string $uuid
     * @return array The spellings a uuid may be stored under
     */
    private static function spellings($uuid)
    {
        return array_values(array_unique([strtolower($uuid), strtoupper($uuid)]));
    }

    /**
     * @param array $uuids
     * @return array
     */
    private static function spellingsOf(array $uuids)
    {
        $all = [];
        foreach ($uuids as $uuid) {
            foreach (self::spellings((string)$uuid) as $spelling) {
                $all[] = $spelling;
            }
        }
        return array_values(array_unique($all));
    }

    public function mayModify($user_id, $collection_id)
    {
        $user = $this->User->getAuthUser($user_id);
        $collection = $this->find('first', [
            'recursive' => -1,
            'conditions' => ['Collection.id' => $collection_id]
        ]);
        return !empty($user) && !empty($collection) && $this->canModify($user, $collection['Collection']);
    }

    /**
     * mayModify() for a collection row already at hand.
     *
     * @param array $user
     * @param array $collection Unwrapped; reads org_id, orgc_id and user_id
     * @return bool
     */
    public function canModify(array $user, array $collection)
    {
        if (!empty($user['Role']['perm_site_admin'])) {
            return true;
        }
        if (empty($user['Role']['perm_modify'])) {
            return false;
        }
        if (!empty($user['Role']['perm_modify_org'])) {
            if ((int)$user['org_id'] === (int)$collection['orgc_id']) {
                return true;
            }
            if (!empty($user['Role']['perm_sync']) && (int)$user['org_id'] === (int)$collection['org_id']) {
                return true;
            }
        }
        return (int)$user['id'] === (int)$collection['user_id'];
    }

    /**
     * Collections as the workspace chooser and the navbar chip show them,
     * newest first.
     *
     * @param array $user
     * @param array $conditions ANDed with what the user may see
     * @param int|null $limit
     * @return array [{id, uuid, name, type, distribution, sharing_group_id,
     *               modified, Orgc: {id, uuid, name}, element_count, published,
     *               last_published, analysis, withheld, changes, _canEdit,
     *               _canPublish}]; `changes` {added, removed} is set on a
     *               withheld collection only
     */
    public function workspaceSummaries(array $user, array $conditions, $limit = null)
    {
        $visible = $this->buildConditions($user);
        $rows = $this->find('all', [
            'recursive' => -1,
            'conditions' => ['AND' => array_values(array_filter([$conditions, $visible]))],
            'fields' => [
                'Collection.id', 'Collection.uuid', 'Collection.name', 'Collection.type',
                'Collection.distribution', 'Collection.sharing_group_id', 'Collection.org_id',
                'Collection.orgc_id', 'Collection.user_id', 'Collection.modified',
                'Collection.published', 'Collection.last_published', 'Collection.analysis',
            ],
            'contain' => ['Orgc', 'SharingGroup'],
            'order' => ['Collection.modified' => 'DESC', 'Collection.id' => 'DESC'],
            'limit' => $limit,
        ]);
        if (empty($rows)) {
            return [];
        }
        $counts = [];
        $grouped = $this->CollectionElement->find('all', [
            'recursive' => -1,
            'fields' => ['CollectionElement.collection_id', 'COUNT(*) AS element_count'],
            'conditions' => ['CollectionElement.collection_id' => array_map('strval', Hash::extract($rows, '{n}.Collection.id'))],
            'group' => ['CollectionElement.collection_id'],
        ]);
        foreach ($grouped as $row) {
            $counts[$row['CollectionElement']['collection_id']] = (int)$row[0]['element_count'];
        }
        $withheld = [];
        foreach ($rows as $row) {
            if (self::isWithheld($row['Collection'])) {
                $withheld[] = (int)$row['Collection']['id'];
            }
        }
        $changes = $this->pendingChanges($withheld);
        $summaries = [];
        foreach ($rows as $row) {
            $collection = $row['Collection'];
            $summaries[] = [
                'id' => (int)$collection['id'],
                'uuid' => strtolower($collection['uuid']),
                'name' => $collection['name'],
                'type' => $collection['type'],
                'distribution' => (int)$collection['distribution'],
                'sharing_group_id' => $collection['sharing_group_id'] === null ? null : (int)$collection['sharing_group_id'],
                'sharing_group' => (int)$collection['distribution'] === 4 && !empty($row['SharingGroup']['id'])
                    ? ['id' => (int)$row['SharingGroup']['id'], 'name' => $row['SharingGroup']['name']] : null,
                'modified' => $collection['modified'],
                'Orgc' => [
                    'id' => (int)($row['Orgc']['id'] ?? $collection['orgc_id']),
                    'uuid' => $row['Orgc']['uuid'] ?? null,
                    'name' => $row['Orgc']['name'] ?? null,
                ],
                'element_count' => $counts[$collection['id']] ?? 0,
                'published' => !empty($collection['published']),
                'last_published' => $collection['last_published'],
                'analysis' => (int)$collection['analysis'],
                'withheld' => self::isWithheld($collection),
                'changes' => $changes[(int)$collection['id']] ?? null,
                '_canEdit' => $this->canModify($user, $collection),
                '_canPublish' => $this->canPublish($user, $collection),
            ];
        }
        return $summaries;
    }

    public function mayView($user_id, $collection_id)
    {
        $user = $this->User->getAuthUser($user_id);
        $collection = $this->find('first', [
            'recursive' => -1,
            'conditions' => ['Collection.id' => $collection_id]
        ]);
        if (empty($user) || empty($collection)) {
            return false;
        }
        if ($user['Role']['perm_site_admin']) {
            return true;
        }
        if ($collection['Collection']['org_id'] == $user['org_id']) {
            return true;
        }
        if (Configure::read('MISP.unpublishedprivate') && self::isWithheld($collection['Collection'])) {
            return false;
        }
        if (in_array($collection['Collection']['distribution'], [1,2,3])) {
            return true;
        }
        if ((int)$collection['Collection']['distribution'] === 4) {
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

    /**
     * @param int|array $user_id A user id, or the user already loaded
     * @return array
     */
    public function buildConditions($user_id)
    {
        $user = is_array($user_id) ? $user_id : $this->User->getAuthUser($user_id);
        $SharingGroup = ClassRegistry::init('SharingGroup');
        $sgids = $SharingGroup->authorizedIds($user);
        $conditions = [];
        if (!$user['Role']['perm_site_admin']) {
            // As for events: unpublished is private to the organisation when set
            $released = Configure::read('MISP.unpublishedprivate') ? ['Collection.published' => true] : [];
            $conditions['OR'] = [
                [
                    'Collection.org_id' => $user['org_id']
                ],
                [
                    'AND' => [
                        ['Collection.distribution IN' => [1,2,3]],
                        $released,
                    ]
                ],
                [
                    'AND' => [
                        [
                            'Collection.distribution' => 4,
                            'Collection.sharing_group_id' => $sgids
                        ],
                        $released,
                    ]
                ]
            ];
        }
        return $conditions;
    }

    /**
     * Takes only `query`, paging, `order` and `returnFormat` (json or count).
     *
     * @param array|null $complexQuery the `query` tree, checked and passed only by AppController::restSearch()
     */
    public function restSearch(array $user, $returnFormat, $filters, $paramsOnly = false, $jobId = false, &$elementCounter = 0, &$renderView = false, &$skippedElementsCounter = 0, $complexQuery = null)
    {
        if (!isset($this->validFormats[$returnFormat])) {
            throw new NotFoundException('Invalid output format.');
        }
        $tool = new ComplexQueryTool($this, ComplexQueryTool::limitsFromConfig(), self::QUERY_FIELDS);
        $order = [];
        if (!empty($filters['order'])) {
            $tool->validateOrder($filters['order'], self::REST_SEARCH_ORDER_FIELDS, 'Collection');
            $order = $this->findOrder($filters['order'], 'Collection', self::REST_SEARCH_ORDER_FIELDS['Collection']) ?? [];
        }
        // a unique last key, or OFFSET paging can repeat or skip rows
        if (!preg_grep('/^Collection\.id /', $order)) {
            $order[] = 'Collection.id asc';
        }
        $limit = (int)($filters['limit'] ?? 0);
        if ($limit < 0) {
            throw new BadRequestException(__('The limit must be a positive integer.'));
        }
        $conditions = $this->buildConditions($user['id']);
        $served = self::servedConditions();
        if (!empty($served)) {
            $conditions['AND'][] = $served;
        }
        if ($complexQuery !== null) {
            $conditions['AND'][] = $tool->compile($tool->validate($complexQuery));
        }
        $tmpfile = new TmpFileTool();
        if ($returnFormat === 'count') {
            $elementCounter = $this->find('count', ['conditions' => $conditions, 'recursive' => -1]);
            $tmpfile->write((string)$elementCounter);
            return $tmpfile;
        }
        $offset = $limit && !empty($filters['page']) ? max(0, (int)$filters['page'] - 1) * $limit : 0;
        $elementCounter = 0;
        $separator = '';
        $tmpfile->write('{"response": [');
        do {
            $size = $limit ? min(self::REST_SEARCH_CHUNK, $limit - $elementCounter) : self::REST_SEARCH_CHUNK;
            $collections = $this->find('all', [
                'conditions' => $conditions,
                'contain' => ['Orgc', 'SharingGroup', 'CollectionElement' => self::servedElementOptions()],
                'recursive' => -1,
                'order' => $order,
                'limit' => $size,
                'offset' => $offset + $elementCounter,
            ]);
            foreach ($this->restSearchRows($user, $collections) as $row) {
                $tmpfile->write($separator . JsonTool::encode($row));
                $separator = ',';
            }
            $elementCounter += count($collections);
        } while (count($collections) === $size && (!$limit || $elementCounter < $limit));
        $tmpfile->write(']}' . PHP_EOL);
        return $tmpfile;
    }

    /**
     * Rows as the REST index returns them, with the analyst data under Collection only,
     * and the sharing group only on distribution 4: a stale one may not be the viewer's.
     */
    private function restSearchRows(array $user, array $collections)
    {
        if (empty($collections)) {
            return [];
        }
        $flat = $this->attachAnalystDataBulk(array_column($collections, 'Collection'));
        $counts = $this->CollectionElement->find('all', [
            'conditions' => ['CollectionElement.collection_id' => array_column($flat, 'id')],
            'fields' => ['CollectionElement.collection_id', 'COUNT(*) AS element_count'],
            'group' => ['CollectionElement.collection_id'],
            'recursive' => -1,
        ]);
        $counts = Hash::combine($counts, '{n}.CollectionElement.collection_id', '{n}.0.element_count');
        $rows = [];
        foreach ($collections as $k => $collection) {
            $record = $flat[$k] + ['RelationshipInbound' => []];
            $record['element_count'] = (int)($counts[$record['id']] ?? 0);
            if ($record['distribution'] != 4) {
                $collection['SharingGroup'] = array_fill_keys(array_keys($collection['SharingGroup']), null);
            }
            $elements = $collection['CollectionElement'];
            if (!empty($elements) && !self::showsAdders($user, $collection['Collection'])) {
                $elements = self::withoutAdders($elements);
            }
            $rows[] = [
                'Collection' => $record,
                'Orgc' => $collection['Orgc'],
                'SharingGroup' => $collection['SharingGroup'],
                'CollectionElement' => empty($elements) ? [] : $this->CollectionElement->withRecords($elements),
            ];
        }
        return $rows;
    }

    /**
     * Minimal index for sync pull: returns [uuid => modified] for every collection the
     * caller may see and distribute (filtered via buildConditions), optionally narrowed
     * by $filters (e.g. the orgc_id OR/NOT pull-rules the controller builds from
     * orgc_name). Mirrors AnalystData::indexMinimal, flattened — a collection has no
     * analyst-data-style type dimension, so the shape is a single [uuid => modified] map.
     * The remote side dedups against this by comparing `modified`.
     *
     * @param array $user The requesting sync user.
     * @param array $filters Extra conditions ANDed onto the visibility gate.
     * @return array uuid => modified (datetime string)
     */
    public function indexMinimal(array $user, array $filters = []): array
    {
        $conditions = [$this->buildConditions($user['id'])];
        $served = self::servedConditions();
        if (!empty($served)) {
            $conditions[] = $served;
        }
        if (!empty($filters)) {
            $conditions[] = $filters;
        }
        $entries = $this->find('all', [
            'recursive' => -1,
            'conditions' => ['AND' => $conditions],
            'fields' => ['Collection.uuid', 'Collection.modified'],
        ]);
        $allData = [];
        foreach ($entries as $entry) {
            $allData[$entry['Collection']['uuid']] = $entry['Collection']['modified'];
        }
        return $allData;
    }

    /**
     * Sync pull entry point. Fetches the remote collection index ({uuid: modified}),
     * dedups it against local copies by `modified` (D6 skip-on-equal), then chunk-fetches
     * and captures every winner. Mirrors AnalystData::pull + pullInChunks, flattened —
     * collections have no analyst-data-style `type` dimension, so the remote index is a
     * single [uuid => modified] map rather than [type][uuid => modified].
     *
     * The shared sink captureCollection() OWNS the distribution downgrade, locked=1 and
     * the D6 conflict rule, so each RAW remote collection is passed through untouched —
     * pre-downgrading here would double-downgrade (T2.1 carry-forward).
     *
     * @param array $user The local sync user driving the capture.
     * @param ServerSyncTool $serverSync Negotiated connection to the remote instance.
     * @return int Number of collections imported (created or updated).
     */
    public function pull(array $user, ServerSyncTool $serverSync)
    {
        // Real negotiation gate: skip silently against a peer without the feature (the
        // ServerSyncTool method throws are pure defense-in-depth on top of this).
        if (!$serverSync->isSupported(ServerSyncTool::FEATURE_COLLECTION_SYNC)) {
            return 0;
        }

        try {
            $filterRules = $this->buildPullFilterRules($serverSync->server());
            if ($serverSync->isSupported(ServerSyncTool::FEATURE_VALUE_TARGETS)) {
                // A 3.0 instance lists unpublished collections, as events
                $filterRules['published'] = 1;
            }
            $remoteData = $serverSync->collectionIndexMinimal($filterRules)->json();
        } catch (Exception $e) {
            $this->logException("Could not fetch collection index from server {$serverSync->server()['Server']['name']}", $e);
            return 0;
        }

        if (empty($remoteData)) {
            return 0;
        }

        $remoteUUIDs = array_keys($remoteData);
        $localRows = $this->find('all', [
            'recursive' => -1,
            'conditions' => ['Collection.uuid' => $remoteUUIDs],
            'fields' => ['Collection.uuid', 'Collection.modified', 'Collection.locked'],
        ]);
        // The capture refuses a remote copy of an original made here, unless the server is internal
        $internal = !empty($serverSync->server()['Server']['internal']);
        $localModified = [];
        $localOriginals = [];
        foreach ($localRows as $localRow) {
            $localModified[$localRow['Collection']['uuid']] = $localRow['Collection']['modified'];
            if (empty($localRow['Collection']['locked']) && !$internal) {
                $localOriginals[$localRow['Collection']['uuid']] = true;
            }
        }

        $uuidsToFetch = [];
        foreach ($remoteData as $remoteUUID => $remoteModified) {
            if (isset($localOriginals[$remoteUUID])) {
                continue;
            }
            if (!isset($localModified[$remoteUUID])) {
                // Missing locally — fetch it.
                $uuidsToFetch[] = $remoteUUID;
            } elseif (strtotime($localModified[$remoteUUID]) < strtotime($remoteModified)) {
                // Strictly newer remote wins (skip-on-equal).
                $uuidsToFetch[] = $remoteUUID;
            }
        }
        unset($remoteData, $remoteUUIDs, $localRows, $localModified, $localOriginals);

        if (empty($uuidsToFetch)) {
            return 0;
        }

        return $this->pullCollectionsInChunks($user, $uuidsToFetch, $serverSync);
    }

    /**
     * Chunk-fetch the deduped UUID list and hand each RAW remote collection to the shared
     * capture sink. Mirrors AnalystData::pullInChunks (100/chunk); no type layer.
     *
     * @param array $user
     * @param array $uuids UUIDs already deduped by Collection::pull.
     * @param ServerSyncTool $serverSync
     * @return int Number of collections imported.
     */
    private function pullCollectionsInChunks(array $user, array $uuids, ServerSyncTool $serverSync)
    {
        $saved = 0;
        // The sink applies the downgrade unless internal + this flag (mirrors pullInChunks).
        $remotePermSyncInternal = !empty($serverSync->cachedUserInfo()['Role']['perm_sync_internal']);
        $fromPre30 = !$serverSync->isSupported(ServerSyncTool::FEATURE_VALUE_TARGETS);

        foreach (array_chunk($uuids, 100) as $uuidChunk) {
            try {
                $chunkedCollections = $serverSync->fetchCollections($uuidChunk)->json();
            } catch (Exception $e) {
                $this->logException("Failed downloading the chunked collections from {$serverSync->server()['Server']['name']}.", $e);
                continue;
            }

            foreach ($chunkedCollections as $collection) {
                // RAW payload straight to the sink — it owns downgrade + locked=1 + D6.
                $savedResult = $this->captureCollection($user, $collection, $serverSync->server(), $remotePermSyncInternal, $fromPre30);
                if ($savedResult['success']) {
                    $saved += $savedResult['imported'];
                }
            }
        }

        return $saved;
    }

    /**
     * Translate a server's org pull-rules into the orgc_name OR/NOT filter the
     * indexMinimal endpoint expects (it resolves names -> orgc_id). Mirrors
     * AnalystData::buildPullFilterRules verbatim.
     */
    private function buildPullFilterRules(array $server): array
    {
        $filterRules = ['orgc_name' => []];
        $pullRules = $this->jsonDecode($server['Server']['pull_rules']);
        if (!empty($pullRules['orgs']['OR'])) {
            $filterRules['orgc_name'] = $pullRules['orgs']['OR'];
        }
        if (!empty($pullRules['orgs']['NOT'])) {
            $filterRules['orgc_name'] = array_merge($filterRules['orgc_name'], array_map(function ($orgName) {
                return '!' . $orgName;
            }, $pullRules['orgs']['NOT']));
        }
        return $filterRules;
    }

    /**
     * Push-receive dedup: given the pushing peer's {uuid: modified} candidates, return
     * only the subset this (receiving) instance actually wants — the receive-side mirror
     * of the pull dedup in Collection::pull. Flattened analogue of
     * AnalystData::filterAnalystDataForPush (no analyst-data `type` dimension).
     *
     * A candidate is wanted when it is either missing locally, OR strictly newer than a
     * local copy that is itself synced-in (locked=1). A locally-created (locked=0)
     * collection is authoritative and is never overwritten by a push, so its uuid is
     * dropped from the wanted set even if the candidate looks newer.
     *
     * @param array $candidates {uuid: modified} offered by the pushing peer.
     * @return array The {uuid: modified} subset the local side wants captured.
     */
    public function filterCollectionsForPush($candidates): array
    {
        $incoming = $candidates;
        $incomingUuids = array_keys($incoming);
        if (empty($incomingUuids)) {
            return [];
        }
        $localRows = $this->find('all', [
            'recursive' => -1,
            'conditions' => ['Collection.uuid' => $incomingUuids],
            'fields' => ['uuid', 'modified', 'locked'],
        ]);
        foreach ($localRows as $localRow) {
            $local = $localRow['Collection'];
            if (empty($incoming[$local['uuid']])) {
                continue;
            }
            if (!$this->isCandidateValidForPush($incoming[$local['uuid']], $local)) {
                unset($incoming[$local['uuid']]);
            }
        }
        return $incoming;
    }

    /**
     * The gate shared by filterCollectionsForPush: a candidate only wins against an existing
     * local row when that row is synced-in (locked=1) AND the candidate is strictly newer.
     * Mirrors AnalystData::isCandidateValidForPush.
     */
    private function isCandidateValidForPush($candidateModified, array $existingEntry): bool
    {
        if ($existingEntry['locked'] == 0) {
            return false;
        }
        if (strtotime($existingEntry['modified']) >= strtotime($candidateModified)) {
            return false;
        }
        return true;
    }

    /**
     * The one ingest point for a collection from another instance, pulled or
     * pushed (as GalaxyCluster::captureCluster):
     *  - the incoming member list replaces the local one, and the remote
     *    `modified` is kept, so sync dedups on it;
     *  - a collection created here (locked = 0) is overwritten only by an
     *    internal server, and stays this instance's own; otherwise a strictly
     *    newer `modified` wins. A new capture is stored as a copy (locked = 1);
     *  - `user_id` is the sync user, `org_id` their organisation; `orgc_id` and
     *    `sharing_group_id` are resolved by uuid;
     *  - distribution is downgraded (1->0, 2->1) unless the server is internal
     *    and the remote sync user has perm_sync_internal.
     *
     * Identity fields come from the server context, never from the payload,
     * and the payload's `id` is dropped. Callers pass the remote collection as
     * received: the downgrade happens here.
     *
     * @param array $user The sync user performing/authorising the capture.
     * @param array $collection Remote collection (with Orgc / SharingGroup / CollectionElement).
     * @param array|false $server The server the capture originates from (internal/locked rules).
     * @param bool $remotePermSyncInternal Whether the remote sync user has perm_sync_internal.
     * @param bool|null $fromPre30 The collection comes from a MISP older than 3.0; null: the requester decides
     * @return array ['success', 'imported', 'ignored', 'failed', 'errors']
     */
    public function captureCollection(array $user, array $collection, $server = false, $remotePermSyncInternal = false, $fromPre30 = null): array
    {
        $results = ['success' => false, 'imported' => 0, 'ignored' => 0, 'failed' => 0, 'errors' => []];

        // Normalise: hoist related data under the Collection key, tolerating both raw
        // find() output (siblings) and an already-rearranged payload (nested).
        if (!isset($collection['Collection'])) {
            $collection = ['Collection' => $collection];
        }
        foreach (['Orgc', 'Org', 'SharingGroup', 'CollectionElement'] as $child) {
            if (isset($collection[$child]) && !isset($collection['Collection'][$child])) {
                $collection['Collection'][$child] = $collection[$child];
                unset($collection[$child]);
            }
        }

        // Served unpublished between the index and the fetch: it waits for its publish
        if (array_key_exists('published', $collection['Collection']) && self::isWithheld($collection['Collection'])) {
            $results['success'] = true;
            $results['ignored'] = 1;
            return $results;
        }

        // No server context ⇒ treat as external + non-internal (downgrade + locked
        // protection both apply — the safe default; also avoids null offset warnings).
        if (empty($server)) {
            $server = ['Server' => ['internal' => 0, 'org_id' => 0]];
        }

        if (empty($collection['Collection']['uuid'])) {
            $collection['Collection']['uuid'] = CakeText::uuid();
        }

        // Resolve creator org (orgc_id) by UUID and, for distribution=4, the sharing
        // group by UUID (create-if-missing) — mirrors GalaxyCluster::captureOrganisationAndSG.
        $collection = $this->captureOrganisationAndSG($collection, $user);

        $collection['Collection']['org_id'] = $user['Organisation']['id'];
        $collection['Collection']['user_id'] = $user['id'];
        $collection['Collection']['locked'] = 1;

        // Distribution downgrade on incoming, unless internal + remote perm_sync_internal
        // (mirrors AnalystData/GalaxyCluster updatePulled*BeforeInsert).
        if (
            empty(Configure::read('MISP.host_org_id')) ||
            empty($server['Server']['internal']) ||
            Configure::read('MISP.host_org_id') != $server['Server']['org_id'] ||
            !$remotePermSyncInternal
        ) {
            switch ((int)($collection['Collection']['distribution'] ?? 0)) {
                case 1:
                    $collection['Collection']['distribution'] = 0; // community -> org only
                    break;
                case 2:
                    $collection['Collection']['distribution'] = 1; // connected -> community only
                    break;
            }
        }
        if ((int)($collection['Collection']['distribution'] ?? 0) !== 4) {
            $collection['Collection']['sharing_group_id'] = null;
        }

        // Replaced after the parent is saved; present but empty removes every member
        $elements = null;
        if (array_key_exists('CollectionElement', $collection['Collection'])) {
            $elements = $collection['Collection']['CollectionElement'];
            unset($collection['Collection']['CollectionElement']);
        }

        // What another instance sends is what it published
        $collection['Collection']['published'] = true;
        $lastPublished = $collection['Collection']['last_published'] ?? null;
        $collection['Collection']['last_published'] = is_string($lastPublished) && preg_match('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $lastPublished)
            ? $lastPublished
            : date('Y-m-d H:i:s');
        $fieldList = [
            'uuid', 'name', 'type', 'description', 'distribution',
            'sharing_group_id', 'org_id', 'orgc_id', 'user_id', 'locked', 'modified',
            'published', 'last_published',
        ];
        if (isset($collection['Collection']['analysis']) && in_array((int)$collection['Collection']['analysis'], self::ANALYSIS_LEVELS, true)) {
            $collection['Collection']['analysis'] = (int)$collection['Collection']['analysis'];
            $fieldList[] = 'analysis';
        } else {
            unset($collection['Collection']['analysis']);
        }

        $existing = $this->find('first', [
            'recursive' => -1,
            'conditions' => ['Collection.uuid' => $collection['Collection']['uuid']],
        ]);

        // current_user drives beforeValidate on the create branch (owner org / user_id /
        // orgc fallback); its perm_sync exemption lets our locked=1 stand.
        $this->current_user = $user;
        $this->writingPublishState = true;
        try {
            if (empty($existing)) {
                unset($collection['Collection']['id']);
                $this->create();
                $saveSuccess = $this->save($collection, true, $fieldList);
            } else {
                if (empty($existing['Collection']['locked']) && empty($server['Server']['internal'])) {
                    $results['errors'][] = __('Blocked an edit to a collection that was created locally. This can happen if a synchronised collection that was created on this instance was modified by an administrator on the remote side.');
                    $results['failed']++;
                    return $results;
                }
                if (isset($collection['Collection']['modified']) && $collection['Collection']['modified'] > $existing['Collection']['modified']) {
                    $collection['Collection']['id'] = $existing['Collection']['id'];
                    // An update leaves it a copy or this instance's own, as an event edit does
                    $saveSuccess = $this->save($collection, true, array_values(array_diff($fieldList, ['locked'])));
                } else {
                    $results['errors'][] = __('Remote version is not newer than local one for collection (%s)', $collection['Collection']['uuid']);
                    $results['ignored']++;
                    return $results;
                }
            }
        } finally {
            $this->writingPublishState = false;
        }

        if ($saveSuccess) {
            $results['imported']++;
            $saved = $this->find('first', [
                'recursive' => -1,
                'conditions' => ['Collection.uuid' => $collection['Collection']['uuid']],
            ]);
            if ($elements !== null) {
                $this->CollectionElement->captureElements([
                    'Collection' => [
                        'id' => $saved['Collection']['id'],
                        'CollectionElement' => $elements,
                    ],
                ], $fromPre30 === null ? SyncTool::valueTargetsWithheld() : $fromPre30, true);
            }
            $id = (int)$saved['Collection']['id'];
            if ($fromPre30 === null ? SyncTool::valueTargetsWithheld() : $fromPre30) {
                // Such a sender speaks for these types alone: members kept beyond
                // them keep their state, and an unpublished change keeps it withheld
                $this->markReleased($id, CollectionElement::PRE30_TYPES);
                $changes = $this->pendingChanges([$id])[$id];
                if ($changes['added'] + $changes['removed'] > 0) {
                    $this->updateAll(['Collection.published' => false], ['Collection.id' => $id]);
                }
            } else {
                $this->markReleased($id);
            }
        } else {
            $results['failed']++;
            foreach ($this->validationErrors as $validationError) {
                $results['errors'][] = is_array($validationError) ? $validationError[0] : $validationError;
            }
        }
        $results['success'] = $results['imported'] > 0;
        return $results;
    }

    /**
     * Resolve the creator organisation (orgc_id) by UUID and, for distribution=4, the
     * sharing group by UUID (create-if-missing). Mirrors
     * GalaxyCluster::captureOrganisationAndSG — Collection keys org/SG by integer id.
     */
    private function captureOrganisationAndSG($collection, $user)
    {
        $this->Event = ClassRegistry::init('Event');
        if (isset($collection['Collection']['distribution']) && $collection['Collection']['distribution'] == 4) {
            $collection['Collection'] = $this->Event->captureSGForElement($collection['Collection'], $user);
        }
        if (isset($collection['Collection']['Orgc'])) {
            $collection['Collection']['orgc_id'] = $this->Orgc->captureOrg($collection['Collection']['Orgc'], $user);
            unset($collection['Collection']['Orgc']);
        } else {
            // No creator org travelled with the payload — default to the sync user's org.
            $collection['Collection']['orgc_id'] = $user['org_id'];
        }
        return $collection;
    }

    /**
     * Sync push entry point. Collects the local collections eligible to leave for this peer,
     * asks the remote which of them it actually wants (filterCollectionsForPush remote dedup),
     * then uploads each accepted collection (with its Orgc / SharingGroup / CollectionElement
     * corpus) to the remote captureCollection sink. Mirrors AnalystData::push, flattened —
     * collections have no analyst-data `type` dimension.
     *
     * ★ RAW passthrough (T2.1 carry-forward): the remote captureCollection() sink OWNS the
     * distribution downgrade and locked=1, so we must NOT pre-downgrade or set locked here (the
     * pull side follows the same rule). This is the deliberate divergence from AnalystData::push,
     * whose updateAnalystDataForSync downgrades + locks on the push side.
     *
     * The push_collections server toggle is checked by the caller (Server::push), mirroring how
     * Server::pull gates Collection::pull on pull_collections — this method only enforces the
     * feature-negotiation gate, keeping push/pull symmetric.
     *
     * @param array $user The local sync user driving the push.
     * @param ServerSyncTool $serverSync Negotiated connection to the remote instance.
     * @param int|null $onlyId This collection alone, as its publish sends it
     * @return int Number of collections accepted + uploaded by the remote.
     */
    public function push(array $user, ServerSyncTool $serverSync, $onlyId = null)
    {
        if (!$serverSync->isSupported(ServerSyncTool::FEATURE_COLLECTION_SYNC)) {
            return 0;
        }
        $server = $serverSync->server();
        $this->Server = ClassRegistry::init('Server');

        $collections = $this->collectDataForPush($server, $onlyId);
        if (!$serverSync->isSupported(ServerSyncTool::FEATURE_VALUE_TARGETS)) {
            $collections = self::withoutElementsNewIn30($collections);
        }
        if (!$serverSync->isSupported(ServerSyncTool::FEATURE_STANDALONE_OBJECTS)) {
            $collections = self::withoutStandaloneObjects($collections);
        }
        if (empty($collections)) {
            return 0;
        }

        // Remote dedup: offer {uuid: modified}, the remote replies with the subset it wants
        // (missing there, or strictly newer than a synced-in remote copy — the mirror of our
        // own filterCollectionsForPush receive logic).
        $candidates = [];
        foreach ($collections as $collection) {
            $candidates[$collection['Collection']['uuid']] = $collection['Collection']['modified'];
        }
        try {
            $wanted = $serverSync->filterCollectionsForPush($candidates)->json();
        } catch (Exception $e) {
            $this->logException("Could not get eligible collection UUIDs from server #{$server['Server']['id']} for push.", $e);
            return 0;
        }
        if (isset($wanted['response'])) {
            $wanted = $wanted['response'];
        }
        if (empty($wanted)) {
            return 0;
        }

        $pushed = 0;
        foreach ($collections as $collection) {
            if (!isset($wanted[$collection['Collection']['uuid']])) {
                continue;
            }
            if ($this->uploadCollectionToServer($collection, $server, $serverSync, $user) === 'Success') {
                $pushed++;
            }
        }
        return $pushed;
    }

    /**
     * Collect the local collections eligible to be pushed to $server: distribution 1-3, or 4
     * when $server is a member of the collection's sharing group; then apply the server's
     * distribution rules (checkDistributionForPush) and org push-rules (orgc OR/NOT). Each kept
     * collection carries its Orgc / SharingGroup / CollectionElement corpus nested under
     * Collection so the remote sink can resolve orgc_id / sharing_group_id by UUID and replace
     * the element corpus. Mirrors AnalystData::collectDataForPush, flattened.
     *
     * @param array $server
     * @param int|null $onlyId This collection alone
     * @return array List of collections, each nested under 'Collection'.
     */
    public function collectDataForPush(array $server, $onlyId = null): array
    {
        $sgIDs = $this->collectValidSharingGroupIDs($server);
        $conditions = [
            'Collection.published' => true,
            'OR' => [
                ['AND' => [['Collection.distribution >' => 0], ['Collection.distribution <' => 4]]],
                ['AND' => ['Collection.distribution' => 4, 'Collection.sharing_group_id' => $sgIDs]],
            ],
        ];
        if ($onlyId !== null) {
            $conditions['Collection.id'] = (int)$onlyId;
        }
        $rows = $this->find('all', [
            'recursive' => -1,
            'contain' => ['Orgc', 'SharingGroup', 'CollectionElement'],
            'conditions' => $conditions,
        ]);
        $this->Event = ClassRegistry::init('Event');
        $SGModel = ClassRegistry::init('SharingGroup');
        $sgStore = [];
        $dataForPush = [];
        foreach ($rows as $row) {
            if ($row['Collection']['distribution'] != 4) {
                unset($row['SharingGroup']);
            }
            // Enrich the dist=4 sharing group with the full org/server structure the remote
            // captureSG needs to create it if missing (mirrors the AnalystData $sgStore cache).
            if (!empty($row['SharingGroup']['id'])) {
                $sgId = $row['SharingGroup']['id'];
                if (!isset($sgStore[$sgId])) {
                    $sg = $SGModel->find('first', [
                        'contain' => [
                            'SharingGroupServer' => ['Server' => ['fields' => ['Server.id', 'Server.url', 'Server.remote_org_id']]],
                            'SharingGroupOrg' => ['Organisation' => ['fields' => ['Organisation.id', 'Organisation.uuid']]],
                            'Organisation' => ['fields' => ['Organisation.id', 'Organisation.uuid']],
                        ],
                        'conditions' => ['SharingGroup.id' => $sgId],
                    ]);
                    $temp = $sg['SharingGroup'];
                    foreach (['Organisation', 'SharingGroupOrg', 'SharingGroupServer'] as $field) {
                        $temp[$field] = $sg[$field];
                    }
                    $sgStore[$sgId] = $temp;
                }
                $row['SharingGroup'] = $sgStore[$sgId];
            }
            // Nest the corpus under Collection — the shape checkDistributionForPush,
            // ServerSyncTool::pushCollection and the remote captureCollection sink all expect.
            $collection = ['Collection' => $row['Collection']];
            foreach (['Orgc', 'SharingGroup', 'CollectionElement'] as $child) {
                if (isset($row[$child])) {
                    $collection['Collection'][$child] = $row[$child];
                }
            }
            if (!empty($collection['Collection']['CollectionElement'])) {
                $collection['Collection']['CollectionElement'] = $this->CollectionElement->withRecords($collection['Collection']['CollectionElement']);
            }
            if (!$this->Event->checkDistributionForPush($collection, $server, 'Collection')) {
                continue;
            }
            if (!$this->isPushableForServerSyncRules($collection['Collection'], $server)) {
                continue;
            }
            $dataForPush[] = $collection;
        }
        return $dataForPush;
    }

    /**
     * A MISP older than 3.0 holds only event and galaxy cluster elements;
     * the collections themselves still go.
     *
     * @param array $collections As collectDataForPush returns them
     * @return array
     */
    public static function withoutElementsNewIn30(array $collections): array
    {
        foreach ($collections as $i => $collection) {
            if (empty($collection['Collection']['CollectionElement'])) {
                continue;
            }
            $collections[$i]['Collection']['CollectionElement'] = array_values(array_filter(
                $collection['Collection']['CollectionElement'],
                ['CollectionElement', 'heldBefore30']
            ));
        }
        return $collections;
    }

    /**
     * @return array Containable options for a collection's elements: a MISP
     *      older than 3.0 is served only those it can hold
     */
    public static function servedElementOptions(): array
    {
        if (!SyncTool::valueTargetsWithheld()) {
            return [];
        }
        return ['conditions' => ['CollectionElement.element_type' => CollectionElement::PRE30_TYPES]];
    }

    /**
     * A MISP that does not announce standalone objects cannot hold them; the
     * collections themselves still go.
     *
     * @param array $collections As collectDataForPush returns them
     * @return array
     */
    public static function withoutStandaloneObjects(array $collections): array
    {
        foreach ($collections as $i => $collection) {
            if (empty($collection['Collection']['CollectionElement'])) {
                continue;
            }
            $collections[$i]['Collection']['CollectionElement'] = array_values(array_filter(
                $collection['Collection']['CollectionElement'],
                function ($element) {
                    return ($element['element_type'] ?? null) !== 'StandaloneObject';
                }
            ));
        }
        return $collections;
    }

    /**
     * Sharing group IDs whose membership includes $server — dist=4 collections in one of these
     * are eligible to push. Mirrors AnalystData::collectValidSharingGroupIDs.
     */
    private function collectValidSharingGroupIDs(array $server): array
    {
        $SGModel = ClassRegistry::init('SharingGroup');
        $sgs = $SGModel->find('all', [
            'recursive' => -1,
            'contain' => ['Organisation', 'SharingGroupOrg' => ['Organisation'], 'SharingGroupServer'],
        ]);
        $sgIDs = [];
        foreach ($sgs as $sg) {
            if ($SGModel->checkIfServerInSG($sg, $server)) {
                $sgIDs[] = $sg['SharingGroup']['id'];
            }
        }
        if (empty($sgIDs)) {
            $sgIDs = [-1];
        }
        return $sgIDs;
    }

    /**
     * Apply the server's org push-rules (orgc OR/NOT) to a collection. Mirrors
     * AnalystData::isPushableForServerSyncRules; keys off the creator org UUID (Orgc.uuid).
     */
    private function isPushableForServerSyncRules(array $collection, array $server): bool
    {
        $pushRules = json_decode($server['Server']['push_rules'], true);
        if (!empty($pushRules['orgs']['OR'])) {
            if (empty($collection['Orgc']['uuid']) || !in_array($collection['Orgc']['uuid'], $pushRules['orgs']['OR'])) {
                return false;
            }
        }
        if (!empty($pushRules['orgs']['NOT'])) {
            if (!empty($collection['Orgc']['uuid']) && in_array($collection['Orgc']['uuid'], $pushRules['orgs']['NOT'])) {
                return false;
            }
        }
        return true;
    }

    /**
     * Prepare + upload a single collection to the remote captureCollection endpoint. Mirrors
     * AnalystData::uploadEntryToServer; logs + returns the error string on failure, 'Success'
     * otherwise (a numeric return from prepareForPushToServer means the collection was blocked).
     */
    public function uploadCollectionToServer(array $collection, array $server, ServerSyncTool $serverSync, array $user)
    {
        $collectionUuid = $collection['Collection']['uuid'];
        $collection = $this->prepareForPushToServer($collection, $server);
        if (is_numeric($collection)) {
            return $collection;
        }
        try {
            if (!$serverSync->isSupported(ServerSyncTool::PERM_SYNC)) {
                return __('The remote user does not have the permission to sync, the upload of the collection has been blocked.');
            }
            $serverSync->pushCollection($collection)->json();
        } catch (Exception $e) {
            $title = __('Uploading Collection (%s) to Server (%s)', $collectionUuid, $server['Server']['id']);
            $this->loadLog()->createLogEntry($user, 'push', 'Collection', 0, $title, $e->getMessage());
            $this->logException("Could not push collection to remote server {$serverSync->serverId()}", $e);
            return $e->getMessage();
        }
        return 'Success';
    }

    /**
     * Final gate + cleanup before a collection leaves for $server. Mirrors
     * AnalystData::prepareForPushToServer, MINUS the downgrade/locked mutation (the remote
     * captureCollection sink owns both — RAW passthrough, T2.1 carry-forward): re-checks the
     * dist=4 sharing-group server membership and the distribution rules, then strips the local
     * id (mass-assignment discipline; the remote keys on uuid). Returns 403 when blocked.
     */
    private function prepareForPushToServer(array $collection, array $server)
    {
        if ($collection['Collection']['distribution'] == 4) {
            if (!empty($collection['Collection']['SharingGroup']['SharingGroupServer'])) {
                $found = false;
                foreach ($collection['Collection']['SharingGroup']['SharingGroupServer'] as $sgs) {
                    if ($sgs['server_id'] == $server['Server']['id']) {
                        $found = true;
                    }
                }
                if (!$found) {
                    return 403;
                }
            } elseif (empty($collection['Collection']['SharingGroup']['roaming'])) {
                return 403;
            }
        }
        $this->Event = ClassRegistry::init('Event');
        if (!$this->Event->checkDistributionForPush($collection, $server, 'Collection')) {
            return 403;
        }
        unset($collection['Collection']['id']);
        if (!empty($collection['Collection']['CollectionElement'])) {
            $collection['Collection']['CollectionElement'] = self::withoutAdders($collection['Collection']['CollectionElement']);
        }
        return $collection;
    }

    /**
     * Who added a member stays inside the collection's organisation; when
     * it was added travels.
     *
     * @param array $user
     * @param array $collection Unwrapped; reads orgc_id
     * @return bool
     */
    public static function showsAdders(array $user, array $collection)
    {
        return !empty($user['Role']['perm_site_admin']) || (int)$user['org_id'] === (int)($collection['orgc_id'] ?? 0);
    }

    /**
     * @param array $elements CollectionElement rows, unwrapped
     * @return array Without who added them, nor whether partners hold them yet
     */
    public static function withoutAdders(array $elements)
    {
        foreach ($elements as $i => $element) {
            if (is_array($element)) {
                unset($elements[$i]['user_id'], $elements[$i]['published']);
            }
        }
        return $elements;
    }

    public function rearrangeCollection(array $collection, $user = null) {
        foreach ($collection as $key => $elements) {
            if ($key !== 'Collection') {
                $collection['Collection'][$key] = $elements;
                unset($collection[$key]);
            }
        }
        if (empty($user) || empty($user['Role']['perm_site_admin'])) {
            unset($collection['Collection']['User']);
        }
        if (!empty($collection['Collection']['CollectionElement']) && (empty($user) || !self::showsAdders($user, $collection['Collection']))) {
            $collection['Collection']['CollectionElement'] = self::withoutAdders($collection['Collection']['CollectionElement']);
        }
        if (!empty($collection['Collection']['CollectionElement'])) {
            $collection['Collection']['CollectionElement'] = $this->CollectionElement->withRecords($collection['Collection']['CollectionElement']);
        }
        return $collection;
    }
}
