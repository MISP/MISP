<?php
App::uses('AppModel', 'Model');
App::uses('ServerSyncTool', 'Tools');
App::uses('SyncTool', 'Tools');

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

    public $current_user = null;

    /** Set while a publish, or a capture from another instance, writes the published state. */
    private $writingPublishState = false;

    /** @var array|null withheldScopes(), read once for a request from another instance */
    private $servedScopes = null;

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
     * Partners hold every member now, and none of those taken out.
     *
     * @param int $id
     */
    private function markReleased($id)
    {
        $this->CollectionElement->updateAll(
            ['CollectionElement.published' => true],
            ['CollectionElement.collection_id' => $id, 'CollectionElement.published' => false]
        );
        ClassRegistry::init('CollectionElementRemoval')->deleteAll(
            ['CollectionElementRemoval.collection_id' => $id],
            false
        );
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
                ];
            }, $added),
        ];

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
        $drawn = $this->relationshipsBetween($orgcUuid, $members, $changedSince);
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
        foreach (['added', 'removed'] as $kind) {
            array_map($collect, $review[$kind]['items']);
        }
        foreach ($review['relationships']['items'] as $relationship) {
            $collect($relationship['from']);
            $collect($relationship['to']);
        }
        $described = empty($targets) ? [] : ClassRegistry::init('AnalystData')->describeTargets($user, array_values($targets));
        $byAddress = [];
        foreach ($described as $address => $description) {
            $byAddress[strtolower((string)$address)] = $description;
        }
        $label = function (array $end) use ($byAddress, $collection) {
            if ($end['type'] === 'Collection' && $end['address'] === strtolower($collection['uuid'])) {
                return $end + ['label' => $collection['name'], 'meta' => []];
            }
            $found = $byAddress[$end['address']] ?? null;
            return $end + ['label' => $found['label'] ?? null, 'meta' => $found['meta'] ?? []];
        };
        foreach (['added', 'removed'] as $kind) {
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
     * What withheld collections keep from partners: per collection, its
     * organisation and the addresses of its members, its own included.
     *
     * @return array [{uuid, orgc_uuid, members: [address => true]}]
     */
    public function withheldScopes()
    {
        $rows = $this->find('all', [
            'recursive' => -1,
            'contain' => ['Orgc'],
            'fields' => ['Collection.id', 'Collection.uuid', 'Orgc.uuid'],
            'conditions' => ['Collection.distribution !=' => 0, 'Collection.published' => false],
        ]);
        if (empty($rows)) {
            return [];
        }
        $members = $this->memberAddresses(Hash::extract($rows, '{n}.Collection.id'));
        $scopes = [];
        foreach ($rows as $row) {
            $id = (int)$row['Collection']['id'];
            $uuid = strtolower($row['Collection']['uuid']);
            $scopes[] = [
                'uuid' => $uuid,
                'orgc_uuid' => strtolower((string)($row['Orgc']['uuid'] ?? '')),
                'members' => ($members[$id] ?? []) + [$uuid => true],
            ];
        }
        return $scopes;
    }

    /**
     * A graph on a withheld collection, or a relationship between its
     * members, waits for the collection's publish when the collection's
     * organisation made it. Notes and opinions never wait.
     *
     * @param array $scopes withheldScopes()'s
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
        $scopes = $this->withheldScopes();
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
        if ($this->servedScopes === null) {
            $this->servedScopes = $this->withheldScopes();
        }
        if (empty($this->servedScopes)) {
            return $rows;
        }
        $scopes = $this->servedScopes;
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
            ['Collection.published' => false],
            ['AND' => [$conditions, ['Collection.orgc_id' => $org['Orgc']['id'], 'Collection.published' => true]]]
        );
    }

    /**
     * A graph saved here on a collection of its organisation changed it.
     *
     * @param array $graph Unwrapped; reads object_type, object_uuid, orgc_uuid and locked
     */
    public function graphSaved(array $graph)
    {
        if (($graph['object_type'] ?? null) !== 'Collection' || !empty($graph['locked']) || !is_string($graph['object_uuid'] ?? null)) {
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
        if (!empty($relationship['locked'])) {
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
                    'conditions' => ['CollectionElement.' . $column => $column === 'element_uuid' ? self::spellings($address) : $address],
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
            'contain' => ['Orgc'],
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
        if ($user['Role']['perm_site_admin']) {
            return true;
        }
        if ($collection['Collection']['org_id'] == $user['org_id']) {
            return true;
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
            $conditions['OR'] = [
                [
                    'Collection.org_id' => $user['org_id']
                ],
                [
                    'Collection.distribution IN' => [1,2,3]
                ],
                [
                    'AND' => [
                        'Collection.distribution' => 4,
                        'Collection.sharing_group_id' => $sgids
                    ]
                ]
            ];
        }
        return $conditions;
    }

    /**
     * Minimal index for sync pull: returns [uuid => modified] for every collection the
     * caller may see and distribute (filtered via buildConditions), optionally narrowed
     * by $filters (e.g. the orgc_id OR/NOT pull-rules the controller builds from
     * orgc_name). Mirrors AnalystData::indexMinimal, flattened — a collection has no
     * analyst-data-style type dimension, so the shape is a single [uuid => modified] map.
     * The remote side dedups against this by comparing `modified` (D6).
     *
     * @param array $user The requesting sync user.
     * @param array $filters Extra conditions ANDed onto the visibility gate.
     * @return array uuid => modified (datetime string)
     */
    public function indexMinimal(array $user, array $filters = []): array
    {
        $conditions = [$this->buildConditions($user['id'])];
        if (SyncTool::requesterIsMisp()) {
            $conditions[] = self::releasedConditions();
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
            'fields' => ['Collection.uuid', 'Collection.modified'],
        ]);
        $localModified = [];
        foreach ($localRows as $localRow) {
            $localModified[$localRow['Collection']['uuid']] = $localRow['Collection']['modified'];
        }

        $uuidsToFetch = [];
        foreach ($remoteData as $remoteUUID => $remoteModified) {
            if (!isset($localModified[$remoteUUID])) {
                // Missing locally — fetch it.
                $uuidsToFetch[] = $remoteUUID;
            } elseif (strtotime($localModified[$remoteUUID]) < strtotime($remoteModified)) {
                // Strictly newer remote wins (skip-on-equal — D6).
                $uuidsToFetch[] = $remoteUUID;
            }
        }
        unset($remoteData, $remoteUUIDs, $localRows, $localModified);

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
     * collection is authoritative and is never overwritten by a push (D6), so its uuid is
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
     * D6 gate shared by filterCollectionsForPush: a candidate only wins against an existing
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
     * Shared sync capture sink for Collections — the single ingest point for BOTH the
     * pull path and the push-receive controller action (mirrors
     * GalaxyCluster::captureCluster / AnalystData::captureAnalystData). Centralising
     * every enforcement rule here means both sync directions are covered once:
     *  - D5 corpus authoritative: the incoming element set replaces the local one
     *    wholesale via CollectionElement::captureElements() (which self-suppresses the
     *    parent `modified` bump, T1.3, so the remote `modified` we write stays
     *    authoritative for `{uuid: modified}` dedup).
     *  - D6 last-writer-wins guarded by `locked`: a locally-created (locked=0) collection
     *    is never overwritten by a non-internal remote; otherwise the strictly-newer
     *    `modified` wins (equal/older is skipped). Accepted captures are marked locked=1.
     *  - D7 creator neutralised: `user_id` is pinned to the sync user, `org_id` to the
     *    sync user's org; `orgc_id`/`sharing_group_id` are resolved by UUID.
     *  - Distribution is downgraded on incoming (1->0, 2->1) unless the server is internal
     *    and the remote sync user has perm_sync_internal.
     *
     * All identity/security fields (uuid, org, orgc, user_id, locked) are pinned from
     * server-derived context, never honoured from the payload; the payload `id` is
     * dropped (capture keys on `uuid` only) — PRD §7 mass-assignment discipline.
     *
     * NB for the pull (T3.3) and push (T4.x) wiring: the downgrade + locked=1 live HERE,
     * so callers must pass the raw remote collection and must NOT pre-downgrade it
     * (avoids a double downgrade). Pull passes $remotePermSyncInternal from the remote
     * user info; push-receive passes !empty($user['Role']['perm_sync_internal']).
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

        // Server-derived, never attacker-controlled: owner org = the sync user's org;
        // creator user neutralised to the sync user (D7); mark as synced-in (locked=1).
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

        // D5: the incoming element corpus is authoritative — pull it aside for a wholesale
        // replace after the parent is saved (present-but-empty ⇒ cull all local elements).
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
                // D6: never let a non-internal remote overwrite a locally-created original.
                if (empty($existing['Collection']['locked']) && empty($server['Server']['internal'])) {
                    $results['errors'][] = __('Blocked an edit to a collection that was created locally. This can happen if a synchronised collection that was created on this instance was modified by an administrator on the remote side.');
                    $results['failed']++;
                    return $results;
                }
                // Last-writer-wins: only a strictly-newer remote version wins.
                if (isset($collection['Collection']['modified']) && $collection['Collection']['modified'] > $existing['Collection']['modified']) {
                    $collection['Collection']['id'] = $existing['Collection']['id'];
                    $saveSuccess = $this->save($collection, true, $fieldList);
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
                // captureElements() replaces the corpus authoritatively and suppresses the
                // Collection.modified bump itself, preserving the remote `modified` (T1.3).
                $this->CollectionElement->captureElements([
                    'Collection' => [
                        'id' => $saved['Collection']['id'],
                        'CollectionElement' => $elements,
                    ],
                ], $fromPre30 === null ? SyncTool::valueTargetsWithheld() : $fromPre30, true);
            }
            $this->markReleased((int)$saved['Collection']['id']);
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
     * @return int Number of collections accepted + uploaded by the remote.
     */
    public function push(array $user, ServerSyncTool $serverSync)
    {
        if (!$serverSync->isSupported(ServerSyncTool::FEATURE_COLLECTION_SYNC)) {
            return 0;
        }
        $server = $serverSync->server();
        $this->Server = ClassRegistry::init('Server');

        $collections = $this->collectDataForPush($server);
        if (!$serverSync->isSupported(ServerSyncTool::FEATURE_VALUE_TARGETS)) {
            $collections = self::withoutValueElements($collections);
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
     * @return array List of collections, each nested under 'Collection'.
     */
    public function collectDataForPush(array $server): array
    {
        $sgIDs = $this->collectValidSharingGroupIDs($server);
        $rows = $this->find('all', [
            'recursive' => -1,
            'contain' => ['Orgc', 'SharingGroup', 'CollectionElement'],
            'conditions' => [
                'Collection.published' => true,
                'OR' => [
                    ['AND' => [['Collection.distribution >' => 0], ['Collection.distribution <' => 4]]],
                    ['AND' => ['Collection.distribution' => 4, 'Collection.sharing_group_id' => $sgIDs]],
                ],
            ],
        ]);
        $this->Event = ClassRegistry::init('Event');
        $SGModel = ClassRegistry::init('SharingGroup');
        $sgStore = [];
        $dataForPush = [];
        foreach ($rows as $row) {
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
     * A MISP older than 3.0 cannot hold elements addressed by a value's SHA-256;
     * the collections themselves still go.
     *
     * @param array $collections As collectDataForPush returns them
     * @return array
     */
    public static function withoutValueElements(array $collections): array
    {
        foreach ($collections as $i => $collection) {
            if (empty($collection['Collection']['CollectionElement'])) {
                continue;
            }
            $collections[$i]['Collection']['CollectionElement'] = array_values(array_filter(
                $collection['Collection']['CollectionElement'],
                function ($element) {
                    return empty($element['element_sha256']);
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
        return $collection;
    }
}
