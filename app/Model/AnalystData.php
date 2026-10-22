<?php
App::uses('AppModel', 'Model');
App::uses('ServerSyncTool', 'Tools');
App::uses('SyncTool', 'Tools');
App::uses('Validation', 'Utility');

class AnalystData extends AppModel
{

    public $recursive = -1;

    public $actsAs = array(
        'AuditLog',
        'Containable'
    );

    const valid_targets = [
        'Attribute',
        'Event',
        'EventReport',
        'GalaxyCluster',
        'Galaxy',
        'Object',
        'Note',
        'Opinion',
        'Relationship',
        'Organisation',
        'SharingGroup',
        'Collection',
        'Graph',
        'AttributeValue',
    ];

    // Addressed by the SHA-256 of their text instead of a uuid
    const SHA256_TARGETS = [
        'AttributeValue',
    ];

    const ADDRESS_ENDS = [
        'object',
    ];

    const NOTE = 0,
        OPINION = 1,
        RELATIONSHIP = 2,
        GRAPH = 3;

    // The types embedded in the records they are attached to
    const ANALYST_DATA_TYPES = [
        'Note',
        'Opinion',
        'Relationship',
    ];

    const TYPES = [
        'Note',
        'Opinion',
        'Relationship',
        'Graph',
    ];

    // A graph pull fetches at most this many bytes, or graphs, per request
    const GRAPH_PULL_BATCH_BYTES = 8388608,
        GRAPH_PULL_BATCH_COUNT = 100;

    // A batched push sends at most this many bytes, or records, per request
    const PUSH_BATCH_BYTES = 8388608,
        PUSH_BATCH_COUNT = 100;

    protected const BASE_EDITABLE_FIELDS = [
        'language',
        'authors',
        'modified',
        'distribution',
        'sharing_group_id',
    ];
    public const EDITABLE_FIELDS = [];

    /** @var object|null */
    protected $Note;
    /** @var object|null */
    protected $Opinion;
    /** @var object|null */
    protected $Relationship;
    /** @var object|null */
    protected $ObjectRelationship;
    /** @var object|null */
    protected $User;
    /** @var object|null */
    public $Org;
    /** @var object|null */
    public $Orgc;
    /** @var object|null */
    public $SharingGroup;
    /** @var array */
    protected $fetchedUUIDFromRecursion = [];

    public $current_user = null;

    public $belongsTo = [
        'SharingGroup' => [
            'className' => 'SharingGroup',
            'foreignKey' => 'sharing_group_id'
        ],
    ];

    public $validate = [
        'uuid' => [
            'uuid' => [
                'rule' => 'uuid',
                'message' => 'Please provide a valid RFC 4122 UUID'
            ],
            'unique' => [
                'rule' => 'isUnique',
                'message' => 'The UUID provided is not unique',
                'on' => 'create'
            ],
        ],
        'object_uuid' => [
            'address' => [
                'rule' => 'validAddress',
            ],
        ],
        'object_sha256' => [
            'address' => [
                'rule' => 'validAddress',
            ],
        ],
        'org_uuid' => [
            'uuid' => [
                'rule' => 'uuid',
                'message' => 'Please provide a valid RFC 4122 UUID'
            ],
        ],
        'orgc_uuid' => [
            'uuid' => [
                'rule' => 'uuid',
                'message' => 'Please provide a valid RFC 4122 UUID'
            ],
        ],
        'distribution' => [
            'rule' => ['inList', ['0', '1', '2', '3', '4']],
            'message' => 'Options: Your organisation only, This community only, Connected communities, All communities, Sharing group',
            'required' => 'create'
        ],
    ];

    public function __construct($id = false, $table = null, $ds = null)
    {
        parent::__construct($id, $table, $ds);
        $this->bindModel([
            'belongsTo' => [
                'Org' => [
                    'className' => 'Organisation',
                    'fields' => [
                        'id', 'name', 'uuid', 'type', 'description', 'sector', 'nationality', 'local'
                    ],
                    'foreignKey' => false,
                    'conditions' => [
                        sprintf('%s.org_uuid = Org.uuid', $this->alias)
                    ],
                ],
                'Orgc' => [
                    'className' => 'Organisation',
                    'fields' => [
                        'id', 'name', 'uuid','type', 'description', 'sector', 'nationality', 'local'
                    ],
                    'foreignKey' => false,
                    'conditions' => [
                        sprintf('%s.orgc_uuid = Orgc.uuid', $this->alias)
                    ],
                ],
                'SharingGroup' => [
                    'className' => 'SharingGroup',
                    'fields' => [
                        'id', 'name', 'uuid', 'releasability', 'description', 'org_id', 'active', 'roaming', 'local'
                    ],
                    'foreignKey' => false,
                    'conditions' => [
                        sprintf('%s.sharing_group_id = SharingGroup.id', $this->alias)
                    ],
                ],
            ]
        ]);
        $this->Org = $this->Orgc = ClassRegistry::init('Organisation');
        if (in_array($this->alias, self::TYPES)) {
            $this->schema();
            $this->_schema['distribution']['default'] = Configure::read('MISP.default_analyst_data_distribution') ?? 1;
        }

        if (!empty($this->childValidate)) {
            $this->validate = array_merge_recursive($this->validate, $this->childValidate);
        }
    }

    public function afterFind($results, $primary = false)
    {
        parent::afterFind($results, $primary);
        $this->setUser();
        foreach ($results as &$v) {
            $v[$this->alias]['note_type'] = $this->current_type_id;
            $v[$this->alias]['note_type_name'] = $this->current_type;
            $v = $this->rearrangeOrganisation($v);
            // Without a user (CLI or a job that set no CurrentUserId), nothing user-dependent is attached
            $user = empty($this->current_user) ? null : $this->current_user;
            $v = $this->rearrangeSharingGroup($v, $user);

            $v[$this->alias]['_canEdit'] = $user !== null && $this->canEditAnalystData($user, $v, $this->alias);
            if ($user !== null && !empty($this->fetchRecursive) && !empty($v[$this->alias]['uuid'])) {
                $this->Note = ClassRegistry::init('Note');
                $this->Opinion = ClassRegistry::init('Opinion');
                $this->Note->fetchRecursive = false;
                $this->Opinion->fetchRecursive = false;
                $v[$this->alias] = $this->fetchChildNotesAndOpinions($this->current_user, $v[$this->alias], false);
                $this->Note->fetchRecursive = true;
                $this->Opinion->fetchRecursive = true;
            }
        }
        return $results;
    }

    public function beforeValidate($options = array())
    {
        parent::beforeValidate($options);
        if (empty($this->id) && empty($this->data[$this->current_type]['uuid'])) {
            $this->data[$this->current_type]['uuid'] = CakeText::uuid();
        }
        if (empty($this->id)) {
            if (empty($this->data[$this->current_type]['orgc_uuid']) || empty($this->current_user['Role']['perm_sync'])) {
                $this->data[$this->current_type]['orgc_uuid'] = $this->current_user['Organisation']['uuid'];
            }
            $this->data[$this->current_type]['org_uuid'] = $this->current_user['Organisation']['uuid'];
            if (empty($this->data[$this->current_type]['authors'])) {
                $this->data[$this->current_type]['authors'] = $this->current_user['email'];
            }
        }
        foreach (static::ADDRESS_ENDS as $end) {
            $this->data[$this->current_type] = self::normaliseAddress($this->data[$this->current_type] ?? [], $end, empty($this->id));
        }
        if (isset($this->data[$this->current_type]['distribution'])) {
            if (
                $this->data[$this->current_type]['distribution'] != 4 &&
                (
                    isset($this->data[$this->current_type]['sharing_group_id']) &&
                    $this->data[$this->current_type]['sharing_group_id'] != 0
                )
            ) {
                $this->data[$this->current_type]['sharing_group_id'] = 0;
            }
        }
        return true;
    }

    /**
     * @param string|null $type
     * @param string $end 'object', 'related_object' or 'element'
     * @return string The column that addresses a target of this type.
     */
    public static function addressColumn($type, $end)
    {
        return $end . (in_array($type, self::SHA256_TARGETS, true) ? '_sha256' : '_uuid');
    }

    /**
     * A SHA-256 is lowercased: PostgreSQL compares case-sensitively, so the
     * unique keys over these columns depend on it. On create, a column left
     * out is added as NULL so that its validation rule runs.
     *
     * @param array $row
     * @param string $end
     * @param bool $creating
     * @return array
     */
    public static function normaliseAddress(array $row, $end, $creating)
    {
        foreach (['_uuid', '_sha256'] as $suffix) {
            $column = $end . $suffix;
            if (!array_key_exists($column, $row)) {
                if ($creating) {
                    $row[$column] = null;
                }
                continue;
            }
            if ($suffix === '_sha256' && is_string($row[$column])) {
                $row[$column] = strtolower(trim($row[$column]));
            }
            if ($row[$column] === '') {
                $row[$column] = null;
            }
        }
        return $row;
    }

    /**
     * @param array $row
     * @param string $column An address column, such as 'object_uuid'.
     * @return string|null Why the column does not fit the row's target type.
     */
    public static function addressError(array $row, $column)
    {
        $end = preg_replace('/_(uuid|sha256)$/', '', $column);
        $expected = self::addressColumn($row[$end . '_type'] ?? null, $end);
        $value = $row[$column] ?? null;
        if ($column !== $expected) {
            return $value === null ? null : __('Must be empty: this target type is addressed by %s.', $expected);
        }
        if ($column === $end . '_sha256') {
            return is_string($value) && preg_match('/^[0-9a-f]{64}$/', $value) ? null : __('Please provide a SHA-256 as 64 hexadecimal characters');
        }
        return Validation::uuid($value) ? null : __('Please provide a valid RFC 4122 UUID');
    }

    /**
     * @param array $check
     * @return bool|string
     */
    public function validAddress($check)
    {
        return self::addressError($this->data[$this->current_type], key($check)) ?? true;
    }

    public function beforeFind($query)
    {
        if (!SyncTool::valueTargetsWithheld()) {
            return $query;
        }
        $conditions = [];
        foreach (static::ADDRESS_ENDS as $end) {
            $conditions[$this->alias . '.' . $end . '_sha256'] = null;
        }
        if (!empty($query['conditions'])) {
            $conditions[] = $query['conditions'];
        }
        $query['conditions'] = $conditions;
        return $query;
    }

    public function beforeSave($options = [])
    {
        parent::beforeSave($options);
        if (empty($this->data[$this->current_type]['created'])) {
            $this->data[$this->current_type]['created'] = (new DateTime())->format('Y-m-d H:i:s');
        }
        if (empty($this->data[$this->current_type]['modified'])) {
            $this->data[$this->current_type]['modified'] = (new DateTime())->format('Y-m-d H:i:s');
        }
        $this->data[$this->current_type]['modified'] = (new DateTime($this->data[$this->current_type]['modified'], new DateTimeZone('UTC')))->format('Y-m-d H:i:s');
        $this->data[$this->current_type]['created'] = (new DateTime($this->data[$this->current_type]['created'], new DateTimeZone('UTC')))->format('Y-m-d H:i:s');

        if (empty($this->data[$this->current_type]['id'])) {
            if (!isset($this->data[$this->current_type]['distribution'])) {
                $this->data[$this->current_type]['distribution'] = $this->_schema['distribution']['default'];
            }
            if ($this->data[$this->current_type]['distribution'] != 4) {
                $this->data[$this->current_type]['sharing_group_id'] = null;
            }
        }
        return true;
    }

    public function afterSave($created, $options = array())
    {
        $isTriggerCallable = $this->isTriggerCallable('analyst-data-after-save');
        if ($isTriggerCallable) {
            $data = $this->data[$this->alias];
            $action = $created ? 'add' : 'edit';
            $workflowErrors = [];
            $logging = [
                'model' => $this->alias,
                'action' => $action,
                'id' => $data['id'],
            ];
            $triggerData = [$this->alias => $this->workflowTriggerData($data)];
            $this->executeTrigger('analyst-data-after-save', $triggerData, $workflowErrors, $logging);
        }
    }

    /**
     * @param array $data The saved row
     * @return array What the after-save workflow receives of it
     */
    protected function workflowTriggerData(array $data)
    {
        return $data;
    }

    public function getEditableFields(): array
    {
        return array_merge(static::BASE_EDITABLE_FIELDS, static::EDITABLE_FIELDS);
    }

    /**
     * Checks if user can modify given analyst data
     *
     * @param array $user
     * @param array $analystData
     * @return bool
     */
    public function canEditAnalystData(array $user, array $analystData, $modelType): bool
    {
        if (!isset($analystData[$modelType])) {
            return false; // This can happen when using find('count')
        }
        if ($user['Role']['perm_site_admin']) {
            return true;
        }
        if (isset($analystData[$modelType]['orgc_uuid']) && $analystData[$modelType]['orgc_uuid'] == $user['Organisation']['uuid']) {
            return true;
        }
        return false;
    }

    public function buildConditions(array $user): array
    {
        $conditions = [];
        if (!$user['Role']['perm_site_admin']) {
            $sgids = $this->SharingGroup->authorizedIds($user);
            $alias = $this->alias;
            $prefix = $alias != 'AnalystData' ? "{$alias}." : '';
            $conditions['AND']['OR'] = [
                "{$prefix}org_uuid" => $user['Organisation']['uuid'],
                [
                    'AND' => [
                        "{$prefix}distribution >" => 0,
                        "{$prefix}distribution <" => 4
                    ],
                ],
                [
                    'AND' => [
                        "{$prefix}sharing_group_id" => $sgids,
                        "{$prefix}distribution" => 4
                    ]
                ]
            ];
        }
        return $conditions;
    }

    protected function setUser()
    {
        if (empty($this->current_user)) {
            $user_id = Configure::read('CurrentUserId');
            $this->User = ClassRegistry::init('User');
            if ($user_id) {
                $this->current_user = $this->User->getAuthUser($user_id);
            }
        }
    }

    private function rearrangeOrganisation(array $analystData): array
    {
        if (!empty($analystData[$this->alias]['orgc_uuid'])) {
            if (!isset($analystData['Orgc'])) {
                $orgFound = $this->Orgc->find('first', [
                    'conditions' => [
                        'uuid' => $analystData[$this->alias]['orgc_uuid']
                    ],
                    'fields' => ['id', 'name', 'uuid']
                ]);
                if (!empty($orgFound)) {
                    $analystData[$this->alias]['Orgc'] = $orgFound['Organisation'];
                }
            } else {
                $analystData[$this->alias]['Orgc'] = $analystData['Orgc'];
            }
            unset($analystData['Orgc']);
        }
        if (!empty($analystData[$this->alias]['org_uuid'])) {
            if (!isset($analystData['Org'])) {
                $orgFound = $this->Org->find('first', [
                    'conditions' => [
                        'uuid' => $analystData[$this->alias]['org_uuid']
                    ],
                    'fields' => ['id', 'name', 'uuid']
                ]);
                if (!empty($orgFound)) {
                    $analystData[$this->alias]['Org'] = $orgFound['Organisation'];
                }
            } else {
                $analystData[$this->alias]['Org'] = $analystData['Org'];
            }
            unset($analystData['Org']);
        }
        return $analystData;
    }

    private function rearrangeSharingGroup(array $analystData, ?array $user): array
    {
        if (isset($analystData[$this->alias]['distribution'])) {
            if ($analystData[$this->alias]['distribution'] == 4) {
                if (!isset($analystData['SharingGroup']) && $user !== null) {
                    $this->SharingGroup = ClassRegistry::init('SharingGroup');
                    $sg = $this->SharingGroup->fetchSG($analystData[$this->alias]['sharing_group_id'], $user, true);
                    if (!empty($sg)) {
                        $sgData = array_intersect_key(
                            $sg['SharingGroup'], array_flip(
                                [
                                    'id', 'name', 'uuid', 'releasability', 'description', 'org_id',
                                    'active', 'roaming', 'local'
                                ]
                            )
                        );
                        $analystData[$this->alias]['SharingGroup'] = $sgData;
                    }
                } else {
                    $analystData[$this->alias]['SharingGroup'] = $analystData['SharingGroup'];
                }
            } else {
                unset($analystData['SharingGroup']);
            }
        }
        return $analystData;
    }

    /**
     * The type of the analyst data the user may read under this uuid. One
     * they may not read is as unknown as a missing one.
     *
     * @param array $user
     * @param string $uuid
     * @return string
     * @throws NotFoundException
     */
    public function deduceType(array $user, string $uuid)
    {
        foreach (self::TYPES as $type) {
            $Model = ClassRegistry::init($type);
            $found = $Model->find('first', [
                'conditions' => ['AND' => [[$Model->alias . '.uuid' => $uuid], $Model->buildConditions($user)]],
                'fields' => [$Model->alias . '.id'],
                'recursive' => -1,
                'callbacks' => false,
            ]);
            if (!empty($found)) {
                return $type;
            }
        }
        throw new NotFoundException(__('Invalid UUID'));
    }

    /**
     * Which of the given targets still resolve on this instance for $user.
     *
     * Analyst data outlives what it points at: an event can be deleted, and a
     * note can arrive through a sync without the object it annotates ever
     * following. A UUID on its own therefore says nothing about whether there
     * is anything to open.
     *
     * One lookup per distinct type, so a page of rows costs a handful of
     * queries rather than one per row.
     *
     * A value is missing whether the dictionary lacks it or no attribute
     * the user can see holds it.
     *
     * @param array $user
     * @param array $targets list of ['type' => string, 'address' => string],
     *                       a SHA-256 for the SHA256_TARGETS, else a uuid
     * @return array address => true for every target that resolves; a
     *               SHA-256 in lower case
     */
    public function existingTargets(array $user, array $targets): array
    {
        $byType = [];
        foreach ($targets as $target) {
            $type = $target['type'] ?? '';
            $address = (string)($target['address'] ?? '');
            if ($address === '' || !in_array($type, self::valid_targets, true)) {
                continue;
            }
            if (in_array($type, self::SHA256_TARGETS, true)) {
                $address = strtolower($address);
            }
            $byType[$type][$address] = $address;
        }

        $found = [];
        foreach ($byType as $type => $addresses) {
            foreach ($this->__resolveTargetsOfType($user, $type, array_values($addresses)) as $address) {
                $found[$address] = true;
            }
        }
        return $found;
    }

    /**
     * @param array $user
     * @param array $hexes
     * @return array [lowercase hex => value id] for the values an attribute
     *               the user can see holds; any attribute for a site admin
     */
    public function visibleValuesBySha256(array $user, array $hexes): array
    {
        $attribute = ClassRegistry::init('MispAttribute');
        $ids = $attribute->loadAttributeValue()->findBySha256($hexes);
        if (empty($ids)) {
            return [];
        }
        $visible = array_flip($attribute->visibleValueIds($user, $ids, count($ids)));
        return array_filter($ids, function ($id) use ($visible) {
            return isset($visible[$id]);
        });
    }

    /**
     * @param array $user
     * @param string $type one of self::valid_targets
     * @param array $addresses
     * @return array the subset of $addresses that exists and is visible to $user
     */
    private function __resolveTargetsOfType(array $user, string $type, array $addresses): array
    {
        if ($type === 'AttributeValue') {
            return array_keys($this->visibleValuesBySha256($user, $addresses));
        }
        $uuids = $addresses;
        if ($type === 'Attribute') {
            $model = ClassRegistry::init('MispAttribute');
            $rows = $model->fetchAttributesSimple($user, [
                'conditions' => ['Attribute.uuid' => $uuids],
                'fields' => ['Attribute.uuid'],
            ]);
            return array_column(array_column($rows, 'Attribute'), 'uuid');
        }
        if ($type === 'Object') {
            $model = ClassRegistry::init('MispObject');
            $rows = $model->fetchObjectSimple($user, [
                'conditions' => ['Object.uuid' => $uuids],
                'fields' => ['Object.uuid'],
            ]);
            return array_column(array_column($rows, 'Object'), 'uuid');
        }

        $model = ClassRegistry::init($type);
        $alias = $model->alias;
        if ($type === 'Event') {
            $conditions = $model->createEventConditions($user);
        } elseif (in_array($type, self::ANALYST_DATA_TYPES, true)) {
            $conditions = $model->buildConditions($user);
        } else {
            $conditions = [];
        }
        $conditions['AND'][] = ["{$alias}.uuid" => $uuids];
        return $model->find('column', [
            'conditions' => $conditions,
            'fields' => ["{$alias}.uuid"],
            'recursive' => -1,
            // Existence, nothing else - afterFind on these models resolves
            // organisations, sharing groups and edit rights per row.
            'callbacks' => false,
        ]);
    }

    /**
     * A readable line for each target $user can open, so a view can name what
     * a note is about instead of printing its UUID. Visibility is decided by
     * existingTargets(); the label is then read without callbacks, save an
     * attribute's, whose value only its find callbacks can read.
     *
     * @param array $user
     * @param array $targets list of ['type' => string, 'address' => string]
     * @return array address => ['label' => string, 'meta' => string[]]; a
     *               SHA-256 in lower case, whose entry also holds the
     *               value's full text as 'value'
     */
    public function describeTargets(array $user, array $targets): array
    {
        $described = [];
        $hexes = [];
        foreach ($targets as $i => $target) {
            if (in_array($target['type'] ?? '', self::SHA256_TARGETS, true)) {
                $hexes[] = strtolower((string)($target['address'] ?? ''));
                unset($targets[$i]);
            }
        }
        if (!empty($hexes)) {
            $ids = $this->visibleValuesBySha256($user, $hexes);
            $texts = empty($ids) ? [] : ClassRegistry::init('MispAttribute')->loadAttributeValue()->fetchValues(array_values($ids));
            foreach ($ids as $hex => $id) {
                if (isset($texts[$id])) {
                    $described[$hex] = [
                        'label' => mb_strimwidth((string)$texts[$id], 0, 160, '…'),
                        'meta' => [],
                        'value' => (string)$texts[$id],
                    ];
                }
            }
        }
        $models = [
            'Event' => ['Event', ['id', 'info', 'date'], 'info'],
            'Attribute' => ['MispAttribute', ['type', 'value', 'event_id'], 'value'],
            'Object' => ['MispObject', ['name', 'meta-category', 'event_id'], 'name'],
            'EventReport' => ['EventReport', ['name', 'event_id'], 'name'],
            'GalaxyCluster' => ['GalaxyCluster', ['value', 'type'], 'value'],
            'Galaxy' => ['Galaxy', ['name', 'type'], 'name'],
            'Note' => ['Note', ['note', 'language'], 'note'],
            'Opinion' => ['Opinion', ['opinion', 'comment'], 'comment'],
            'Relationship' => ['Relationship', ['relationship_type', 'related_object_type'], 'relationship_type'],
            'Organisation' => ['Organisation', ['name', 'type'], 'name'],
            'SharingGroup' => ['SharingGroup', ['name'], 'name'],
        ];
        $visible = $this->existingTargets($user, $targets);
        foreach ($targets as $target) {
            $type = $target['type'] ?? '';
            $uuid = $target['address'] ?? '';
            if (empty($visible[$uuid]) || !isset($models[$type])) {
                continue;
            }
            list($modelName, $fields, $labelField) = $models[$type];
            $model = ClassRegistry::init($modelName);
            $alias = $model->alias;
            $row = $model->find('first', [
                'conditions' => ["{$alias}.uuid" => $uuid],
                'fields' => array_map(function ($field) use ($alias) {
                    return "{$alias}.{$field}";
                }, $fields),
                'recursive' => -1,
                // An attribute's value is read through the value dictionary, in its callbacks
                'callbacks' => $modelName === 'MispAttribute',
            ]);
            if (empty($row[$alias])) {
                continue;
            }
            $row = $row[$alias];
            $label = (string)($row[$labelField] ?? '');
            $meta = [];
            foreach ($fields as $field) {
                if ($field === $labelField || !isset($row[$field]) || $row[$field] === '') {
                    continue;
                }
                if ($field === 'id') {
                    $meta[] = '#' . $row[$field];
                } elseif ($field === 'event_id') {
                    $meta[] = __('Event #%s', $row[$field]);
                } elseif ($field === 'opinion') {
                    $meta[] = __('%s/100', $row[$field]);
                } else {
                    $meta[] = (string)$row[$field];
                }
            }
            $described[$uuid] = [
                'label' => mb_strimwidth($label, 0, 160, '…'),
                'meta' => $meta,
            ];
        }
        return $described;
    }

    public function deduceAnalystDataType(array $analystData)
    {
        if (!empty($analystData['note_type_name']) && in_array($analystData['note_type_name'], self::TYPES)) {
            return $analystData['note_type_name'];
        }
        foreach (self::TYPES as $type) {
            if (isset($analystData[$type])) {
                return $type;
            }
        }
        throw new NotFoundException(__('Invalid or could not deduce analyst data type'));
    }

    public function getIDFromUUID($type, $id): int
    {
        $tmpForID = $this->find('first', [
            'conditions' => [
                'uuid' => $id,
            ],
            'fields' => ['id', 'uuid',],
        ]);
        $id = -1;
        if (!empty($tmpForID)) {
            $id = $tmpForID[$type]['id'];
        }
        return $id;
    }

    public function fetchSimple(array $user, $id): array
    {
        $conditions = [
            'AND' => [
                $this->buildConditions($user)
            ],
        ];
        if (Validation::uuid($id)) {
            $conditions[$this->alias . '.uuid'] = $id;
        } else {
            $conditions[$this->alias . '.id'] = $id;
        }
        return $this->find('first', [
            'conditions' => $conditions,
            'contain' => ['Org', 'Orgc'],
        ]);
    }

    public function fetchChildNotesAndOpinions(array $user, array $analystData, $isRest = true, $depth = 2): array
    {
        if ($depth == 0 || !empty($this->fetchedUUIDFromRecursion[$analystData['uuid']])) {
            $hasMoreNotesOrOpinions =  $this->hasMoreNotesOrOpinions($analystData, $user);
            $analystData['_max_depth_reached'] = $hasMoreNotesOrOpinions;
            return $isRest ? [] : $analystData;
        }
        $this->fetchedUUIDFromRecursion[$analystData['uuid']] = true;
        $this->Note = ClassRegistry::init('Note');
        $this->Opinion = ClassRegistry::init('Opinion');

        $paramsNote = [
            'recursive' => -1,
            'contain' => ['Org', 'Orgc'],
            'conditions' => [
                'AND' => [
                    $this->Note->buildConditions($user)
                ],
                'object_type' => $analystData['note_type_name'],
                'object_uuid' => $analystData['uuid'],
            ]
        ];
        $paramsOpinion = [
            'recursive' => -1,
            'contain' => ['Org', 'Orgc'],
            'conditions' => [
                'AND' => [
                    $this->Opinion->buildConditions($user)
                ],
                'object_type' => $analystData['note_type_name'],
                'object_uuid' => $analystData['uuid'],
            ]
        ];

        if ($isRest) {
            // fetch notes and opinions as lists
            $childNotesAndOpinions = [];
            $childNotes = $this->Note->find('all', $paramsNote);
            $childOpinions = $this->Opinion->find('all', $paramsOpinion);
            $orgFields = ['id', 'uuid', 'name', 'type', 'description', 'sector', 'nationality', 'local'];
            $orgTypes = ['Org', 'Orgc'];
            if (!empty($childNotes)) {
                foreach ($childNotes as $childNote) {
                    foreach ($orgTypes as $orgType) {
                        if (!empty($childNote['Note'][$orgType])) {
                            $childNote['Note'][$orgType] = array_filter($childNote['Note'][$orgType], function ($key) use ($orgFields) {
                                return in_array($key, $orgFields);
                            }, ARRAY_FILTER_USE_KEY);    
                        }
                    }
                    $childNotesAndOpinions[] = $childNote;
                    $expandedNotesAndOpinions = $this->fetchChildNotesAndOpinions($user, $childNote['Note'], $isRest, $depth-1);
                    if (!empty($expandedNotesAndOpinions)) {
                        foreach ($expandedNotesAndOpinions as $expandedNoteOrOpinion) {
                            $childNotesAndOpinions[] = $expandedNoteOrOpinion;
                        }
                    }
                }
            }
            if (!empty($childOpinions)) {
                foreach ($childOpinions as $childOpinion) {
                    foreach ($orgTypes as $orgType) {
                        if (!empty($childOpinion['Opinion'][$orgType])) {
                            $childOpinion['Opinion'][$orgType] = array_filter($childOpinion['Opinion'][$orgType], function ($key) use ($orgFields) {
                                return in_array($key, $orgFields);
                            }, ARRAY_FILTER_USE_KEY);
                        }
                    }
                    $childNotesAndOpinions[] = $childOpinion;
                    $expandedNotesAndOpinions = $this->fetchChildNotesAndOpinions($user, $childOpinion['Opinion'], $isRest, $depth-1);
                    if (!empty($expandedNotesAndOpinions)) {
                        foreach ($expandedNotesAndOpinions as $expandedNoteOrOpinion) {
                            $childNotesAndOpinions[] = $expandedNoteOrOpinion;
                        }
                    }
                }
            }
            return $childNotesAndOpinions;
        }
        // recursively fetch and include nested notes and opinions
        $childNotes = array_map(function ($item) use ($user, $isRest, $depth) {
            $expandedNotes = $this->fetchChildNotesAndOpinions($user, $item['Note'], $isRest, $depth-1);
            return $expandedNotes;
        }, $this->Note->find('all', $paramsNote));
        $childOpinions = array_map(function ($item) use ($user, $isRest, $depth) {
            $expandedNotes = $this->fetchChildNotesAndOpinions($user, $item['Opinion'], $isRest, $depth-1);
            return $expandedNotes;
        }, $this->Opinion->find('all', $paramsOpinion));

        if (!empty($childNotes)) {
            foreach ($childNotes as $childNote) {
                $this->fetchedUUIDFromRecursion[$childNote['uuid']] = true;
            }
            $analystData['Note'] = $childNotes;
        }
        if (!empty($childOpinions)) {
            foreach ($childOpinions as $childOpinion) {
                $this->fetchedUUIDFromRecursion[$childOpinion['uuid']] = true;
            }
            $analystData['Opinion'] = $childOpinions;
        }
        return $analystData;
    }

    protected function hasMoreNotesOrOpinions($analystData, array $user): bool
    {
        $hasMoreNotes = $this->Note->find('first', [
            'recursive' => -1,
            'conditions' => [
                'AND' => [
                    $this->Note->buildConditions($user)
                ],
                'object_type' => $analystData['note_type_name'],
                'object_uuid' => $analystData['uuid'],
            ]
        ]);
        if (!empty($hasMoreNotes)) {
            return true;
        }
        $hasMoreOpinions = $this->Opinion->find('first', [
            'recursive' => -1,
            'conditions' => [
                'AND' => [
                    $this->Opinion->buildConditions($user)
                ],
                'object_type' => $analystData['note_type_name'],
                'object_uuid' => $analystData['uuid'],
            ]
        ]);
        if (!empty($hasMoreOpinions)) {
            return true;
        }
        return false;
    }

    public function getExistingRelationships()
    {
        $existingRelationships = $this->find('column', [
            'recursive' => -1,
            'fields' => ['relationship_type'],
            'unique' => true,
        ]);
        $this->ObjectRelationship = ClassRegistry::init('ObjectRelationship');
        $objectRelationships = $this->ObjectRelationship->find('column', [
            'recursive' => -1,
            'fields' => ['name'],
            'unique' => true,
        ]);
        return array_unique(array_merge($existingRelationships, $objectRelationships));
    }

    /**
     * The analyst data thread attached to an object, as the user may see it:
     * notes and opinions with their own child notes/opinions nested, outbound
     * relationships with their target resolved, and inbound relationships with
     * their source resolved in related_object.
     *
     * @param array $user
     * @param string $objectType
     * @param string $objectUuid
     * @return array ['Note' => [], 'Opinion' => [], 'Relationship' => [], 'RelationshipInbound' => []]
     */
    public function fetchThreadForObject(array $user, $objectType, $address): array
    {
        $bySha256 = in_array($objectType, self::SHA256_TARGETS, true);
        if ($bySha256) {
            $address = strtolower($address);
        }
        $thread = ['Note' => [], 'Opinion' => [], 'Relationship' => [], 'RelationshipInbound' => []];
        $models = [];
        foreach (['Note', 'Opinion', 'Relationship'] as $type) {
            $models[$type] = ClassRegistry::init($type);
            $models[$type]->current_user = $user;
            $models[$type]->fetchRecursive = false;
            // The cycle guard outlives a walk; a thread already touched
            // earlier in the request would otherwise come back childless.
            $models[$type]->fetchedUUIDFromRecursion = [];
        }
        // afterFind's own recursion stops two levels down; walk the thread
        // explicitly so replies to replies are shown too.
        foreach ($models as $type => $model) {
            $fetched = $bySha256
                ? $model->fetchForSha256s([$address], $user)
                : $model->fetchForUuids([$address], $user);
            foreach ($fetched[$address][$type] ?? [] as $item) {
                $thread[$type][] = $model->fetchChildNotesAndOpinions($user, $item, false, 4);
            }
        }
        $Relationship = ClassRegistry::init('Relationship');
        $thread['RelationshipInbound'] = Hash::extract(
            $Relationship->getInboundRelationships($user, $objectType, $address),
            '{n}.Relationship'
        );
        return $thread;
    }

    /**
     * Total analyst data attached to an object, counted RECURSIVELY: the object's
     * (direct notes/opinions/relationships, plus analyst data at any depth
     */
    public function countForObjectRecursive(array $user, string $address, $objectType = null): int
    {
        $models = [
            'Note' => ClassRegistry::init('Note'),
            'Opinion' => ClassRegistry::init('Opinion'),
            'Relationship' => ClassRegistry::init('Relationship'),
        ];
        if (in_array($objectType, self::SHA256_TARGETS, true)) {
            $address = strtolower($address);
        }
        $total = 0;
        $frontier = [$address];
        $seen = [$address => true];
        // Only the object itself may be SHA-256-addressed, its analyst data never is
        $column = self::addressColumn($objectType, 'object');
        // Walk the tree level by level
        while (!empty($frontier)) {
            $next = [];
            foreach ($models as $alias => $model) {
                $rows = $model->find('all', [
                    'recursive' => -1,
                    'fields' => [$alias . '.uuid'],
                    'conditions' => array_merge([$column => $frontier], $model->buildConditions($user)),
                    'callbacks' => false,
                ]);
                foreach ($rows as $row) {
                    $total++;
                    $childUuid = $row[$alias]['uuid'];
                    if (empty($seen[$childUuid])) {
                        $seen[$childUuid] = true;
                        $next[] = $childUuid;
                    }
                }
            }
            $frontier = $next;
            $column = 'object_uuid';
        }
        // Inbound relationships (they point to this object; shown flat in the card).
        $total += (int)$models['Relationship']->find('count', [
            'recursive' => -1,
            'conditions' => array_merge([self::addressColumn($objectType, 'related_object') => $address], $models['Relationship']->buildConditions($user)),
            'callbacks' => false,
        ]);

        return $total;
    }

    public function getChildren($user, $uuid, $depth=2): array
    {
        $analystData = $this->fetchSimple($user, $uuid);
        if (empty($analystData)) {
            return [];
        }
        $analystData = $analystData[$this->alias];
        $this->Note = ClassRegistry::init('Note');
        $this->Opinion = ClassRegistry::init('Opinion');
        $analystData = $this->fetchChildNotesAndOpinions($user, $analystData, isset($this->__isRest) ? $this->__isRest : false, $depth);
        return $analystData;
    }

    /**
     * Gets a cluster then save it.
     *
     * @param array $user
     * @param array $analystData Analyst data to be saved
     * @param bool  $fromPull If the current capture is performed from a PULL sync
     * @param int   $orgId The organisation id that should own the analyst data
     * @param array $server The server for which to capture is ongoing
     * @param bool|null $fromPre30 The data comes from a MISP older than 3.0; null: the requester decides
     * @return array Result of the capture including successes, fails and errors
     */
    public function captureAnalystData(array $user, array $analystData, $fromPull=false, $orgUUId=false, $server=false, $fromPre30=null): array
    {
        $this->Note = ClassRegistry::init('Note');
        $this->Opinion = ClassRegistry::init('Opinion');
        $this->Relationship = ClassRegistry::init('Relationship');
        $results = ['success' => false, 'imported' => 0, 'ignored' => 0, 'failed' => 0, 'errors' => []];
        $type = $this->deduceAnalystDataType($analystData);
        if (!isset($analystData[$type])) {
            $analystData = [$type => $analystData];
        }
        $analystModel = ClassRegistry::init($type);

        if ($fromPre30 === null) {
            $fromPre30 = SyncTool::valueTargetsWithheld();
        }
        if ($fromPre30 && self::isValueAddressed($analystData[$type])) {
            $results['errors'][] = __('Analyst data on attribute values is not accepted from a MISP older than 3.0');
            $results['ignored']++;
            return $results;
        }

        if ($fromPull && !empty($orgUUId)) {
            $analystData[$type]['org_uuid'] = $orgUUId;
        } else {
            $analystData[$type]['org_uuid'] = $user['Organisation']['uuid'];
        }

        if (!isset($analystData[$type]['uuid'])) {
            $analystData[$type]['uuid'] = CakeText::uuid();
        }

        $this->AnalystDataBlocklist = ClassRegistry::init('AnalystDataBlocklist');
        if ($this->AnalystDataBlocklist->checkIfBlocked($analystData[$type]['uuid'])) {
            $results['errors'][] = __('Blocked by blocklist');
            $results['ignored']++;
            return $results;
        }

        if (!isset($analystData[$type]['orgc_uuid']) && !isset($analystData[$type]['Orgc'])) {
            $analystData[$type]['orgc_uuid'] = $analystData[$type]['org_uuid'];
        } else {
            if (!isset($analystData[$type]['Orgc'])) {
                if (isset($analystData[$type]['orgc_uuid']) && $analystData[$type]['orgc_uuid'] != $user['Organisation']['uuid'] && !$user['Role']['perm_sync'] && !$user['Role']['perm_site_admin']) {
                    $analystData[$type]['orgc_uuid'] = $analystData[$type]['org_uuid']; // Only sync user can create analyst data on behalf of other users
                }
            } else {
                if ($analystData[$type]['Orgc']['uuid'] != $user['Organisation']['uuid'] && !$user['Role']['perm_sync'] && !$user['Role']['perm_site_admin']) {
                    $analystData[$type]['orgc_uuid'] = $analystData[$type]['org_uuid']; // Only sync user can create analyst data on behalf of other users
                }
            }
            if (isset($analystData[$type]['orgc_uuid']) && $analystData[$type]['orgc_uuid'] != $user['Organisation']['uuid'] && !$user['Role']['perm_sync'] && !$user['Role']['perm_site_admin']) {
                $analystData[$type]['orgc_uuid'] = $analystData[$type]['org_uuid']; // Only sync user can create analyst data on behalf of other users
            }
        }

        if (!Configure::check('MISP.enableOrgBlocklisting') || Configure::read('MISP.enableOrgBlocklisting') !== false) {
            $analystModel->OrgBlocklist = ClassRegistry::init('OrgBlocklist');
            $orgcUUID = $analystData[$type]['orgc_uuid'];
            if ($orgcUUID != 0 && $analystModel->OrgBlocklist->hasAny(array('OrgBlocklist.org_uuid' => $orgcUUID))) {
                $results['errors'][] = __('Organisation blocklisted (%s)', $orgcUUID);
                $results['ignored']++;
                return $results;
            }
        }

        $analystData = $analystModel->captureOrganisationAndSG($analystData, $type, $user);

        // Start saving from the leaf since to make sure child elements get saved even if the parent should not be saved (or updated due to locked or timestamp)
        foreach (self::ANALYST_DATA_TYPES as $childType) {
            if (!empty($analystData[$type][$childType])) {
                foreach ($analystData[$type][$childType] as $childAnalystData) {
                    $captureResult = $this->{$childType}->captureAnalystData($user, $childAnalystData, $fromPull, $orgUUId, $server, $fromPre30);
                    $results['imported'] += $captureResult['imported'];
                    $results['ignored'] += $captureResult['ignored'];
                    $results['failed'] += $captureResult['failed'];
                    $results['errors'] = array_merge($results['errors'], $captureResult['errors']);
                }
            }
        }

        $existingAnalystData = $analystModel->find('first', [
            'conditions' => ["{$type}.uuid" => $analystData[$type]['uuid'],],
        ]);
        if (empty($existingAnalystData)) {
            unset($analystData[$type]['id']);
            $analystModel->create();
            $saveSuccess = $analystModel->save($analystData);
        } else {
            // DPT-4: a regular (non-sync, non-site-admin) caller - the web
            // add/edit afterSave, or analyst data nested in an object/
            // attribute/report/event capture - must not be able to overwrite
            // an existing record it could not edit directly. The incoming
            // orgc_uuid was already force-rewritten to the caller's own org
            // above, so authorise against the EXISTING (DB) record's orgc.
            // The sync/pull path (perm_sync) is intentionally exempt and keeps
            // its locked + timestamp semantics below.
            if (
                !$user['Role']['perm_sync'] && !$user['Role']['perm_site_admin'] &&
                !$analystModel->canEditAnalystData($user, $existingAnalystData, $type)
            ) {
                $results['errors'][] = __('Cannot edit analyst data (%s) created by another organisation.', $analystData[$type]['uuid']);
                $results['failed']++;
                return $results;
            }
            if (!$existingAnalystData[$type]['locked'] && empty($server['Server']['internal'])) {
                $results['errors'][] = __('Blocked an edit to an analyst data that was created locally. This can happen if a synchronised analyst data that was created on this instance was modified by an administrator on the remote side.');
                $results['failed']++;
                return $results;
            }
            if ($analystData[$type]['modified'] > $existingAnalystData[$type]['modified']) {
                $analystData[$type]['id'] = $existingAnalystData[$type]['id'];
                $saveSuccess = $analystModel->save($analystData);
            } else {
                $results['errors'][] = __('Remote version is not newer than local one for analyst data (%s)', $analystData[$type]['uuid']);
                $results['ignored']++;
                return $results;
            }
        }
        if ($saveSuccess) {
            $results['imported']++;
        } else {
            $results['failed']++;
            foreach ($analystModel->validationErrors as $validationError) {
                $results['errors'][] = $validationError[0];
            }
        }
        $results['success'] = $results['imported'] > 0;
        return $results;
    }

    /**
     * Captures the records of a batched push, each on its own: one refused
     * or broken record does not stop the others.
     *
     * @param array $user
     * @param array $records A list of {Type: record}
     * @return array {imported, ignored, failed, results: [{type, uuid, result, errors}]},
     *               one result per record, in order
     */
    public function captureBatch(array $user, array $records): array
    {
        $report = ['imported' => 0, 'ignored' => 0, 'failed' => 0, 'results' => []];
        foreach (array_values($records) as $record) {
            $type = null;
            if (is_array($record)) {
                foreach (self::TYPES as $candidate) {
                    if (isset($record[$candidate]) && is_array($record[$candidate])) {
                        $type = $candidate;
                        break;
                    }
                }
            }
            $uuid = $type !== null && isset($record[$type]['uuid']) && is_string($record[$type]['uuid'])
                ? $record[$type]['uuid']
                : null;
            if ($type === null) {
                $outcome = ['result' => 'failed', 'errors' => [__('Not an analyst data record of a known type.')]];
            } else {
                try {
                    $capture = $this->captureAnalystData($user, [$type => $record[$type]]);
                    if ($capture['success']) {
                        $result = 'imported';
                    } else {
                        $result = $capture['failed'] > 0 ? 'failed' : 'ignored';
                    }
                    $outcome = ['result' => $result, 'errors' => array_values($capture['errors'])];
                } catch (Exception $e) {
                    $this->logException("Could not capture pushed analyst data ($type)", $e);
                    $outcome = ['result' => 'failed', 'errors' => [__('The record could not be captured.')]];
                }
            }
            $report[$outcome['result']]++;
            $report['results'][] = ['type' => $type, 'uuid' => $uuid] + $outcome;
        }
        return $report;
    }

    public function captureOrganisationAndSG($element, $model, $user)
    {
        $this->Event = ClassRegistry::init('Event');
        if (isset($element[$model]['distribution']) && $element[$model]['distribution'] == 4) {
            $element[$model] = $this->Event->captureSGForElement($element[$model], $user);
        }
        // first we want to see how the creator organisation is encoded
        // The options here are either by passing an organisation object along or simply passing a string along
        if (isset($element[$model]['Orgc'])) {
            $element[$model]['orgc_uuid'] = $this->Orgc->captureOrg($element[$model]['Orgc'], $user, false, true);
            unset($element[$model]['Orgc']);
        } else {
            // Can't capture the Orgc, default to the current user
            $element[$model]['orgc_uuid'] = $user['Organisation']['uuid'];
        }
        return $element;
    }

    /**
     * Push Analyst Data to remote server. Collect eligible data locally and propose the list to the remote.
     * Remote will then return the list of UUIDs it's willing to get. Then, upload these entries.
     * 
     * @param array $user
     * @param ServerSyncTool $serverSync
     * @return array
     * @throws Exception
     */
    public function push(array $user, ServerSyncTool $serverSync): array
    {
        $server = $serverSync->server();

        if (!$server['Server']['push_analyst_data']) {
            return [];
        }
        $this->Server = ClassRegistry::init('Server');

        $serverSync->debug("Starting Analyst Data sync");

        $types = self::ANALYST_DATA_TYPES;
        // A peer that predates graphs fails its whole analyst-data push on the key
        if ($serverSync->isSupported(ServerSyncTool::FEATURE_ANALYST_GRAPH)) {
            $types[] = 'Graph';
        }
        $analystData = $this->collectDataForPush($serverSync->server(), $types);
        if (!$serverSync->isSupported(ServerSyncTool::FEATURE_VALUE_TARGETS)) {
            $analystData = self::withoutValueTargets($analystData);
        }
        $keyedAnalystData = [];
        foreach ($analystData as $type => $entries) {
            foreach ($entries as $entry) {
                $entry = $entry[$type];
                $keyedAnalystData[$type][$entry['uuid']] =  $entry['modified'];
            }
        }
        if (empty($analystData)) {
            return [];
        }

        try {
            $conditions = [];
            foreach ($keyedAnalystData as $type => $entry) {
                $conditions[$type] = array_keys($entry);
            }
            $analystDataToPush = $this->identifyUUIDsForPush($serverSync, $analystData, $conditions);
        } catch (Exception $e) {
            $this->logException("Could not get eligible Analyst Data IDs from server #{$server['Server']['id']} for push.", $e);
            return [];
        }
        if ($serverSync->isSupported(ServerSyncTool::FEATURE_ANALYST_DATA_BATCH)) {
            return $this->pushInBatches($user, $analystDataToPush, $serverSync);
        }
        $successes = [];
        foreach ($analystDataToPush as $type => $entries) {
            foreach ($entries as $entry) {
                $result = $this->uploadEntryToServer($type, $entry, $server, $serverSync, $user);
                if ($result === 'Success') {
                    $successes[] = __('AnalystData %s', $entry[$type]['uuid']);
                }
            }
        }
        return $successes;
    }

    /**
     * Collect eligible data to be pushed on a server
     *
     * @param array $server
     * @param array $types
     * @return array
     */
    public function collectDataForPush(array $server, array $types = self::ANALYST_DATA_TYPES): array
    {
        $sgIDs = $this->collectValidSharingGroupIDs($server);
        $options = [
            'recursive' => -1,
            'conditions' => [
                'OR' => [
                    [
                        'AND' => [
                            ['distribution >' => 0],
                            ['distribution <' => 4],
                        ]
                    ],
                    [
                        'AND' => [
                            'distribution' => 4,
                            'sharing_group_id' => $sgIDs,
                        ]
                    ],
                ]
            ],
        ];
        $typeOptions = [];
        if (in_array('Graph', $types, true)) {
            // Content is read at upload, for the graphs the remote accepts
            $typeOptions['Graph']['fields'] = ClassRegistry::init('Graph')->metadataFields();
        }
        $dataForPush = $this->getAllAnalystData('all', $options, $types, $typeOptions);
        $this->Event = ClassRegistry::init('Event');
        $SGModel = ClassRegistry::init('SharingGroup');
        $sgStore = [];
        foreach ($dataForPush as $type => $entries) {
            foreach ($entries as $i => $analystData) {
                if (isset($analystData[$type]['SharingGroup'])) {
                    $sg_id = $analystData[$type]['SharingGroup']['id'];
                    if (!isset($sgStore[$sg_id])) {
                        $sg = $SGModel->find('first', [
                            'contain' => [
                                'SharingGroupServer' => [
                                    'Server' => [
                                        'fields' => [
                                            'Server.id',
                                            'Server.url',
                                            'Server.remote_org_id'
                                        ]
                                    ]
                                ],
                                'SharingGroupOrg' => [
                                    'Organisation' => [
                                        'fields' => [
                                            'Organisation.id',
                                            'Organisation.uuid'
                                        ]
                                    ]
                                ],
                                'Organisation' => [
                                    'fields' => [
                                        'Organisation.id',
                                        'Organisation.uuid'
                                    ]
                                ]
                            ],
                            'conditions' => ['SharingGroup.id' => $sg_id]
                        ]);
                        $temp = $sg['SharingGroup'];
                        $captureSGDataFields = ['Organisation', 'SharingGroupOrg', 'SharingGroupServer'];
                        foreach ($captureSGDataFields as $field) {
                            $temp[$field] = $sg[$field];
                        }
                        $sgStore[$sg_id] = $temp;
                    }
                    if (isset($sgStore[$analystData[$type]['SharingGroup']['id']])) {
                        $dataForPush[$type][$i][$type]['SharingGroup'] = $sgStore[$sg_id];
                    }
                }
                if (!$this->Event->checkDistributionForPush($dataForPush[$type][$i], $server, $type)) {
                    unset($dataForPush[$type][$i]);
                }
                if (!$this->isPushableForServerSyncRules($analystData[$type], $server)) {
                    unset($dataForPush[$type][$i]);
                }
            }
            $dataForPush[$type] = array_values($dataForPush[$type]);
        }
        return $dataForPush;
    }

    /**
     * A MISP older than 3.0 cannot hold rows addressed by a value's SHA-256.
     *
     * @param array $dataForPush [type => [[type => row], ...]], as collectDataForPush returns it
     * @return array The same, without the rows addressing a value at either end
     */
    public static function withoutValueTargets(array $dataForPush): array
    {
        foreach ($dataForPush as $type => $entries) {
            $dataForPush[$type] = array_values(array_filter($entries, function ($entry) use ($type) {
                return !self::isValueAddressed($entry[$type]);
            }));
        }
        return $dataForPush;
    }

    /**
     * @param array $row A note, opinion or relationship
     * @return bool Whether either end is addressed by a value's SHA-256
     */
    public static function isValueAddressed(array $row): bool
    {
        foreach (['object', 'related_object'] as $end) {
            if (!empty($row[$end . '_sha256']) || in_array($row[$end . '_type'] ?? null, self::SHA256_TARGETS, true)) {
                return true;
            }
        }
        return false;
    }

    private function collectValidSharingGroupIDs(array $server): array
    {
        $this->SharingGroup = ClassRegistry::init('SharingGroup');
        $sgs = $this->SharingGroup->find('all', [
            'recursive' => -1,
            'contain' => ['Organisation', 'SharingGroupOrg' => ['Organisation'], 'SharingGroupServer']
        ]);
        $sgIDs = [];
        foreach ($sgs as $sg) {
            if ($this->SharingGroup->checkIfServerInSG($sg, $server)) {
                $sgIDs[] = $sg['SharingGroup']['id'];
            }
        }
        if (empty($sgIDs)) {
            $sgIDs = [-1];
        }
        return $sgIDs;
    }

    private function isPushableForServerSyncRules(array $analystData, array $server): bool
    {
        $push_rules = json_decode($server['Server']['push_rules'], true);
        if (!empty($push_rules['orgs']['OR'])) {
            if (!in_array($analystData['Orgc']['uuid'], $push_rules['orgs']['OR'])) {
                return false;
            }
        }
        if (!empty($push_rules['orgs']['NOT'])) {
            if (in_array($analystData['Orgc']['uuid'], $push_rules['orgs']['NOT'])) {
                return false;
            }
        }
        return true;
    }


    /**
     * Get an array of analyst data that the remote is willing to get and returns analyst data that should be pushed.
     * @param ServerSyncTool $serverSync
     * @param array $localAnalystData
     * @param array $conditions
     * @return array
     * @throws HttpSocketHttpException
     * @throws HttpSocketJsonException
     * @throws JsonException
     */
    public function identifyUUIDsForPush(ServerSyncTool $serverSync, array $localAnalystData=[], array $conditions=[]): array
    {
        $this->log("Fetching eligible analyst data from server #{$serverSync->serverId()} for push: " . JsonTool::encode($conditions), LOG_INFO);
        $candidates = [];
        foreach ($localAnalystData as $type => $entries) {
            foreach ($entries as $entry) {
                $entry = $entry[$type];
                $candidates[$type][$entry['uuid']] =  $entry['modified'];
            }
        }
        $remoteDataArray = $this->proposeDataToRemote($serverSync, $candidates);
        foreach ($localAnalystData as $type => $entries) {
            foreach ($entries as $i => $entry) {
                $entry = $entry[$type];
                if (!isset($remoteDataArray[$type][$entry['uuid']])) {
                    unset($localAnalystData[$type][$i]);
                }
            }
        }
        return $localAnalystData;
    }

    public function proposeDataToRemote(ServerSyncTool $serverSync, array $candidates): array
    {
        $acceptedDataForPush = $this->Server->filterAnalystDataForPush($serverSync, $candidates);
        return $acceptedDataForPush;
    }

    public function filterAnalystDataForPush($allIncomingAnalystData): array
    {
        $allData = array_fill_keys(self::ANALYST_DATA_TYPES, []);
        foreach ($allIncomingAnalystData as $model => $entries) {
            // A type this instance does not know is left out, not fatal
            if (!in_array($model, self::TYPES, true) || !is_array($entries)) {
                continue;
            }
            $incomingAnalystData = $entries;
            $incomingUuids = array_keys($entries);
            $options = [
                'conditions' => ["{$model}.uuid" => $incomingUuids],
                'recursive' => -1,
                'fields' => ['uuid', 'modified', 'locked']
            ];
            $analystData = ClassRegistry::init($model)->find('all', $options);
            foreach ($analystData as $entry) {
                if (empty($incomingAnalystData[$entry[$model]['uuid']])) {
                    continue;
                }
                if (!$this->isCandidateValidForPush($incomingAnalystData[$entry[$model]['uuid']], $entry[$model])) {
                    unset($incomingAnalystData[$entry[$model]['uuid']]);
                }
            }
            $allData[$model] = $incomingAnalystData;
        }
        return $allData;
    }

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
     * The types a sync index lists: those the caller names, or the embedded
     * types when it names none, as a caller that predates graphs does.
     *
     * @param mixed $requested
     * @return array
     */
    public static function syncTypes($requested): array
    {
        if (!is_array($requested)) {
            return self::ANALYST_DATA_TYPES;
        }
        return array_values(array_intersect(self::TYPES, array_filter($requested, 'is_string')));
    }

    /**
     * @param array $user
     * @param array $filters
     * @param array $types
     * @return array [type => [uuid => modified]]; a Graph entry is
     *               {modified, size}, its content size in bytes
     */
    public function indexMinimal(array $user, $filters = [], array $types = self::ANALYST_DATA_TYPES): array
    {
        $options = [
            'recursive' => -1,
            'conditions' => [
                'AND' => [
                    $this->buildConditions($user),
                    'AND' => [$filters],
                ],
            ],
            'fields' => ['uuid', 'modified', 'locked']
        ];
        $tmp = $this->getAllAnalystData('all', $options, $types, [
            'Graph' => ['fields' => ['uuid', 'modified', 'locked', 'content_size']],
        ]);
        $allData = [];
        foreach ($tmp as $type => $entries) {
            foreach ($entries as $i => $entry) {
                $entry = $entry[$type];
                if ($type === 'Graph') {
                    $allData[$type][$entry['uuid']] = [
                        'modified' => $entry['modified'],
                        'size' => (int)$entry['content_size'],
                    ];
                } else {
                    $allData[$type][$entry['uuid']] = $entry['modified'];
                }
            }
        }
        return $allData;
    }

    /**
     * getAllAnalystData Collect the analyst data of the given types
     *
     * @param string $findType
     * @param array $findOptions
     * @param array $types
     * @param array $typeOptions Find options of one type, over $findOptions
     * @return array
     */
    public function getAllAnalystData($findType='all', array $findOptions=[], array $types = self::ANALYST_DATA_TYPES, array $typeOptions = []): array
    {
        $allData = [];
        foreach ($types as $type) {
            $model = ClassRegistry::init($type);
            $options = array_merge($findOptions, $typeOptions[$type] ?? []);
            $allData[$model->alias] = $model->find($findType, $options);
        }
        return $allData;
    }

    public function uploadEntryToServer($type, array $analystData, array $server, ServerSyncTool $serverSync, array $user)
    {
        $analystDataID = $analystData[$type]['id'];
        $analystData = $this->prepareEntryForUpload($type, $analystData, $server);
        if (!is_array($analystData)) {
            return $analystData;
        }
        return $this->sendEntryToServer($type, $analystDataID, $analystData, $server, $serverSync, $user);
    }

    /**
     * Pushes the accepted records in batches of at most PUSH_BATCH_COUNT
     * records and PUSH_BATCH_BYTES bytes, a larger record alone. A graph's
     * content is read as its batch fills, so a push holds one batch at most.
     *
     * @param array $user
     * @param array $analystDataToPush [type => [record]]
     * @param ServerSyncTool $serverSync
     * @return array The records the remote imported
     */
    private function pushInBatches(array $user, array $analystDataToPush, ServerSyncTool $serverSync): array
    {
        if (!$serverSync->isSupported(ServerSyncTool::PERM_SYNC) || !$serverSync->isSupported(ServerSyncTool::PERM_ANALYST_DATA)) {
            return [];
        }
        $server = $serverSync->server();
        $successes = [];
        $batch = [];
        $bytes = 0;
        foreach ($analystDataToPush as $type => $entries) {
            foreach ($entries as $entry) {
                $id = $entry[$type]['id'];
                $record = $this->prepareEntryForUpload($type, $entry, $server);
                if (!is_array($record)) {
                    continue;
                }
                $size = strlen(JsonTool::encode($record));
                if (!empty($batch) && (count($batch) >= static::PUSH_BATCH_COUNT || $bytes + $size > static::PUSH_BATCH_BYTES)) {
                    $successes = array_merge($successes, $this->uploadBatchToServer($batch, $server, $serverSync, $user));
                    $batch = [];
                    $bytes = 0;
                }
                $batch[] = ['type' => $type, 'id' => $id, 'record' => $record];
                $bytes += $size;
            }
        }
        if (!empty($batch)) {
            $successes = array_merge($successes, $this->uploadBatchToServer($batch, $server, $serverSync, $user));
        }
        return $successes;
    }

    /**
     * One batch. A request that fails as a whole is sent again one record per
     * request, so a single bad record cannot hold back the rest.
     *
     * @param array $batch [{type, id, record}]
     * @return array The records the remote imported
     */
    private function uploadBatchToServer(array $batch, array $server, ServerSyncTool $serverSync, array $user): array
    {
        $successes = [];
        try {
            $response = $serverSync->pushAnalystDataBatch(array_column($batch, 'record'))->json();
        } catch (Exception $e) {
            $this->logException("Could not push a batch of analyst data to remote server {$serverSync->serverId()}, sending its records one by one", $e);
            foreach ($batch as $item) {
                if ($this->sendEntryToServer($item['type'], $item['id'], $item['record'], $server, $serverSync, $user) === 'Success') {
                    $successes[] = __('AnalystData %s', $item['record'][$item['type']]['uuid']);
                }
            }
            return $successes;
        }
        $results = isset($response['results']) && is_array($response['results']) ? $response['results'] : [];
        foreach ($batch as $i => $item) {
            $uuid = $item['record'][$item['type']]['uuid'];
            $result = $results[$i] ?? null;
            if (!is_array($result) || strtolower((string)($result['uuid'] ?? '')) !== strtolower($uuid)) {
                $result = ['result' => 'failed', 'errors' => [__('The remote did not report on this record.')]];
            }
            $outcome = $result['result'] ?? null;
            if ($outcome === 'imported') {
                $successes[] = __('AnalystData %s', $uuid);
            } elseif ($outcome !== 'ignored') {
                $title = __('Uploading AnalystData (%s::%s) to Server (%s)', $item['type'], $item['id'], $server['Server']['id']);
                $errors = !empty($result['errors']) && is_array($result['errors'])
                    ? implode(', ', array_map('strval', $result['errors']))
                    : __('Refused by the remote.');
                $this->loadLog()->createLogEntry($user, 'push', 'AnalystData', $item['id'], $title, $errors);
            }
        }
        return $successes;
    }

    /**
     * A collected record as it goes to a remote: a graph with its content.
     *
     * @return array|string|int The record; a message when it is gone, 403
     *                          when it may not go to this server
     */
    private function prepareEntryForUpload($type, array $analystData, array $server)
    {
        if ($type === 'Graph') {
            $Graph = ClassRegistry::init('Graph');
            $analystData = $Graph->attachContent($analystData);
            if ($analystData === null) {
                return __('The workspace was deleted before it could be pushed.');
            }
            if (is_array($analystData['Graph']['content'])) {
                $analystData['Graph']['content'] = ClassRegistry::init('AnalystGraphData')
                    ->documentForServer($analystData['Graph']['content'], $server);
            }
        }
        return $this->prepareForPushToServer($type, $analystData, $server);
    }

    private function sendEntryToServer($type, $analystDataID, array $analystData, array $server, ServerSyncTool $serverSync, array $user)
    {
        try {
            if (!$serverSync->isSupported(ServerSyncTool::PERM_SYNC) || !$serverSync->isSupported(ServerSyncTool::PERM_ANALYST_DATA)) {
                return __('The remote user does not have the permission to manipulate analyst data, the upload of the analyst data has been blocked.');
            }
            $serverSync->pushAnalystData($type, $analystData)->json();
        } catch (Exception $e) {
            $title = __('Uploading AnalystData (%s::%s) to Server (%s)', $type, $analystDataID, $server['Server']['id']);
            $this->loadLog()->createLogEntry($user, 'push', 'AnalystData', $analystDataID, $title, $e->getMessage());

            $this->logException("Could not push analyst data to remote server {$serverSync->serverId()}", $e);
            return $e->getMessage();
        }

        return 'Success';
    }

    private function prepareForPushToServer($type, array $analystData, array $server)
    {
        if ($analystData[$type]['distribution'] == 4) {
            if (!empty($analystData[$type]['SharingGroup']['SharingGroupServer'])) {
                $found = false;
                foreach ($analystData[$type]['SharingGroup']['SharingGroupServer'] as $sgs) {
                    if ($sgs['server_id'] == $server['Server']['id']) {
                        $found = true;
                    }
                }
                if (!$found) {
                    return 403;
                }
            } elseif (empty($analystData[$type]['SharingGroup']['roaming'])) {
                return 403;
            }
        }
        $this->Event = ClassRegistry::init('Event');
        if ($this->Event->checkDistributionForPush($analystData, $server, $type)) {
            return $this->updateAnalystDataForSync($type, $analystData, $server);
        }
        return 403;
    }

    private function updateAnalystDataForSync($type, array $analystData, array $server): array
    {
        $this->Event = ClassRegistry::init('Event');
        // cleanup the array from things we do not want to expose
        foreach (['id'] as $field) {
            unset($analystData[$type][$field]);
        }
        // Add the local server to the list of instances in the SG
        if (isset($analystData[$type]['SharingGroup']) && isset($analystData[$type]['SharingGroup']['SharingGroupServer'])) {
            foreach ($analystData[$type]['SharingGroup']['SharingGroupServer'] as &$s) {
                if ($s['server_id'] == 0) {
                    $s['Server'] = array(
                        'id' => 0,
                        'url' => $this->Event->__getAnnounceBaseurl(),
                        'name' => $this->Event->__getAnnounceBaseurl()
                    );
                }
            }
        }

        $analystData[$type]['locked'] = true;
        // Downgrade the event from connected communities to community only
        if (!$server['Server']['internal'] && $analystData[$type]['distribution'] == 2) {
            $analystData[$type]['distribution'] = 1;
        }
        return $analystData;
    }

    /**
     * Collect all UUIDs with their modified time on the remote side, then filter the list based on what we have locally.
     * Afterward, iteratively pull what should be pulled.
     *
     * @param array $user
     * @param ServerSyncTool $serverSync
     * @return int Number of saved analysis
     */
    public function pull(array $user, ServerSyncTool $serverSync)
    {
        if (!$serverSync->isSupported(ServerSyncTool::PERM_ANALYST_DATA)) {
            return 0;
        }

        $this->Server = ClassRegistry::init('Server');
        try {
            $filterRules = $this->buildPullFilterRules($serverSync->server());
            $filterRules['types'] = self::TYPES;
            $remoteData = $serverSync->fetchIndexMinimal($filterRules)->json();
        } catch (Exception $e) {
            $this->logException("Could not fetch analyst data IDs from server {$serverSync->server()['Server']['name']}", $e);
            return 0;
        }

        if (empty($remoteData) || !is_array($remoteData)) {
            return 0;
        }
        $remoteIndex = self::readRemoteIndex($remoteData);
        $allRemoteUUIDs = [];
        foreach ($remoteIndex as $entries) {
            $allRemoteUUIDs = array_merge($allRemoteUUIDs, array_keys($entries));
        }
        if (empty($allRemoteUUIDs)) {
            return 0;
        }

        $localAnalystData = $this->getAllAnalystData('list', [
            'conditions' => ['uuid' => $allRemoteUUIDs],
            'fields' => ['uuid', 'modified'],
        ], array_keys($remoteIndex));

        $remoteUUIDsToFetch = self::planPull($remoteIndex, $localAnalystData);
        unset($remoteData, $remoteIndex, $allRemoteUUIDs, $localAnalystData);

        if (empty($remoteUUIDsToFetch)) {
            return 0;
        }

        return $this->pullInChunks($user, $remoteUUIDsToFetch, $serverSync);
    }

    /**
     * A remote sync index, read: only the types known here, each entry as its
     * modified time and size. The size is null when the remote gives none or
     * an unusable one.
     *
     * @param array $remoteData
     * @return array [type => [uuid => ['modified' => string, 'size' => int|null]]]
     */
    public static function readRemoteIndex(array $remoteData): array
    {
        $index = [];
        foreach (self::TYPES as $type) {
            if (empty($remoteData[$type]) || !is_array($remoteData[$type])) {
                continue;
            }
            foreach ($remoteData[$type] as $uuid => $entry) {
                $modified = is_array($entry) ? ($entry['modified'] ?? null) : $entry;
                $size = is_array($entry) ? ($entry['size'] ?? null) : null;
                if (!is_string($modified)) {
                    continue;
                }
                $index[$type][$uuid] = [
                    'modified' => $modified,
                    'size' => is_numeric($size) && $size >= 0 ? (int)$size : null,
                ];
            }
        }
        return $index;
    }

    /**
     * The remote entries to fetch: missing here, or newer than the local copy.
     *
     * @param array $remoteIndex As readRemoteIndex() returns it
     * @param array $local [type => [uuid => modified]]
     * @return array [type => [uuid => size|null]]
     */
    public static function planPull(array $remoteIndex, array $local): array
    {
        $toFetch = [];
        foreach ($remoteIndex as $type => $entries) {
            foreach ($entries as $uuid => $entry) {
                if (
                    !isset($local[$type][$uuid]) ||
                    strtotime($local[$type][$uuid]) < strtotime($entry['modified'])
                ) {
                    $toFetch[$type][$uuid] = $entry['size'];
                }
            }
        }
        return $toFetch;
    }

    /**
     * Packs keys, in order, into batches of at most $maxCount keys and
     * $maxBytes bytes. A key of unknown size (null), or over $maxBytes
     * alone, gets a batch of its own.
     *
     * @param array $sizes [key => int|null]
     * @param int $maxBytes
     * @param int $maxCount
     * @return array[] Lists of keys
     */
    public static function sizedBatches(array $sizes, int $maxBytes, int $maxCount): array
    {
        $batches = [];
        $batch = [];
        $bytes = 0;
        foreach ($sizes as $key => $size) {
            if ($size === null || $size > $maxBytes) {
                $batches[] = [(string)$key];
                continue;
            }
            if (!empty($batch) && (count($batch) >= $maxCount || $bytes + $size > $maxBytes)) {
                $batches[] = $batch;
                $batch = [];
                $bytes = 0;
            }
            $batch[] = (string)$key;
            $bytes += $size;
        }
        if (!empty($batch)) {
            $batches[] = $batch;
        }
        return $batches;
    }

    private function pullInChunks(array $user, array $analystDataUuids, ServerSyncTool $serverSync)
    {
        $saved = 0;
        $serverOrgUUID = $this->Org->find('first', [
            'recursive' => -1,
            'conditions' => ['id' => $serverSync->server()['Server']['org_id']],
            'fields' => ['id', 'uuid']
        ])['Organisation']['uuid'];

        $remoteUser = $serverSync->cachedUserInfo();
        $remotePermSyncInternal = !empty($remoteUser['Role']['perm_sync_internal']);
        $fromPre30 = !$serverSync->isSupported(ServerSyncTool::FEATURE_VALUE_TARGETS);

        foreach ($analystDataUuids as $type => $entries) {
            if (empty($entries)) {
                continue;
            }
            if ($type === 'Graph') {
                $chunks = self::sizedBatches($entries, self::GRAPH_PULL_BATCH_BYTES, self::GRAPH_PULL_BATCH_COUNT);
            } else {
                $chunks = array_chunk(array_keys($entries), 100);
            }

            foreach ($chunks as $uuidChunk) {
                try {
                    $chunkedAnalystData = $serverSync->fetchAnalystData($type, $uuidChunk)->json();
                } catch (Exception $e) {
                    $this->logException("Failed downloading the chunked analyst data from {$serverSync->server()['Server']['name']}.", $e);
                    continue;
                }
    
                foreach ($chunkedAnalystData as $analystData) {
                    $analystData = $this->updatePulledBeforeInsert($analystData, $type, $serverSync->server(), $user, $serverSync->pullRules(), $remotePermSyncInternal);
                    $savedResult = $this->captureAnalystData($user, $analystData, true, $serverOrgUUID, $serverSync->server(), $fromPre30);
                    if ($savedResult['success']) {
                        $saved += $savedResult['imported'];
                    }
                }
            }
        }

        return $saved;
    }

    private function updatePulledBeforeInsert(array $analystData, $type, array $server, array $user, array $pullRules, $remotePermSyncInternal = false): array
    {
        $downgrade = empty(Configure::read('MISP.host_org_id')) || !$server['Server']['internal'] ||  Configure::read('MISP.host_org_id') != $server['Server']['org_id'] || !$remotePermSyncInternal;
        $analystData[$type] = self::updatePulledAnalystData($analystData[$type], $downgrade);
        return $analystData;
    }

    /**
     * A pulled analyst data row is locked and, over a non-internal link, downgraded
     * (community only to org only, connected communities to community only).
     * Its nested children get the same.
     *
     * @param array $analystData A single Note, Opinion or Relationship row
     * @param bool $downgrade
     * @return array
     */
    public static function updatePulledAnalystData(array $analystData, $downgrade): array
    {
        $analystData['locked'] = true;
        if ($downgrade && isset($analystData['distribution'])) {
            if ($analystData['distribution'] == 1) {
                $analystData['distribution'] = '0';
            } elseif ($analystData['distribution'] == 2) {
                $analystData['distribution'] = '1';
            }
        }
        return self::updatePulledNested($analystData, $downgrade);
    }

    /**
     * Apply updatePulledAnalystData() to the analyst data nested in a pulled element
     * (an event, attribute, object, report or another analyst data row).
     *
     * @param array $element
     * @param bool $downgrade
     * @return array
     */
    public static function updatePulledNested(array $element, $downgrade): array
    {
        foreach (self::ANALYST_DATA_TYPES as $type) {
            if (empty($element[$type]) || !is_array($element[$type])) {
                continue;
            }
            foreach ($element[$type] as $k => $analystData) {
                if (is_array($analystData)) {
                    $element[$type][$k] = self::updatePulledAnalystData($analystData, $downgrade);
                }
            }
        }
        return $element;
    }

    private function buildPullFilterRules(array $server): array
    {
        $filterRules = ['orgc_name' => []];
        $pullRules = $this->jsonDecode($server['Server']['pull_rules']);
        if (!empty($pullRules['orgs']['OR'])) {
            $filterRules['orgc_name'] = $pullRules['orgs']['OR'];
        }
        if (!empty($pullRules['orgs']['NOT'])) {
            $filterRules['orgc_name'] = array_merge($filterRules['orgc_name'], array_map(function($orgName) {
                return '!' . $orgName;
            }, $pullRules['orgs']['NOT']));
        }
        return $filterRules;
    }
}
