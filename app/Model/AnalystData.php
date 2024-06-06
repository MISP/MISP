<?php
App::uses('AppModel', 'Model');
App::uses('ServerSyncTool', 'Tools');

class AnalystData extends AppModel
{

    public $recursive = -1;

    public $actsAs = array(
        'AuditLog',
        'Containable'
    );

    public $valid_targets = [
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
        'SharingGroup'
    ];

    const NOTE = 0,
        OPINION = 1,
        RELATIONSHIP = 2;

    const ANALYST_DATA_TYPES = [
        'Note',
        'Opinion',
        'Relationship',
    ];

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
                        'id', 'name', 'uuid','type', 'sector', 'nationality', 'local'
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
        $this->Org = ClassRegistry::init('Organisation');
        $this->Orgc = ClassRegistry::init('Organisation');
    }

    public function afterFind($results, $primary = false)
    {
        parent::afterFind($results, $primary);

        $this->setUser();
        foreach ($results as $i => $v) {
            $results[$i][$this->alias]['note_type'] = $this->current_type_id;
            $results[$i][$this->alias]['note_type_name'] = $this->current_type;

            $results[$i] = $this->rearrangeOrganisation($results[$i], $this->current_user);
            $results[$i] = $this->rearrangeSharingGroup($results[$i], $this->current_user);

            $results[$i][$this->alias]['_canEdit'] = $this->canEditAnalystData($this->current_user, $v, $this->alias);
            if (!empty($this->fetchRecursive) && !empty($results[$i][$this->alias]['uuid'])) {
                $this->Note = ClassRegistry::init('Note');
                $this->Opinion = ClassRegistry::init('Opinion');
                $this->Note->fetchRecursive = false;
                $this->Opinion->fetchRecursive = false;
                $results[$i][$this->alias] = $this->fetchChildNotesAndOpinions($this->current_user, $results[$i][$this->alias]);
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
                $this->data[$this->current_type]['distribution'] = Configure::read('MISP.default_event_distribution'); // use default event distribution
            }
            if ($this->data[$this->current_type]['distribution'] != 4) {
                $this->data[$this->current_type]['sharing_group_id'] = null;
            }
        }
        return true;
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
                $analystData[$this->alias]['Orgc'] = $this->Orgc->find('first', ['conditions' => ['uuid' => $analystData[$this->alias]['orgc_uuid']]])['Organisation'];
            } else {
                $analystData[$this->alias]['Orgc'] = $analystData['Orgc'];
            }
            unset($analystData['Orgc']);
        }
        if (!empty($analystData[$this->alias]['org_uuid'])) {
            if (!isset($analystData['Org'])) {
                $analystData[$this->alias]['Org'] = $this->Org->find('first', ['conditions' => ['uuid' => $analystData[$this->alias]['org_uuid']]])['Organisation'];
            } else {
                $analystData[$this->alias]['Org'] = $analystData['Org'];
            }
            unset($analystData['Org']);
        }
        return $analystData;
    }

    private function rearrangeSharingGroup(array $analystData, array $user): array
    {
        if (isset($analystData[$this->alias]['distribution'])) {
            if ($analystData[$this->alias]['distribution'] == 4) {
                if (!isset($analystData['SharingGroup'])) {
                    $this->SharingGroup = ClassRegistry::init('SharingGroup');
                    $sg = $this->SharingGroup->fetchSG($analystData[$this->alias]['sharing_group_id'], $user, true);
                    $sgData = array_intersect_key(
                        $sg['SharingGroup'], array_flip(
                            [
                                'id', 'name', 'uuid', 'releasability', 'description', 'org_id',
                                'active', 'roaming', 'local'
                            ]
                        )
                    );
                    $analystData[$this->alias]['SharingGroup'] = $sgData;
                } else {
                    $analystData[$this->alias]['SharingGroup'] = $analystData['SharingGroup'];
                }
            } else {
                unset($analystData['SharingGroup']);
            }
        }
        return $analystData;
    }

    public function deduceType(string $uuid)
    {
        foreach ($this->valid_targets as $valid_target) {
            $this->{$valid_target} = ClassRegistry::init($valid_target);
            $result = $this->$valid_target->find('first', [
                'conditions' => [$valid_target.'.uuid' => $uuid],
                'recursive' => -1
            ]);
            if (!empty($result)) {
                return $valid_target;
            }
        }
        throw new NotFoundException(__('Invalid UUID'));
    }

    public function getAnalystDataTypeFromUUID($uuid)
    {
        foreach (self::ANALYST_DATA_TYPES as $type) {
            $this->{$type} = ClassRegistry::init($type);
            $result = $this->{$type}->find('first', [
                'conditions' => [$type.'.uuid' => $uuid],
                'recursive' => -1
            ]);
            if (!empty($result)) {
                return $type;
            }
        }
        throw new NotFoundException(__('Invalid UUID'));
    }

    public function deduceAnalystDataType(array $analystData)
    {
        if (!empty($analystData['note_type_name']) && in_array($analystData['note_type_name'], self::ANALYST_DATA_TYPES)) {
            return $analystData['note_type_name'];
        }
        foreach (self::ANALYST_DATA_TYPES as $type) {
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

    public function fetchChildNotesAndOpinions(array $user, array $analystData, $depth = 2): array
    {
        if ($depth == 0 || !empty($this->fetchedUUIDFromRecursion[$analystData['uuid']])) {
            $hasMoreNotesOrOpinions =  $this->hasMoreNotesOrOpinions($analystData, $user);
            $analystData['_max_depth_reached'] = $hasMoreNotesOrOpinions;
            return $analystData;
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

        // recursively fetch and include nested notes and opinions
        $childNotes = array_map(function ($item) use ($user, $depth) {
            $expandedNotes = $this->fetchChildNotesAndOpinions($user, $item['Note'], $depth-1);
            return $expandedNotes;
        }, $this->Note->find('all', $paramsNote));
        $childOpinions = array_map(function ($item) use ($user, $depth) {
            $expandedNotes = $this->fetchChildNotesAndOpinions($user, $item['Opinion'], $depth-1);
            return $expandedNotes;
        }, $this->Opinion->find('all', $paramsOpinion));

        if (!empty($childNotes)) {
            foreach ($childNotes as $childNote) {
                $this->fetchedUUIDFromRecursion[$childNote['uuid']] = true;
            }
            $analystData['Note'] = $childNotes;
        }
        if (!empty($childOpinions)) {
            foreach ($childNotes as $childNote) {
                $this->fetchedUUIDFromRecursion[$childNote['uuid']] = true;
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

    public function getChildren($user, $uuid, $depth=2): array
    {
        $analystData = $this->fetchSimple($user, $uuid);
        if (empty($analystData)) {
            return [];
        }
        $analystData = $analystData[$this->alias];
        $this->Note = ClassRegistry::init('Note');
        $this->Opinion = ClassRegistry::init('Opinion');
        $analystData = $this->fetchChildNotesAndOpinions($user, $analystData, $depth);
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
     * @return array Result of the capture including successes, fails and errors
     */
    public function captureAnalystData(array $user, array $analystData, $fromPull=false, $orgUUId=false, $server=false): array
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
                    $captureResult = $this->{$childType}->captureAnalystData($user, $childAnalystData, $fromPull, $orgUUId, $server);
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
            $saveSuccess = true;
        } else {
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
     * Push Analyst Data to remote server. Collect elligible data locally and propose the list to the remote.
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

        $analystData = $this->collectDataForPush($serverSync->server());
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
     * Collect elligible data to be pushed on a server
     *
     * @param array $user
     * @return array
     */
    public function collectDataForPush(array $server): array
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
        $dataForPush = $this->getAllAnalystData('all', $options);
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
            if (!in_array($analystData['Orgc']['id'], $push_rules['orgs']['OR'])) {
                return false;
            }
        }
        if (!empty($push_rules['orgs']['NOT'])) {
            if (in_array($analystData['Orgc']['id'], $push_rules['orgs']['NOT'])) {
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
        $validModels = [
            'Note' => ClassRegistry::init('Note'),
            'Opinion' => ClassRegistry::init('Opinion'),
            'Relationship' => ClassRegistry::init('Relationship'),
        ];

        $allData = ['Note' => [], 'Opinion' => [], 'Relationship' => []];
        foreach ($allIncomingAnalystData as $model => $entries) {
            $incomingAnalystData = $entries;
            $incomingUuids = array_keys($entries);
            $options = [
                'conditions' => ["{$model}.uuid" => $incomingUuids],
                'recursive' => -1,
                'fields' => ['uuid', 'modified', 'locked']
            ];
            $analystData = $validModels[$model]->find('all', $options);
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

    public function indexMinimal(array $user, $filters = []): array
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
        $tmp = $this->getAllAnalystData('all', $options);
        $allData = [];
        foreach ($tmp as $type => $entries) {
            foreach ($entries as $i => $entry) {
                $entry = $entry[$type];
                $allData[$type][$entry['uuid']] = $entry['modified'];
            }
        }
        return $allData;
    }

    /**
     * getAllAnalystData Collect all analyst data regardless if they are notes, opinions or relationships
     *
     * @param array $user
     * @return array
     */
    public function getAllAnalystData($findType='all', array $findOptions=[]): array
    {
        $allData = [];
        $validModels = [
            'Note' => ClassRegistry::init('Note'),
            'Opinion' => ClassRegistry::init('Opinion'),
            'Relationship' => ClassRegistry::init('Relationship'),
        ];
        foreach ($validModels as $model) {
            $result = $model->find($findType, $findOptions);
            $allData[$model->alias] = $result;
        }
        return $allData;
    }

    public function uploadEntryToServer($type, array $analystData, array $server, ServerSyncTool $serverSync, array $user)
    {
        $analystDataID = $analystData[$type]['id'];
        $analystData = $this->prepareForPushToServer($type, $analystData, $server);
        if (is_numeric($analystData)) {
            return $analystData;
        }

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
            $remoteData = $serverSync->fetchIndexMinimal($filterRules)->json();
        } catch (Exception $e) {
            $this->logException("Could not fetch analyst data IDs from server {$serverSync->server()['Server']['name']}", $e);
            return 0;
        }

        $allRemoteUUIDs = [];
        if (empty($remoteData)) {
            return 0;
        }
        foreach (self::ANALYST_DATA_TYPES as $type) {
            if (isset($remoteData[$type])) {
                $allRemoteUUIDs = array_merge($allRemoteUUIDs, array_keys($remoteData[$type]));
            }
        }

        $localAnalystData = $this->getAllAnalystData('list', [
            'conditions' => ['uuid' => $allRemoteUUIDs],
            'fields' => ['uuid', 'modified'],
        ]);

        $remoteUUIDsToFetch = [];
        foreach ($remoteData as $type => $remoteAnalystData) {
            foreach ($remoteAnalystData as $remoteUUID => $remoteModified) {
                if (!isset($localAnalystData[$type][$remoteUUID])) {
                    $remoteUUIDsToFetch[$type][$remoteUUID] = $remoteModified;
                } elseif (strtotime($localAnalystData[$type][$remoteUUID]) < strtotime($remoteModified)) {
                    $remoteUUIDsToFetch[$type][$remoteUUID] = $remoteModified;
                }
            }
        }
        unset($remoteData, $allRemoteUUIDs, $localAnalystData);

        if (empty($remoteUUIDsToFetch)) {
            return 0;
        }

        return $this->pullInChunks($user, $remoteUUIDsToFetch, $serverSync);
    }

    private function pullInChunks(array $user, array $analystDataUuids, ServerSyncTool $serverSync)
    {
        $saved = 0;
        $serverOrgUUID = $this->Org->find('first', [
            'recursive' => -1,
            'conditions' => ['id' => $serverSync->server()['Server']['org_id']],
            'fields' => ['id', 'uuid']
        ])['Organisation']['uuid'];

        foreach ($analystDataUuids as $type => $entries) {
            $uuids = array_keys($entries);
            if (empty($uuids)) {
                continue;
            }

            foreach (array_chunk($uuids, 100) as $uuidChunk) {
                try {
                    $chunkedAnalystData = $serverSync->fetchAnalystData($type, $uuidChunk)->json();
                } catch (Exception $e) {
                    $this->logException("Failed downloading the chunked analyst data from {$serverSync->server()['Server']['name']}.", $e);
                    continue;
                }
    
                foreach ($chunkedAnalystData as $analystData) {
                    $analystData = $this->updatePulledBeforeInsert($analystData, $type, $serverSync->server(), $user, $serverSync->pullRules());
                    $savedResult = $this->captureAnalystData($user, $analystData, true, $serverOrgUUID, $serverSync->server());
                    if ($savedResult['success']) {
                        $saved += $savedResult['imported'];
                    }
                }
            }
        }

        return $saved;
    }

    private function updatePulledBeforeInsert(array $analystData, $type, array $server, array $user, array $pullRules): array
    {
        $analystData[$type]['locked'] = true;

        if (empty(Configure::read('MISP.host_org_id')) || !$server['Server']['internal'] ||  Configure::read('MISP.host_org_id') != $server['Server']['org_id']) {
            switch ($analystData[$type]['distribution']) {
                case 1:
                    // if community only, downgrade to org only after pull
                    $analystData[$type]['distribution'] = '0';
                    break;
                case 2:
                    // if connected communities downgrade to community only
                    $analystData[$type]['distribution'] = '1';
                    break;
            }
        }
        return $analystData;
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
