<?php
App::uses('AppModel', 'Model');

/**
 * On demand correlation behaviour
 */
class OnDemandCorrelationBehavior extends ModelBehavior
{
    const TABLE_NAME = 'default_correlations';

    const CONFIG = [
        'AttributeFetcher' => [
            'fields' =>  [
                'Attribute.event_id',
                'Attribute.object_id',
                'Attribute.id',
                'Attribute.type',
                'Attribute.distribution',
                'Attribute.sharing_group_id',
                'Attribute.value1',
                'Attribute.value2',
            ],
            'contain' => [
                'Event' => [
                    'fields' => [
                        'Event.id',
                        'Event.orgc_id',
                        'Event.org_id',
                        'Event.distribution',
                        'Event.sharing_group_id',
                        'Event.disable_correlation',
                        'Event.info',
                    ]
                ],
                'Object' => [
                    'fields' => [
                        'Object.id',
                        'Object.distribution',
                        'Object.sharing_group_id',
                    ]
                ]
            ],
        ]
    ];

    /** @var Correlation */
    public $Correlation;

    private $deadlockAvoidance = false;

    private $correlatingTypes = [];
    private $value2CorrelatingTypes = [];
    private $correlationExclusions = [
        'substringMatch' => [],
        'startsWithMatch' => [],
        'endsWithMatch' => [],
        'fullMatch' => []
    ];

    private $customIndices = [
        'attributes' => [
            'idx_val1_source' => false,
            'idx_val1_target' => false,
            'idx_val2_target' => false,
            'idx_val2_source' => false
        ]
    ];

    private $_nonCorrelatingEvents = [];

    public function onDemandEngine() {
        return true;
    }

    public function setup(Model $Model, $settings = [])
    {
        $Model->useTable = self::TABLE_NAME;
        $this->Correlation = $Model;
        $this->deadlockAvoidance = $settings['deadlockAvoidance'];
        $this->correlatingTypes = array_diff(array_keys($this->Correlation->Attribute->generateTypeDefinitions()), $this->Correlation->Attribute::NON_CORRELATING_TYPES);
        $this->value2CorrelatingTypes = array_diff($this->correlatingTypes, $this->Correlation->Attribute::PRIMARY_ONLY_CORRELATING_TYPES);
        $CorrelationExclusion = ClassRegistry::init('CorrelationExclusion');
        $temp = $CorrelationExclusion->find('column', [
            'recursive' => -1,
            'fields' => ['value']
        ]);
        foreach ($temp as $exclusion) {
            if ($exclusion[0] === '%' && $exclusion[-1] === '%') {
                $this->correlationExclusions['substringMatch'][] = trim($exclusion, '%');
            } else if ($exclusion[0] === '%') {
                $this->correlationExclusions['startsWithMatch'][] = trim($exclusion, '%');
            } else if ($exclusion[-1] === '%') {
                $this->correlationExclusions['endsWithMatch'][] = trim($exclusion, '%');
            } else {
                $this->correlationExclusions['fullMatch'][] = $exclusion;
            }
        }
        foreach ($this->customIndices as $table => $indices) {
            foreach ($indices as $index => $status) {
                $this->customIndices[$table][$index] = $this->Correlation->indexExists($table, $index);
            }
        }
    }

    public function getTableName(Model $Model)
    {
        return self::TABLE_NAME;
    }

    /**
     * @param Model $Model
     * @param string $value
     * @param array $a
     * @param array $b
     * @return array
     */
    public function createCorrelationEntry(Model $Model, $value, $a, $b)
    {
        return true;
    }

    public function saveCorrelations(Model $Model, array $correlations)
    {
        return true;
    }

    public function runBeforeSaveCorrelation(Model $Model, $attribute)
    {
        return true;
    }

    // return true if there's a hit for an exclusion
    private function checkForExclusion($value)
    {   
        if (in_array($value, $this->correlationExclusions['fullMatch'])) {
            return true;
        }
        foreach ($this->correlationExclusions['substringMatch'] as $pattern) {
            if (str_contains($value, $pattern)) {
                return true;
            }
        }
        foreach ($this->correlationExclusions['startsWithMatch'] as $pattern) {
            if (str_starts_with($value, $pattern)) {
                return true;
            }
        }
        foreach ($this->correlationExclusions['endsWithMatch'] as $pattern) {
            if (str_ends_with($value, $pattern)) {
                return true;
            }
        }
    }

    public function getContainRules(Model $Model, $filter = null)
    {
        if (empty($filter)) {
            return self::CONFIG['AttributeFetcher']['contain'];
        } else {
            return empty(self::CONFIG['AttributeFetcher']['contain'][$filter]) ? false : self::CONFIG['AttributeFetcher']['contain'][$filter];
        }
    }

    public function getFieldRules(Model $Model)
    {
        return self::CONFIG['AttributeFetcher']['fields'];
    }


    /**
     * Fetch correlations for given event.
     * @param array $user
     * @param int|array $eventId
     * @param array $sgids
     * @param bool $primary
     * @return array
     */
    private function __collectCorrelations($eventId)
    {
        if ($this->_checkEventCanCorrelate($eventId) === false) {
            return [];
        }
        $eventId = (int)$eventId;
        $max_correlations = Configure::read('MISP.max_correlations_per_event') ?: 5000;
        $max_value_correlation = Configure::read('MISP.correlation_limit') ?: 20;
        $corrValueCounts = [];
        $flat = [];
        $queryRuns = [
            ['a' => 'value1', 'b' => 'value1'],
            ['a' => 'value1', 'b' => 'value2'],
            ['a' => 'value2', 'b' => 'value1'],
            ['a' => 'value2', 'b' => 'value2']
        ];
        foreach ($queryRuns as $pair) {
            if (
                $pair['a'] === 'value2' &&
                $pair['b'] === 'value2'
            ) {
                if (!$max_correlations) {
                    continue;
                }
                $this->Correlation->query("
                CREATE TEMPORARY TABLE tmp_source_values (
                    value2 VARCHAR(64) PRIMARY KEY,
                    id INT(10) UNSIGNED NOT NULL
                ) ENGINE=MEMORY;");
                $this->Correlation->query("
                        INSERT INTO tmp_source_values (value2, id)
                        SELECT a.value2, MIN(a.id) as id
                        FROM attributes a
                        WHERE
                            a.event_id = ? AND
                            a.value2 <> '' AND
                            a.deleted = 0 AND
                            a.disable_correlation = 0 AND
                            a.type IN ('" . implode("','", $this->value2CorrelatingTypes) . "')
                        GROUP BY a.value2
                    ",
                    [$eventId]
                );
                $use_index = $this->customIndices['attributes']['idx_val2_target'] ? 'FORCE INDEX (`idx_val2_target`)' : '';
                $sql = "
                    SELECT 
                        target.id AS id,
                        target.event_id AS event_id,
                        target.value2 AS 'value',
                        target.type,
                        source.id AS source_id
                    FROM attributes AS target " . $use_index . "
                    JOIN tmp_source_values source
                    ON target.value2 = source.value2
                    WHERE
                        target.event_id != ? AND
                        target.value2 <> '' AND
                        target.deleted = 0 AND
                        target.disable_correlation = 0 AND
                        target.type IN ('" . implode("','", $this->value2CorrelatingTypes) . "')
                    LIMIT " . $max_correlations
                ;
                $chunk = $this->Correlation->Attribute->query($sql, [$eventId]);
                $this->Correlation->Attribute->query('DROP TABLE tmp_source_values');
                $result_count = count($chunk);
                if ($result_count >= $max_correlations) {
                    $max_correlations = 0;
                } else {
                    $max_correlations = $max_correlations - $result_count;
                }
                foreach ($chunk as $row) {
                    if (isset($corrValueCounts[$row['target']['value']])) {
                        $corrValueCounts[$row['target']['value']] += 1;
                    } else {
                        $corrValueCounts[$row['target']['value']] = 1;
                    }
                    if (
                        $this->Correlation->CorrelationRule->checkEventIds($eventId, $row['target']['event_id']) &&
                        !$this->checkForExclusion($row['target']['value'])
                    ) {
                        $flat[] = array_merge(
                            $row['target'],
                            [
                                'source_id' => $row['source']['source_id'] ?? $row['source']['id'],
                                'source_event_id' => $eventId
                            ]
                        );
                    }
                }
            } else {
                if (!$max_correlations) {
                    continue;
                }

                $indexHints = [
                    'value1:value1' => ['source' => 'idx_val1_source', 'target' => 'idx_val1_target'],
                    'value1:value2' => ['source' => 'idx_val1_source', 'target' => 'idx_val2_target'],
                    'value2:value1' => ['source' => 'idx_val2_source', 'target' => 'idx_val1_target'],
                ];
                
                $key = "{$pair['a']}:{$pair['b']}";
                $sourceIndex = $this->customIndices['attributes'][$indexHints[$key]['source']] ? "FORCE INDEX (`{$indexHints[$key]['source']}`)" : '';
                $targetIndex = $this->customIndices['attributes'][$indexHints[$key]['source']] ? "FORCE INDEX (`{$indexHints[$key]['target']}`)" : '';


                $sql = "
                    SELECT 
                        target.id AS id,
                        target.event_id AS event_id,
                        source.id AS source_id,
                        target.{$pair['b']} AS 'value',
                        target.type
                    FROM attributes AS source {$sourceIndex}
                    JOIN attributes AS target {$targetIndex}
                        ON source.{$pair['a']} = target.{$pair['b']}
                    WHERE
                        source.event_id = ? AND target.event_id != ?
                        AND source.deleted = 0 AND target.deleted = 0
                        AND source.disable_correlation = 0 AND target.disable_correlation = 0
                        AND source.{$pair['a']} != ''
                        AND target.{$pair['b']} != ''
                        AND source.type IN ('" . implode("','", $this->correlatingTypes) . "')
                        AND target.type IN ('" . implode("','", $this->correlatingTypes) . "')
                    LIMIT " . $max_correlations
                ;
                $chunk = $this->Correlation->Attribute->query($sql, [$eventId, $eventId]);
                $result_count = count($chunk);
                if ($result_count >= $max_correlations) {
                    $max_correlations = 0;
                } else {
                    $max_correlations = $max_correlations - $result_count;
                }
                foreach ($chunk as $row) {
                    if (isset($corrValueCounts[$row['target']['value']])) {
                        $corrValueCounts[$row['target']['value']] += 1;
                    } else {
                        $corrValueCounts[$row['target']['value']] = 1;
                    }

                    if (!$this->_checkEventCanCorrelate($row['target']['event_id'])) {
                        continue;
                    }

                    // yeet correlations that would trip over correlation rules
                    if (
                        $this->Correlation->CorrelationRule->checkEventIds($eventId, $row['target']['event_id']) &&
                        !$this->checkForExclusion($row['target']['value'])
                    ) {
                        $flat[] = array_merge(
                            $row['target'],
                            [
                                'source_id' => $row['source']['source_id'] ?? $row['source']['id'],
                                'source_event_id' => $eventId
                            ]
                        );
                    }
                }
            }
        }
        
        foreach ($flat as $k => $corr) {
            if ($corrValueCounts[$corr['value']] > $max_value_correlation) {
                unset($flat[$k]);
            }
        }
        $flat = array_values($flat);
        return $flat;
    }

    public function _checkEventCanCorrelate($eventId)
    {
        if (isset($this->__nonCorrelatingEvents[$eventId])) {
            return !$this->__nonCorrelatingEvents[$eventId];
        }
        $result = $this->Correlation->Event->find('column', [
            'recursive' => -1,
            'fields' => ['disable_correlation'],
            'conditions' => [
                'Event.id' => $eventId
            ]
        ]);
        return isset($result[0]) ? !$result[0] : false;
    }

    /**
     * @param Correlation $Model
     * @param array $user
     * @param int|array $id Event ID
     * @param array $sgids
     * @return array
     */
    public function runGetAttributesRelatedToEvent(Model $Model, $user, $id, $sgids)
    {
        $correlations = $this->__collectCorrelations($id);
        if (empty($correlations)) {
            return [];
        }
        $eventIds = [];
        foreach ($correlations as $correlation) {
            $eventIds[$correlation['event_id']] = true;
        }
        $conditions = ['Event.id' => array_keys($eventIds)];
        $events = $Model->Event->find('all', [
            'recursive' => -1,
            'conditions' => $conditions,
            'fields' => ['Event.id', 'Event.orgc_id', 'Event.info', 'Event.date'],
        ]);
        $events = array_column(array_column($events, 'Event'), null, 'id');
        $relatedAttributes = [];
        foreach ($correlations as $correlation) {
            $eventId = $correlation['event_id'];
            if (!isset($events[$eventId])) {
                continue;
            }
            $event = $events[$eventId];
            $relatedAttributes[$correlation['source_id']][] = [
                'id' => $correlation['event_id'],
                'attribute_id' => $correlation['id'],
                'parent_id' => $correlation['source_id'],
                'value' => $correlation['value'],
                'org_id' => $event['orgc_id'],
                'date' => $event['date'],
                'info' => $event['info']
            ];
        }
        return $relatedAttributes;
    }

    public function runGetRelatedAttributes(Model $Model, $user, $sgids, $attribute, $fields = [], $includeEventData = false)
    {

        $conditions = [
            [
                'Correlation.1_event_id !=' => $attribute['event_id'],
                'Correlation.attribute_id' => $attribute['id']
            ],
            [
                'Correlation.event_id !=' => $attribute['event_id'],
                'Correlation.1_attribute_id' => $attribute['id']
            ]
        ];
        $corr_fields = [
            [
                '1_attribute_id',
                '1_object_id',
                '1_distribution',
                '1_object_distribution',
                '1_event_distribution',
                '1_sharing_group_id',
                '1_object_sharing_group_id',
                '1_event_sharing_group_id',
                '1_org_id',
            ],
            [
                'attribute_id',
                'object_id',
                'distribution',
                'object_distribution',
                'event_distribution',
                'sharing_group_id',
                'object_sharing_group_id',
                'event_sharing_group_id',
                'org_id',
            ]
        ];
        $prefixes = ['1_', ''];
        $correlatedAttributeIds = [];
        foreach ($conditions as $k => $condition) {
            $temp_correlations = $Model->find('all', [
                'recursive' => -1,
                'conditions' => $condition,
                'fields' => $corr_fields[$k]
            ]);
            if (!empty($temp_correlations)) {
                foreach ($temp_correlations as $temp_correlation) {
                    if (empty($user['Role']['perm_site_admin'])) {
                        if (!$this->checkCorrelationACL($user, $temp_correlation, $sgids, $prefixes[$k])) {
                            continue;
                        }
                    }
                    $correlatedAttributeIds[] = $temp_correlation['Correlation'][$prefixes[$k] . 'attribute_id'];
                }
            }
        }

        if (empty($correlatedAttributeIds)) {
            return [];
        }

        $contain = [];
        if (!empty($includeEventData)) {
            $contain['Event'] = [
                'fields' => [
                    'Event.id',
                    'Event.uuid',
                    'Event.threat_level_id',
                    'Event.analysis',
                    'Event.info',
                    'Event.extends_uuid',
                    'Event.distribution',
                    'Event.sharing_group_id',
                    'Event.published',
                    'Event.date',
                    'Event.orgc_id',
                    'Event.org_id'
                ]
            ];
        }
        $relatedAttributes = $Model->Attribute->find('all', [
            'recursive' => -1,
            'conditions' => [
                'Attribute.id' => $correlatedAttributeIds
            ],
            'fields' => $fields,
            'contain' => $contain
        ]);
        if (!empty($includeEventData)) {
            $results = [];
            foreach ($relatedAttributes as $attribute) {
                $temp = $attribute['Attribute'];
                $temp['Event'] = $attribute['Event'];
                $results[] = $temp;
            }
            return $results;
        } else {
            return $relatedAttributes;
        }
    }

    /**
     * @param Correlation $Model
     * @param array $user Not used
     * @param int $eventId
     * @param array $sgids Not used
     * @return array
     */
    public function fetchRelatedEventIds(Model $Model, array $user, int $eventId, array $sgids)
    {
        return $this->__filterRelatedEvents($Model, $user, $eventId, $sgids, false);
    }

    /**
     * @param Model $Model
     * @param array $user Not used
     * @param int $eventId
     * @param array $sgids Not used
     * @param bool $primary Not used
     * @return array|int[]
     */
    private function __filterRelatedEvents(Model $Model, array $user, int $eventId, array $sgids, bool $primary)
    {
        $correlations = $this->__collectCorrelations($eventId);
        $eventIds = [];
        foreach ($correlations as $correlation) {
            $eventIds[$correlation['event_id']] = true;
        }
        return array_keys($eventIds);
        
    }

    /**
     * @param array $user
     * @param array $correlation
     * @param array $sgids
     * @param string $prefix
     * @return bool
     */
    private function checkCorrelationACL(array $user, $correlation, $sgids, $prefix)
    {
        return true;
    }

    public function updateContainedCorrelations(
        Model $Model,
        array $data,
        string $type = 'event',
        array $options = []
    )
    {
        return true;
    }

    public function purgeCorrelations(Model $Model, $eventId = null)
    {
        return true;
    }

    public function purgeByValue(Model $Model, string $value)
    {
        return true;
    }
}
