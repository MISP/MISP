<?php
App::uses('AppModel', 'Model');

/**
 * ACL-less correlation behaviour for end-point instances
 */
class NoAclCorrelationBehavior extends ModelBehavior
{
    const TABLE_NAME = 'no_acl_correlations';

    const CONFIG = [
        'AttributeFetcher' => [
            'fields' =>  [
                'Attribute.event_id',
                'Attribute.id',
                'Attribute.type',
                'Attribute.value1_id',
                'Attribute.value2_id',
            ],
            'contain' => [
                'Event' => [
                    'fields' => [
                        'Event.id',
                        'Event.disable_correlation',
                        'Event.orgc_id',
                        'Event.org_id',
                        'Event.distribution',
                        'Event.sharing_group_id',
                        'Event.info',
                    ]
                ]
            ],
        ]
    ];

    /** @var Correlation */
    public $Correlation;

    /** @var bool */
    private $deadlockAvoidance = false;

    public function setup(Model $Model, $settings = [])
    {
        $Model->useTable = self::TABLE_NAME;
        $this->Correlation = $Model;
        $this->deadlockAvoidance = $settings['deadlockAvoidance'];
    }

    public function getTableName(Model $Model)
    {
        return self::TABLE_NAME;
    }

    public function onDemandEngine() {
        return false;
    }

    /**
     * @param Model $Model
     * @param string $value
     * @param array $a
     * @param array $b
     * @return array|int[]
     */
    public function createCorrelationEntry(Model $Model, $value, $a, $b)
    {
        if ($this->deadlockAvoidance) {
            return [
                'value_id' => $value,
                '1_event_id' => $a['Event']['id'],
                '1_attribute_id' => $a['Attribute']['id'],
                'event_id' => $b['Event']['id'],
                'attribute_id' => $b['Attribute']['id']
            ];
        } else {
            return [
                $value,
                (int) $a['Event']['id'],
                (int) $a['Attribute']['id'],
                (int) $b['Event']['id'],
                (int) $b['Attribute']['id']
            ];
        }
    }

    /**
     * @param Model $Model
     * @param array $correlations
     * @return bool
     */
    public function saveCorrelations(Model $Model, array $correlations)
    {
        $fields = [
            'value_id',
            '1_event_id',
            '1_attribute_id',
            'event_id',
            'attribute_id'
        ];

        if ($this->deadlockAvoidance) {
            return $this->Correlation->saveMany($correlations, [
                'atomic' => false,
                'callbacks' => false,
                'deep' => false,
                'validate' => false,
                'fieldList' => $fields,
            ]);
        } else {
            $db = $this->Correlation->getDataSource();
            // Split to chunks datasource is is enabled
            if (count($correlations) > 100) {
                foreach (array_chunk($correlations, 100) as $chunk) {
                    $db->insertMulti(self::TABLE_NAME, $fields, $chunk);
                }
                return true;
            } else {
                return $db->insertMulti(self::TABLE_NAME, $fields, $correlations);
            }
        }
    }

    public function runBeforeSaveCorrelation(Model $Model, $attribute)
    {
        // (update-only) clean up the relation of the old value: remove the existing relations related to that attribute, we DO have a reference, the id
        // ==> DELETE FROM no_acl_correlations WHERE 1_attribute_id = $a_id OR attribute_id = $a_id; */
        // first check if it's an update
        if (isset($attribute['id'])) {
            $Model->deleteAll([
                'OR' => [
                    '1_attribute_id' => $attribute['id'],
                    'attribute_id' => $attribute['id']
                ],
            ], false);
        }
        if ($attribute['type'] === 'ssdeep') {
            $this->FuzzyCorrelateSsdeep = ClassRegistry::init('FuzzyCorrelateSsdeep');
            $this->FuzzyCorrelateSsdeep->purge(null, $attribute['id']);
        }
    }

    /**
     * @param Model $Model
     * @param string|null $filter
     * @return false|mixed
     */
    public function getContainRules(Model $Model, $filter = null)
    {
        if (empty($filter)) {
            return self::CONFIG['AttributeFetcher']['contain'];
        } else {
            return self::CONFIG['AttributeFetcher']['contain'][$filter] ?? false;
        }
    }

    public function getFieldRules(Model $Model)
    {
        return self::CONFIG['AttributeFetcher']['fields'];
    }

    /**
     * @param array $user
     * @param int $eventId
     * @param bool $primary
     * @return array
     */
    private function __collectCorrelations(array $user, $eventId, $primary)
    {
        $max_correlations = Configure::read('MISP.max_correlations_per_event') ?: 5000;
        $source = $primary ? '' : '1_';
        $prefix = $primary ? '1_' : '';
        $display = $this->Correlation->displayValueQuery('Correlation.' . $prefix . 'attribute_id');
        return $this->Correlation->find('all', [
            'fields' => [
                $source . 'attribute_id',
                $prefix . 'attribute_id',
                $prefix . 'event_id',
                $display['field']
            ],
            'conditions' => [
                'OR' => [
                    'Correlation.' . $source . 'event_id' => $eventId
                ],
                'AND' => $this->Correlation->excludedValueConditions()
            ],
            'recursive' => -1,
            'joins' => $display['joins'],
            'order' => false,
            'limit' => $max_correlations
        ]);
    }

    /**
     * @param Model $Model
     * @param array $user
     * @param int|array $id Event ID
     * @return array
     */
    public function runGetAttributesRelatedToEvent(Model $Model, array $user, $id)
    {
        $correlations = [];
        $eventIds = [];

        $temp_correlations = $this->__collectCorrelations($user, $id, false);
        foreach ($temp_correlations as $temp_correlation) {
            $correlations[] = [
                'id' => $temp_correlation['Correlation']['event_id'],
                'attribute_id' => $temp_correlation['Correlation']['attribute_id'],
                'parent_id' => $temp_correlation['Correlation']['1_attribute_id'],
                'value' => isset($temp_correlation[0]['display_value']) ? $temp_correlation[0]['display_value'] : '',
            ];
            $eventIds[$temp_correlation['Correlation']['event_id']] = true;
        }

        $temp_correlations = $this->__collectCorrelations($user, $id, true);
        foreach ($temp_correlations as $temp_correlation) {
            $correlations[] = [
                'id' => $temp_correlation['Correlation']['1_event_id'],
                'attribute_id' => $temp_correlation['Correlation']['1_attribute_id'],
                'parent_id' => $temp_correlation['Correlation']['attribute_id'],
                'value' => isset($temp_correlation[0]['display_value']) ? $temp_correlation[0]['display_value'] : '',
            ];
            $eventIds[$temp_correlation['Correlation']['1_event_id']] = true;
        }
        if (empty($correlations)) {
            return [];
        }
        $conditions = [
            'Event.id' => array_keys($eventIds)
        ];
        $events = $Model->Event->find('all', array(
            'recursive' => -1,
            'conditions' => $conditions,
            'fields' => ['Event.id', 'Event.orgc_id', 'Event.info', 'Event.date'],
        ));

        $events = array_column(array_column($events, 'Event'), null, 'id');
        $relatedAttributes = [];
        foreach ($correlations as $correlation) {
            $eventId = $correlation['id'];
            if (!isset($events[$eventId])) {
                continue;
            }
            $event = $events[$eventId];
            $correlation['org_id'] = $event['orgc_id'];
            $correlation['info'] = $event['info'];
            $correlation['date'] = $event['date'];
            $parentId = $correlation['parent_id'];
            unset($correlation['parent_id']);
            $relatedAttributes[$parentId][] = $correlation;
        }
        return $relatedAttributes;
    }

    /**
     * @param Correlation $Model
     * @param array $user Not used
     * @param array $sgids Not used
     * @param array $attribute
     * @param array $fields Attribute fields to fetch
     * @param bool $includeEventData
     * @param bool $valueText See Correlation::getRelatedAttributes()
     * @return array
     */
    public function runGetRelatedAttributes(Model $Model, $user, $sgids, $attribute, $fields = [], $includeEventData = false, $valueText = true)
    {
        $correlatedAttributeIds = $Model->find('column', [
            'conditions' => [
                'Correlation.1_event_id !=' => $attribute['event_id'],
                'Correlation.attribute_id' => $attribute['id'],
            ],
            'fields' => ['1_attribute_id'],
        ]);

        $correlatedAttributeIds2 = $Model->find('column', [
            'conditions' => [
                'Correlation.event_id !=' => $attribute['event_id'],
                'Correlation.1_attribute_id' => $attribute['id'],
            ],
            'fields' => ['attribute_id'],
        ]);
        foreach ($correlatedAttributeIds2 as $tempCorrelation) {
            $correlatedAttributeIds[] = $tempCorrelation;
        }

        if (empty($correlatedAttributeIds)) {
            return [];
        }

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
        } else {
            $contain = [];
        }

        $relatedAttributes = $Model->Attribute->find('all', [
            'recursive' => -1,
            'conditions' => [
                'Attribute.id' => $correlatedAttributeIds
            ],
            'fields' => $fields,
            'contain' => $contain,
            'valueText' => $valueText,
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
     * Fetch correlations scoped to specific attribute IDs.
     * NoAcl variant — no per-correlation ACL checks, only
     * event-level visibility is enforced.
     *
     * @param Model $Model
     * @param array $user
     * @param int $eventId
     * @param array $sgids Not used
     * @param array $attributeIds
     * @return array Keyed by source attribute ID
     */
    public function runGetAttributeCorrelations(
        Model $Model,
        array $user,
        $eventId,
        array $sgids,
        array $attributeIds
    ) {
        $conditions = [
            [
                'Correlation.attribute_id' => $attributeIds,
                'Correlation.1_event_id !=' => $eventId,
            ],
            [
                'Correlation.1_attribute_id' => $attributeIds,
                'Correlation.event_id !=' => $eventId,
            ],
        ];
        $fields = [
            [
                'attribute_id', '1_attribute_id',
                '1_event_id', 'value_id',
            ],
            [
                '1_attribute_id', 'attribute_id',
                'event_id', 'value_id',
            ],
        ];
        $sourceFields = ['', '1_'];
        $prefixes = ['1_', ''];

        $correlations = [];
        $eventIds = [];
        foreach ($conditions as $k => $condition) {
            $display = $Model->displayValueQuery('Correlation.' . $prefixes[$k] . 'attribute_id');
            $rows = $Model->find('all', [
                'recursive' => -1,
                'conditions' => $condition,
                'fields' => array_merge($fields[$k], [$display['field']]),
                'joins' => $display['joins'],
            ]);
            $prefix = $prefixes[$k];
            $sourceField = $sourceFields[$k];
            foreach ($rows as $row) {
                $corr = $row['Correlation'];
                $parentId = $corr[
                    $sourceField . 'attribute_id'
                ];
                $targetEventId = $corr[
                    $prefix . 'event_id'
                ];
                $correlations[] = [
                    'id' => $targetEventId,
                    'attribute_id' => $corr[
                        $prefix . 'attribute_id'
                    ],
                    'parent_id' => $parentId,
                    'value' => isset($row[0]['display_value']) ? $row[0]['display_value'] : '',
                ];
                $eventIds[$targetEventId] = true;
            }
        }

        if (empty($correlations)) {
            return [];
        }


        // Event-level ACL only
        $eventConditions = $Model->Event
            ->createEventConditions($user);
        $eventConditions['Event.id'] = array_keys($eventIds);
        $events = $Model->Event->find('all', [
            'recursive' => -1,
            'conditions' => $eventConditions,
            'fields' => [
                'Event.id', 'Event.orgc_id',
                'Event.info', 'Event.date',
            ],
        ]);
        $events = array_column(
            array_column($events, 'Event'), null, 'id'
        );

        $result = [];
        foreach ($correlations as $corr) {
            $evId = $corr['id'];
            if (!isset($events[$evId])) {
                continue;
            }
            $event = $events[$evId];
            $parentId = $corr['parent_id'];
            $result[$parentId][] = [
                'id' => $evId,
                'attribute_id' => $corr['attribute_id'],
                'value' => $corr['value'],
                'org_id' => $event['orgc_id'],
                'info' => $event['info'],
                'date' => $event['date'],
            ];
        }
        return $result;
    }

    /**
     * @param Correlation $Model
     * @param array $user Not used
     * @param int $eventId
     * @param array $sgids Not used
     * @param bool $excludeNonCorrelating Restrict the result to the events that
     *      runGetAttributesRelatedToEvent() can actually show a correlation for
     * @return array
     */
    public function fetchRelatedEventIds(Model $Model, array $user, int $eventId, array $sgids, bool $excludeNonCorrelating = false)
    {
        if ($excludeNonCorrelating) {
            // The same set runGetAttributesRelatedToEvent() lists: no value held
            // in correlation_exclusions or over_correlating_values, and no more
            // than max_correlations_per_event correlations read each way.
            $limit = Configure::read('MISP.max_correlations_per_event') ?: 5000;
            list($eventIds) = $this->__correlatingEventIds($eventId, $limit);
            return $eventIds;
        }
        $primaryEventIds = $this->__filterRelatedEvents($Model, $eventId, true);
        $secondaryEventIds = $this->__filterRelatedEvents($Model, $eventId, false);
        return array_unique(array_merge($primaryEventIds, $secondaryEventIds), SORT_REGULAR);
    }

    /**
     * How many events fetchRelatedEventIds(..., true) finds within $limit
     * correlations each way, and whether either way held more.
     *
     * @param Correlation $Model
     * @param array $user Not used
     * @param int $eventId
     * @param array $sgids Not used
     * @param int $limit
     * @return array [int $count, bool $more]
     */
    public function fetchRelatedEventCount(Model $Model, array $user, int $eventId, array $sgids, int $limit)
    {
        list($eventIds, $read) = $this->__correlatingEventIds($eventId, $limit + 1);
        return [count($eventIds), $read > $limit];
    }

    /**
     * The events $eventId correlates with through a value that is neither
     * excluded nor over-correlating, read from at most $limit correlations each
     * way, one row per related event.
     *
     * @param int $eventId
     * @param int $limit
     * @return array [int[] $eventIds, int $read] the most correlations read one way
     */
    private function __correlatingEventIds(int $eventId, int $limit)
    {
        $db = $this->Correlation->getDataSource();
        $eventIds = [];
        $read = 0;
        foreach ([true, false] as $primary) {
            $source = $primary ? '' : '1_';
            $related = ($primary ? '1_' : '') . 'event_id';
            $inner = $db->buildStatement([
                'fields' => [$db->name('Correlation.' . $related)],
                'table' => $db->fullTableName($this->Correlation),
                'alias' => 'Correlation',
                'joins' => [[
                    'table' => $db->fullTableName($this->Correlation->CorrelationValue),
                    'alias' => 'CorrelationValue',
                    'type' => 'INNER',
                    'conditions' => ['CorrelationValue.id = Correlation.value_id'],
                ]],
                'conditions' => [
                    'Correlation.' . $source . 'event_id' => $eventId,
                    'CorrelationValue.value NOT IN (select value from correlation_exclusions)',
                    'CorrelationValue.value NOT IN (select value from over_correlating_values)',
                ],
                'order' => null,
                'group' => null,
                'limit' => $limit,
                'offset' => null,
            ], $this->Correlation);
            $rows = $db->fetchAll(
                sprintf(
                    'SELECT %1$s, COUNT(*) AS %2$s FROM (%3$s) AS %4$s GROUP BY %1$s',
                    $db->name($related),
                    $db->name('n'),
                    $inner,
                    $db->name('related')
                ),
                [],
                ['cache' => false]
            );
            $directionRead = 0;
            foreach ($rows as $row) {
                $row = ($row['related'] ?? []) + ($row[0] ?? []);
                $directionRead += (int)$row['n'];
                $eventIds[$row[$related]] = true;
            }
            $read = max($read, $directionRead);
        }
        return [array_keys($eventIds), $read];
    }

    /**
     * @param Correlation $Model
     * @param int $eventId
     * @param bool $primary
     * @return array
     */
    private function __filterRelatedEvents(Model $Model, int $eventId, bool $primary)
    {
        $current = $primary ? '' : '1_';
        $prefix = $primary ? '1_' : '';
        return $Model->find('column', [
            'recursive' => -1,
            'fields' => [
                $prefix . 'event_id'
            ],
            'conditions' => [
                $current . 'event_id' => $eventId
            ],
            'unique' => true,
        ]);
    }

    public function updateContainedCorrelations(
        Model $Model,
        array $data,
        string $type = 'event',
        array $options = []
    ): bool
    {
        // We don't care. No ACL means nothing to change.
        return true;
    }

    public function purgeCorrelations(Model $Model, $eventId = null)
    {
        if (!$eventId) {
            $Model->query('TRUNCATE TABLE no_acl_correlations;');
            //$Model->query('TRUNCATE TABLE over_correlating_values;');
        } else {
            $Model->deleteAll([
                'Correlation.event_id' => $eventId
            ], false);
            $Model->deleteAll([
                'Correlation.1_event_id' => $eventId
            ], false);
        }
    }

    /**
     * @param Correlation $Model
     * @param string $value
     * @return void
     */
    public function purgeByValue(Model $Model, string $value)
    {
        $condition = $Model->exclusionMatchCondition($value);
        if ($condition !== null) {
            $Model->deleteAll($condition, false);
        }
    }
}
