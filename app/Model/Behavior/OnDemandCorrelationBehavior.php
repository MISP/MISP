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
                'Attribute.value1_id',
                'Attribute.value2_id',
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

    private $_nonCorrelatingEvents = [];

    /**
     * Memoised output of __collectCorrelations(), keyed by event ID.
     * A single request resolves correlations for the same event more
     * than once (fetchEvent() asks for both the related events and the
     * related attributes), and every miss costs four self-joins over
     * the attributes table.
     * @var array
     */
    private $correlationCache = [];

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
     *
     * The returned set is always reduced to the correlations $user is
     * allowed to see - see __filterCorrelationsByAcl(). Every read path
     * of this engine funnels through here, so the filter is applied at
     * the single chokepoint rather than at each caller.
     *
     * @param array $user
     * @param int|array $eventId
     * @return array
     */
    private function __collectCorrelations(array $user, $eventId)
    {
        // The cached set is ACL-filtered, so it belongs to one user. A
        // single process does serve several: generatePeriodicSummary()
        // walks every subscribed user with both correlation flags set.
        // Without an id there is no safe key, so skip the cache rather
        // than risk handing one user another's correlations.
        $cacheKey = empty($user['id'])
            ? null
            : ((int)$eventId) . '-' . $user['id'];
        if ($cacheKey !== null && isset($this->correlationCache[$cacheKey])) {
            return $this->correlationCache[$cacheKey];
        }
        if ($this->_checkEventCanCorrelate($eventId) === false) {
            return $this->__cacheCorrelations($cacheKey, []);
        }
        $eventId = (int)$eventId;
        $max_correlations = Configure::read('MISP.max_correlations_per_event') ?: 5000;
        $max_value_correlation = Configure::read('MISP.correlation_limit') ?: 20;
        $found = [];
        $passes = [
            ['value1_id', 'value1_id'],
            ['value1_id', 'value2_id'],
            ['value2_id', 'value1_id'],
            ['value2_id', 'value2_id'],
        ];
        foreach ($passes as list($sourceColumn, $targetColumn)) {
            if ($max_correlations <= 0) {
                break;
            }
            $chunk = $this->Correlation->Attribute->query(
                $this->__passQuery($sourceColumn, $targetColumn, $max_correlations),
                [$eventId, $eventId, $eventId]
            );
            $max_correlations -= count($chunk);
            foreach ($chunk as $row) {
                // The columns land under their table aliases, or under 0
                $found[] = array_merge(...array_values($row));
            }
        }
        if (empty($found)) {
            return $this->__cacheCorrelations($cacheKey, []);
        }
        // Counted per exact target value, before any filter
        $corrValueCounts = array_count_values(array_column($found, 'value_id'));
        $correlatingEvents = $this->__correlatingEvents(array_column($found, 'event_id'));
        $flat = [];
        foreach ($found as $row) {
            if (
                $corrValueCounts[$row['value_id']] > $max_value_correlation ||
                !isset($correlatingEvents[$row['event_id']]) ||
                !$this->Correlation->CorrelationRule->checkEventIds($eventId, $row['event_id']) ||
                $this->Correlation->isExcludedValue($row['value'])
            ) {
                continue;
            }
            $flat[] = [
                'id' => $row['id'],
                'event_id' => $row['event_id'],
                'value' => $row['value'],
                'type' => $row['type'],
                'source_id' => $row['source_id'],
                'source_event_id' => $eventId,
            ];
        }
        $flat = $this->__filterCorrelationsByAcl($user, $flat);
        return $this->__cacheCorrelations($cacheKey, $flat);
    }

    /**
     * Attributes of other events holding a case variant of a value of the
     * event, one source column against one target column. A side reading
     * value2 takes only the types whose value2 correlates.
     *
     * Each distinct value is looked up once, then joined back to the event's
     * attributes; STRAIGHT_JOIN keeps that order, the optimizer undoes it.
     *
     * @param string $sourceColumn value1_id or value2_id
     * @param string $targetColumn value1_id or value2_id
     * @param int $limit
     * @return string Binds the event id three times
     */
    private function __passQuery($sourceColumn, $targetColumn, $limit)
    {
        $types = function ($column) {
            $types = $column === 'value2_id' ? $this->value2CorrelatingTypes : $this->correlatingTypes;
            return "'" . implode("', '", $types) . "'";
        };
        $excluded = function ($column) {
            $Attribute = $this->Correlation->Attribute;
            $types = $Attribute::NON_CORRELATING_TYPES;
            if ($column === 'value2_id') {
                $types = array_merge($types, $Attribute::PRIMARY_ONLY_CORRELATING_TYPES);
            }
            return "'" . implode("', '", $types) . "'";
        };
        return sprintf(
            "SELECT STRAIGHT_JOIN
                target.id AS id,
                target.event_id AS event_id,
                target_value.value AS value,
                target.type AS type,
                target.%2\$s AS value_id,
                source.id AS source_id
            FROM (
                SELECT DISTINCT %1\$s AS id
                FROM attributes
                WHERE
                    event_id = ? AND deleted = 0 AND disable_correlation = 0
                    AND type NOT IN (%6\$s) AND %1\$s IS NOT NULL
            ) AS source_ids
            JOIN attribute_values AS source_value ON source_value.id = source_ids.id
            JOIN attribute_values AS target_value ON target_value.value = source_value.value
            JOIN attributes AS target ON target.%2\$s = target_value.id
            JOIN attributes AS source ON source.event_id = ? AND source.%1\$s = source_ids.id
            WHERE
                target.event_id != ?
                AND source.deleted = 0 AND target.deleted = 0
                AND source.disable_correlation = 0 AND target.disable_correlation = 0
                AND source_value.value <> ''
                AND source.type IN (%3\$s)
                AND target.type IN (%4\$s)
            LIMIT %5\$d",
            $sourceColumn,
            $targetColumn,
            $types($sourceColumn),
            $types($targetColumn),
            $limit,
            $excluded($sourceColumn)
        );
    }

    /**
     * @param array $eventIds
     * @return array [event id => true] for the events that exist and correlate
     */
    private function __correlatingEvents(array $eventIds)
    {
        $eventIds = $this->Correlation->Event->find('column', [
            'recursive' => -1,
            'fields' => ['Event.id'],
            'conditions' => [
                'Event.id' => array_values(array_unique(array_map('intval', $eventIds))),
                'Event.disable_correlation' => 0,
            ],
        ]);
        return array_fill_keys(array_map('intval', $eventIds), true);
    }

    /**
     * Store a collected set under $cacheKey, or skip storing it when
     * there is no key to store it safely under. Returns the set either
     * way, so callers can return straight through it.
     *
     * @param string|null $cacheKey
     * @param array $correlations
     * @return array
     */
    private function __cacheCorrelations($cacheKey, array $correlations)
    {
        if ($cacheKey !== null) {
            $this->correlationCache[$cacheKey] = $correlations;
        }
        return $correlations;
    }

    /**
     * Reduce a set of collected correlations to the ones $user may see.
     *
     * The correlation queries above match on value alone - they carry no
     * distribution, sharing group or ownership condition - so the target
     * attributes have to be vetted before anything derived from them is
     * handed back. Rather than reimplementing the distribution rules,
     * the target IDs are run through MispAttribute::fetchAttributesSimple(),
     * which applies buildConditions(): event, attribute and object level
     * distribution plus sharing group membership, against live rows.
     *
     * @param array $user
     * @param array $correlations
     * @return array
     */
    private function __filterCorrelationsByAcl(array $user, array $correlations)
    {
        if (empty($correlations) || !empty($user['Role']['perm_site_admin'])) {
            return $correlations;
        }
        $attributeIds = [];
        foreach ($correlations as $correlation) {
            $attributeIds[$correlation['id']] = true;
        }
        $visible = array_flip($this->__filterAttributeIdsByAcl(
            $user,
            array_keys($attributeIds)
        ));
        foreach ($correlations as $k => $correlation) {
            if (!isset($visible[$correlation['id']])) {
                unset($correlations[$k]);
            }
        }
        return array_values($correlations);
    }

    /**
     * Reduce a list of attribute IDs to the ones $user may see.
     * Used by the read paths that resolve correlations from the stored
     * table rather than through __collectCorrelations().
     *
     * @param array $user
     * @param array $attributeIds
     * @return array
     */
    private function __filterAttributeIdsByAcl(array $user, array $attributeIds)
    {
        if (empty($attributeIds) || !empty($user['Role']['perm_site_admin'])) {
            return $attributeIds;
        }
        $visible = $this->Correlation->Attribute->fetchAttributesSimple($user, [
            'conditions' => [
                'Attribute.id' => $attributeIds,
                'Attribute.deleted' => 0
            ],
            'fields' => ['Attribute.id']
        ]);
        return array_column(array_column($visible, 'Attribute'), 'id');
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
        $correlations = $this->__collectCorrelations($user, $id);
        if (empty($correlations)) {
            return [];
        }
        $eventIds = [];
        foreach ($correlations as $correlation) {
            $eventIds[$correlation['event_id']] = true;
        }
        $conditions = $Model->Event->createEventConditions($user);
        $conditions['Event.id'] = array_keys($eventIds);
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

    public function runGetRelatedAttributes(Model $Model, $user, $sgids, $attribute, $fields = [], $includeEventData = false, $valueText = true)
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
                    $correlatedAttributeIds[] = $temp_correlation['Correlation'][$prefixes[$k] . 'attribute_id'];
                }
            }
        }

        // Unlike the rest of this engine, this path resolves correlations
        // from the stored table. Under OnDemand nothing writes, updates or
        // purges that table, so its denormalised distribution columns are
        // frozen at whatever the previously active engine last wrote. The
        // access check therefore has to be made against the live attribute
        // rows rather than against the stored copies.
        $correlatedAttributeIds = $this->__filterAttributeIdsByAcl(
            $user,
            $correlatedAttributeIds
        );

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
     * OnDemand variant — computes correlations on the fly
     * from the attributes table, then filters to requested
     * attribute IDs.
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
        $correlations = $this->__collectCorrelations($user, $eventId);
        if (empty($correlations)) {
            return [];
        }

        // Filter to only the requested attribute IDs
        $attributeIdFlip = array_flip($attributeIds);
        $filtered = [];
        $eventIds = [];
        foreach ($correlations as $corr) {
            if (!isset($attributeIdFlip[$corr['source_id']])) {
                continue;
            }
            $filtered[] = $corr;
            $eventIds[$corr['event_id']] = true;
        }

        if (empty($filtered)) {
            return [];
        }

        $conditions = $Model->Event->createEventConditions(
            $user
        );
        $conditions['Event.id'] = array_keys($eventIds);
        $events = $Model->Event->find('all', [
            'recursive' => -1,
            'conditions' => $conditions,
            'fields' => [
                'Event.id', 'Event.orgc_id',
                'Event.info', 'Event.date',
            ],
        ]);
        $events = array_column(
            array_column($events, 'Event'), null, 'id'
        );

        $result = [];
        foreach ($filtered as $corr) {
            $evId = $corr['event_id'];
            if (!isset($events[$evId])) {
                continue;
            }
            $event = $events[$evId];
            $parentId = $corr['source_id'];
            $result[$parentId][] = [
                'id' => $evId,
                'attribute_id' => $corr['id'],
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
     * @param array $user
     * @param int $eventId
     * @param array $sgids Not used
     * @param bool $excludeNonCorrelating Not used - this engine already feeds
     *      both this call and runGetAttributesRelatedToEvent() from the same
     *      __collectCorrelations(), so the two never disagree.
     * @return array
     */
    public function fetchRelatedEventIds(Model $Model, array $user, int $eventId, array $sgids, bool $excludeNonCorrelating = false)
    {
        return $this->__filterRelatedEvents($Model, $user, $eventId, $sgids, false);
    }

    /**
     * @param Model $Model
     * @param array $user
     * @param int $eventId
     * @param array $sgids
     * @param int $limit Not used
     * @return array [int $count, bool $more]
     */
    public function fetchRelatedEventCount(Model $Model, array $user, int $eventId, array $sgids, int $limit)
    {
        return [count($this->fetchRelatedEventIds($Model, $user, $eventId, $sgids, true)), false];
    }

    /**
     * @param Model $Model
     * @param array $user
     * @param int $eventId
     * @param array $sgids Not used
     * @param bool $primary Not used
     * @return array|int[]
     */
    private function __filterRelatedEvents(Model $Model, array $user, int $eventId, array $sgids, bool $primary)
    {
        $correlations = $this->__collectCorrelations($user, $eventId);
        $eventIds = [];
        foreach ($correlations as $correlation) {
            $eventIds[$correlation['event_id']] = true;
        }
        return array_keys($eventIds);

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
