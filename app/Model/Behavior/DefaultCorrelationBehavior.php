<?php
App::uses('AppModel', 'Model');

/**
 * Default correlation behaviour
 */
class DefaultCorrelationBehavior extends ModelBehavior
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

    /**
     * @param Model $Model
     * @param string $value
     * @param array $a
     * @param array $b
     * @return array
     */
    public function createCorrelationEntry(Model $Model, $value, $a, $b)
    {
        if ($this->deadlockAvoidance) {
            return [
                'value_id' => $value,
                '1_event_id' => $a['Event']['id'],
                '1_object_id' => $a['Attribute']['object_id'],
                '1_attribute_id' => $a['Attribute']['id'],
                '1_org_id' => $a['Event']['org_id'],
                '1_distribution' => $a['Attribute']['distribution'],
                '1_event_distribution' => $a['Event']['distribution'],
                '1_object_distribution' => empty($a['Attribute']['object_id']) ? 0 : $a['Object']['distribution'],
                '1_sharing_group_id' => $a['Attribute']['sharing_group_id'],
                '1_event_sharing_group_id' => $a['Event']['sharing_group_id'],
                '1_object_sharing_group_id' => empty($a['Attribute']['object_id']) ? 0 : $a['Object']['sharing_group_id'],
                'event_id' => $b['Event']['id'],
                'object_id' => $b['Attribute']['object_id'],
                'attribute_id' => $b['Attribute']['id'],
                'org_id' => $b['Event']['org_id'],
                'distribution' => $b['Attribute']['distribution'],
                'event_distribution' => $b['Event']['distribution'],
                'object_distribution' => empty($b['Attribute']['object_id']) ? 0 : $b['Object']['distribution'],
                'sharing_group_id' => $b['Attribute']['sharing_group_id'],
                'event_sharing_group_id' => $b['Event']['sharing_group_id'],
                'object_sharing_group_id' => empty($b['Attribute']['object_id']) ? 0 : $b['Object']['sharing_group_id'],
            ];
        } else {
            return [
                $value,
                (int) $a['Event']['id'],
                (int) ($a['Attribute']['object_id'] ?? 0),
                (int) $a['Attribute']['id'],
                (int) $a['Event']['org_id'],
                (int) $a['Attribute']['distribution'],
                (int) $a['Event']['distribution'],
                empty($a['Attribute']['object_id']) ? 0 : (int) $a['Object']['distribution'],
                (int) $a['Attribute']['sharing_group_id'],
                (int) $a['Event']['sharing_group_id'],
                empty($a['Attribute']['object_id']) ? 0 : (int) $a['Object']['sharing_group_id'],
                (int) $b['Event']['id'],
                (int) ($b['Attribute']['object_id'] ?? 0),
                (int) $b['Attribute']['id'],
                (int) $b['Event']['org_id'],
                (int) $b['Attribute']['distribution'],
                (int) $b['Event']['distribution'],
                empty($b['Attribute']['object_id']) ? 0 : (int) $b['Object']['distribution'],
                (int) $b['Attribute']['sharing_group_id'],
                (int) $b['Event']['sharing_group_id'],
                empty($b['Attribute']['object_id']) ? 0 : (int) $b['Object']['sharing_group_id']
            ];
        }
    }

    public function saveCorrelations(Model $Model, array $correlations)
    {
        $fields = [
            'value_id',
            '1_event_id',
            '1_object_id',
            '1_attribute_id',
            '1_org_id',
            '1_distribution',
            '1_event_distribution',
            '1_object_distribution',
            '1_sharing_group_id',
            '1_event_sharing_group_id',
            '1_object_sharing_group_id',
            'event_id',
            'object_id',
            'attribute_id',
            'org_id',
            'distribution',
            'event_distribution',
            'object_distribution',
            'sharing_group_id',
            'event_sharing_group_id',
            'object_sharing_group_id'
        ];

        $this->Correlation->CorrelationValue->replaceValueWithId($correlations, $this->deadlockAvoidance ? 'value_id' : 0);

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
                    $db->insertMulti('default_correlations', $fields, $chunk);
                }
                return true;
            } else {
                return $db->insertMulti('default_correlations', $fields, $correlations);
            }
        }
    }

    public function runBeforeSaveCorrelation(Model $Model, $attribute)
    {
        // (update-only) clean up the relation of the old value: remove the existing relations related to that attribute, we DO have a reference, the id
        // ==> DELETE FROM default_correlations WHERE 1_attribute_id = $a_id OR attribute_id = $a_id; */
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
    private function __collectCorrelations(array $user, $eventId, $sgids, $primary)
    {
        $maxCorrelations = Configure::read('MISP.max_correlations_per_event') ?: 5000;
        $source = $primary ? '' : '1_';
        $prefix = $primary ? '1_' : '';
        $correlations = $this->Correlation->find('all', array(
            'fields' => [
                $source . 'attribute_id',
                $prefix . 'attribute_id',
                $prefix . 'org_id',
                $prefix . 'event_id',
                $prefix . 'event_distribution',
                $prefix . 'event_sharing_group_id',
                $prefix . 'object_id',
                $prefix . 'object_distribution',
                $prefix . 'object_sharing_group_id',
                $prefix . 'distribution',
                $prefix . 'sharing_group_id'
            ],
            'conditions' => [
                'OR' => [
                    $source . 'event_id' => $eventId
                ],
                'AND' => [
                    [
                        'CorrelationValue.value NOT IN (select value from correlation_exclusions)'
                    ],
                    [
                        'CorrelationValue.value NOT IN (select value from over_correlating_values)'
                    ]
                ]
            ],
            'recursive' => -1,
            'contain' => [
                'CorrelationValue' => [
                    'fields' => [
                        'CorrelationValue.value'
                    ]
                ]
            ],
            'order' => false,
            'limit' => $maxCorrelations
        ));
        foreach ($correlations as $k => $correlation) {
            if (!$this->checkCorrelationACL($user, $correlation['Correlation'], $sgids, $prefix)) {
                unset($correlations[$k]);
            }
        }
        return $correlations;
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
        $correlations = [];
        $eventIds = [];
        foreach ($this->__collectCorrelations($user, $id, $sgids, false) as $correlation) {
            $correlations[] = [
                'id' => $correlation['Correlation']['event_id'],
                'attribute_id' => $correlation['Correlation']['attribute_id'],
                'parent_id' => $correlation['Correlation']['1_attribute_id'],
                'value' => $correlation['CorrelationValue']['value']
            ];
            $eventIds[$correlation['Correlation']['event_id']] = true;
        }
        foreach ($this->__collectCorrelations($user, $id, $sgids, true) as $correlation) {
            $correlations[] = [
                'id' => $correlation['Correlation']['1_event_id'],
                'attribute_id' => $correlation['Correlation']['1_attribute_id'],
                'parent_id' => $correlation['Correlation']['attribute_id'],
                'value' => $correlation['CorrelationValue']['value']
            ];
            $eventIds[$correlation['Correlation']['1_event_id']] = true;
        }
        if (empty($correlations)) {
            return [];
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

    public function runGetRelatedAttributes(Model $Model, $user, $sgids, $attribute, $fields = [], $includeEventData = false)
    {
        // LATER getRelatedAttributes($attribute) this might become a performance bottleneck
        // prepare the conditions
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

    public function fetchRelatedEventIds(Model $Model, array $user, int $eventId, array $sgids)
    {
        // search the correlation table for the event ids of the related events
        // Rules:
        // 1. Event is owned by the user (org_id matches)
        // 2. User is allowed to see both the event and the org:
        //    a.  Event:
        //        i. Event has a distribution between 1-3 (community only, connected communities, all orgs)
        //        ii. Event has a sharing group that the user is accessible to view
        //    b.  Attribute:
        //        i. Attribute has a distribution of 5 (inheritance of the event, for this the event check has to pass anyway)
        //        ii. Attribute has a distribution between 1-3 (community only, connected communities, all orgs)
        //        iii. Attribute has a sharing group that the user is accessible to view
        $primaryEventIds = $this->__filterRelatedEvents($Model, $user, $eventId, $sgids, true);
        $secondaryEventIds = $this->__filterRelatedEvents($Model, $user, $eventId, $sgids, false);
        return array_unique(array_merge($primaryEventIds,$secondaryEventIds), SORT_REGULAR);
    }

    /**
     * @param Model $Model
     * @param array $user
     * @param int $eventId
     * @param array $sgids
     * @param bool $primary
     * @return array|int[]
     */
    private function __filterRelatedEvents(Model $Model, array $user, int $eventId, array $sgids, bool $primary)
    {
        $current = $primary ? '' : '1_';
        $prefix = $primary ? '1_' : '';

        if (empty($user['Role']['perm_site_admin'])) {
            $correlations = $Model->find('all', [
                'recursive' => -1,
                'fields' => [
                    $prefix . 'org_id',
                    $prefix . 'event_id',
                    $prefix . 'event_distribution',
                    $prefix . 'event_sharing_group_id',
                    $prefix . 'object_id',
                    $prefix . 'object_distribution',
                    $prefix . 'object_sharing_group_id',
                    $prefix . 'distribution',
                    $prefix . 'sharing_group_id'
                ],
                'conditions' => [
                    $current . 'event_id' => $eventId
                ],
            ]);

            $eventIds = [];
            foreach ($correlations as $correlation) {
                $correlation = $correlation['Correlation'];
                // if we have already added this event as a valid target, no need to check again.
                if (isset($eventIds[$correlation[$prefix . 'event_id']])) {
                    continue;
                }
                if ($this->checkCorrelationACL($user, $correlation, $sgids, $prefix)) {
                    $eventIds[$correlation[$prefix . 'event_id']] = true;
                }
            }
            return array_keys($eventIds);
        }

        return $Model->find('column', [
            'fields' => [$prefix . 'event_id'],
            'conditions' => [
                $current . 'event_id' => $eventId
            ],
            'unique' => true,
        ]);
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
        if ($user['Role']['perm_site_admin']) {
            return true;
        }
        // Check if user can see the event
        if (isset($correlation['Correlation'])) {
            $correlation = $correlation['Correlation'];
        }
        if (
            $correlation[$prefix . 'org_id'] != $user['org_id'] &&
            (
                $correlation[$prefix . 'event_distribution'] == 0 ||
                (
                    $correlation[$prefix . 'event_distribution'] == 4 &&
                    !in_array($correlation[$prefix . 'event_sharing_group_id'], $sgids)
                )
            )
        ) {
            return false;
        }

        // Check if the user can see the object, if we're looking at an object attribute
        if (
            $correlation[$prefix . 'object_id'] &&
            (
                $correlation[$prefix . 'object_distribution'] == 0 ||
                (
                    $correlation[$prefix . 'object_distribution'] == 4 &&
                    !in_array($correlation[$prefix . 'object_sharing_group_id'], $sgids)
                )
            )
        ) {
            return false;
        }

        // Check if the user can see the attribute
        if (
            (
                $correlation[$prefix . 'distribution'] == 0 ||
                (
                    $correlation[$prefix . 'distribution'] == 4 &&
                    !in_array($correlation[$prefix . 'sharing_group_id'], $sgids)
                )
            )
        ) {
            return false;
        }
        return true;
    }

    public function updateContainedCorrelations(
        Model $Model,
        array $data,
        string $type = 'event',
        array $options = []
    )
    {
        $updateCorrelation = [];
        $updateFields = [
            'Correlation.' . $type . '_id',
            'Correlation.1_' . $type . '_id'
        ];
        if (
            isset($data['distribution']) &&
            (
                empty($options['fieldList']) ||
                in_array('distribution', $options['fieldList'], true)
            )
        ) {
            $updateCorrelation[0]['Correlation.' . $type . '_distribution'] = (int)$data['distribution'];
            $updateCorrelation[1]['Correlation.1_' . $type . '_distribution'] = (int)$data['distribution'];
        }
        if (
            isset($data['sharing_group_id']) &&
            (
                empty($options['fieldList']) ||
                in_array('sharing_group_id', $options['fieldList'], true)
            )
        ) {
            $updateCorrelation[0]['Correlation.' . $type . '_sharing_group_id'] = (int)$data['sharing_group_id'];
            $updateCorrelation[1]['Correlation.1_' . $type . '_sharing_group_id'] = (int)$data['sharing_group_id'];
        }
        foreach ($updateCorrelation as $k => $side) {
            $Model->updateAll(
                $side,
                [
                    $updateFields[$k] => (int)$data['id']
                ]
            );
        }
        return true;
    }

    public function purgeCorrelations(Model $Model, $eventId = null)
    {
        if (!$eventId) {
            $Model->query('TRUNCATE TABLE default_correlations;');
            //$Model->query('TRUNCATE TABLE correlation_values;');
            //$Model->query('TRUNCATE TABLE over_correlating_values;');
        } else {
            $Model->deleteAll([
                'OR' => array(
                    'Correlation.1_event_id' => $eventId,
                    'Correlation.event_id' => $eventId,
                )
            ], false);
        }
    }

    public function purgeByValue(Model $Model, string $value)
    {
        $valueIds = $Model->CorrelationValue->find('column', [
            'recursive' => -1,
            'conditions' => [
                'OR' => [
                    'CorrelationValue.value LIKE' => '%' . $value,
                    'CorrelationValue.value LIKE' => $value . '%'
                ]
            ],
            'fields' => [
                'CorrelationValue.id'
            ]
        ]);
        $Model->deleteAll([
            'Correlation.value_id' => $valueIds
        ], false);
    }
}
